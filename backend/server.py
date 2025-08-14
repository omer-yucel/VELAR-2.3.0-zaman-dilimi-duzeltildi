from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
import qrcode
from io import BytesIO
from fastapi.responses import Response
from PIL import Image, ImageDraw, ImageFont
import math
import base64
import bcrypt
import jwt
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Timezone configuration
from zoneinfo import ZoneInfo
import time as _time
IST_TZ = ZoneInfo("Europe/Istanbul")

def now_ist() -> datetime:
    return datetime.now(IST_TZ)

os.environ.setdefault('TZ', 'Europe/Istanbul')
if hasattr(_time, 'tzset'):
    _time.tzset()

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url, tz_aware=True, tzinfo=IST_TZ)
db = client[os.environ['DB_NAME']]

# Security
security = HTTPBearer()
JWT_SECRET = "production-tracking-secret-key"  # In production, use environment variable
JWT_ALGORITHM = "HS256"

# Enums
class ProcessStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"

class UserRole(str, Enum):
    OPERATOR = "operator"
    MANAGER = "manager"
    ADMIN = "admin"

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    role: UserRole
    created_at: datetime = Field(default_factory=now_ist)

class UserCreate(BaseModel):
    username: str
    password: str
    role: UserRole

class UserLogin(BaseModel):
    username: str
    password: str

class Project(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    process_steps: List[str]  # Ordered list of process step names
    created_at: datetime = Field(default_factory=now_ist)
    created_by: str

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    process_steps: List[str]

class Part(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    part_number: str
    project_id: str
    planned_quantity: int = Field(..., gt=0, description="Total number of products planned for production")
    current_step_index: int = 0
    status: ProcessStatus = ProcessStatus.PENDING
    created_at: datetime = Field(default_factory=now_ist)

class PartWithStepInfo(BaseModel):
    id: str
    part_number: str
    project_id: str
    planned_quantity: int
    current_step_index: int
    status: ProcessStatus
    created_at: datetime
    total_steps: int  # Actual number of process instances for this work order
    current_step_name: Optional[str] = None  # Name of the current step
    completed_count: int = 0
    in_progress_count: int = 0
    remaining_count: int = 0

class PartCreate(BaseModel):
    part_number: str
    project_id: str
    planned_quantity: int = Field(..., gt=0, description="Total number of products planned for production")
    process_steps: List[str]  # Required custom process steps for this work order

class ProcessInstance(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    part_id: str
    step_name: str
    step_index: int
    status: ProcessStatus = ProcessStatus.PENDING
    remaining_count: int = 0
    in_progress_count: int = 0
    completed_count: int = 0
    operator_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    start_qr_code: str = Field(default_factory=lambda: str(uuid.uuid4()))
    end_qr_code: str = Field(default_factory=lambda: str(uuid.uuid4()))
    process_records: List[dict] = []  # List of process quantity records
    created_at: datetime = Field(default_factory=now_ist)

class WorkOrderQRCode(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    part_id: str
    qr_code: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=now_ist)

class QRScanRequest(BaseModel):
    qr_code: str
    username: str
    password: str
    
class WorkOrderScanRequest(BaseModel):
    qr_code: str
    username: str
    password: str
    
class ProcessActionRequest(BaseModel):
    qr_code: str
    username: str
    password: str
    process_index: int
    action: str  # "start" or "end"
    process_quantity: int = Field(..., gt=0, description="Number of products affected by this action")

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

# Create the main app
app = FastAPI(title="Production Tracking System")
api_router = APIRouter(prefix="/api")

# Helper Functions
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_jwt_token(user_id: str, username: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": int((now_ist() + timedelta(hours=24)).timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def generate_qr_code(data: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    img_str = base64.b64encode(buffer.read()).decode()
    return f"data:image/png;base64,{img_str}"

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Check if token is expired
        exp = payload.get("exp")
        if exp is None:
            raise HTTPException(status_code=401, detail="Token has no expiration")
        
        if _time.time() > exp:
            raise HTTPException(status_code=401, detail="Token has expired")
            
        user = await db.users.find_one({"id": payload["user_id"]})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return User(**user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication error: {str(e)}")

# Authentication Routes
@api_router.post("/auth/register")
async def register_user(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    hashed_password = hash_password(user_data.password)
    user = User(
        username=user_data.username,
        password_hash=hashed_password,
        role=user_data.role
    )
    
    await db.users.insert_one(user.dict())
    
    # Create token
    token = create_jwt_token(user.id, user.username, user.role.value)
    
    return {
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    }

@api_router.post("/auth/login")
async def login_user(login_data: UserLogin):
    user = await db.users.find_one({"username": login_data.username})
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(user["id"], user["username"], user["role"])
    
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }

# NEW: Session verification endpoint
@api_router.get("/auth/verify")
async def verify_session(current_user: User = Depends(get_current_user)):
    """
    Verify the current user's session and return user information.
    This endpoint is used to validate tokens and restore user sessions after page refresh.
    """
    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role
        }
    }

# Project Routes
@api_router.post("/projects", response_model=Project)
async def create_project(project_data: ProjectCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    project = Project(**project_data.dict(), created_by=current_user.id)
    await db.projects.insert_one(project.dict())
    return project

@api_router.get("/projects", response_model=List[Project])
async def get_projects(current_user: User = Depends(get_current_user)):
    projects = await db.projects.find().to_list(1000)
    return [Project(**project) for project in projects]

@api_router.get("/projects/{project_id}", response_model=Project)
async def get_project(project_id: str, current_user: User = Depends(get_current_user)):
    project = await db.projects.find_one({"id": project_id})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return Project(**project)

@api_router.get("/projects/{project_id}/parts", response_model=List[PartWithStepInfo])
async def get_project_parts(project_id: str, current_user: User = Depends(get_current_user)):
    # Verify project exists
    project = await db.projects.find_one({"id": project_id})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get all parts for this project
    parts = await db.parts.find({"project_id": project_id}).to_list(1000)
    
    # Build parts with step info similar to dashboard endpoint
    parts_with_step_info = []
    for part in parts:
        # Get the actual process instances for this part to determine total steps
        process_instances = await db.process_instances.find({"part_id": part["id"]}).to_list(100)
        
        # Find current step from actual process instances
        current_step_name = "Completed"
        if part["current_step_index"] < len(process_instances):
            # Sort process instances by step_index to ensure correct order
            process_instances.sort(key=lambda x: x["step_index"])
            current_step_name = process_instances[part["current_step_index"]]["step_name"]
        
        # Calculate total counts across all steps
        total_completed = sum(pi["completed_count"] for pi in process_instances)
        total_in_progress = sum(pi["in_progress_count"] for pi in process_instances)
        total_remaining = part.get("planned_quantity", 1) - total_completed - total_in_progress
        
        # Create PartWithStepInfo object
        part_with_info = PartWithStepInfo(
            id=part["id"],
            part_number=part["part_number"],
            project_id=part["project_id"],
            planned_quantity=part.get("planned_quantity", 1),
            current_step_index=part["current_step_index"],
            status=part["status"],
            created_at=part["created_at"],
            total_steps=len(process_instances),  # Actual number of steps for this work order
            current_step_name=current_step_name,
            completed_count=total_completed,
            in_progress_count=total_in_progress,
            remaining_count=max(0, total_remaining)
        )
        parts_with_step_info.append(part_with_info)
    
    return parts_with_step_info

@api_router.delete("/projects/{project_id}")
async def delete_project(project_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Check if project exists
    project = await db.projects.find_one({"id": project_id})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if there are parts associated with this project
    parts = await db.parts.find({"project_id": project_id}).to_list(1000)
    if parts:
        # Delete all associated process instances first
        for part in parts:
            await db.process_instances.delete_many({"part_id": part["id"]})
        # Delete all parts
        await db.parts.delete_many({"project_id": project_id})
    
    # Delete the project
    result = await db.projects.delete_one({"id": project_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {"message": "Project deleted successfully"}

# Part Routes
@api_router.post("/parts", response_model=Part)
async def create_part(part_data: PartCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Validation: At least one process step must be provided
    if not part_data.process_steps or len(part_data.process_steps) == 0:
        raise HTTPException(status_code=400, detail="At least one process step must be selected")
    
    # Validate planned quantity
    if part_data.planned_quantity <= 0:
        raise HTTPException(status_code=400, detail="Planned quantity must be greater than 0")
    
    # Verify project exists
    project = await db.projects.find_one({"id": part_data.project_id})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Create part
    part = Part(**part_data.dict(exclude={'process_steps'}))
    await db.parts.insert_one(part.dict())
    
    # Create process instances using the custom process steps (not project's default steps)
    for i, step_name in enumerate(part_data.process_steps):
        process_instance = ProcessInstance(
            part_id=part.id,
            step_name=step_name,
            step_index=i,
            remaining_count=part.planned_quantity if i == 0 else 0,
            in_progress_count=0,
            completed_count=0,
            process_records=[]
        )
        await db.process_instances.insert_one(process_instance.dict())
    
    # Create a single QR code for the entire work order
    work_order_qr = WorkOrderQRCode(part_id=part.id)
    await db.work_order_qr_codes.insert_one(work_order_qr.dict())
    
    return part

@api_router.get("/parts", response_model=List[Part])
async def get_parts(current_user: User = Depends(get_current_user)):
    parts = await db.parts.find().to_list(1000)
    return [Part(**part) for part in parts]

@api_router.get("/parts/{part_id}/status")
async def get_part_status(part_id: str, current_user: User = Depends(get_current_user)):
    part = await db.parts.find_one({"id": part_id})
    if not part:
        raise HTTPException(status_code=404, detail="Part not found")
    
    process_instances = await db.process_instances.find({"part_id": part_id}).to_list(100)
    
    return {
        "part": Part(**part),
        "process_instances": [ProcessInstance(**pi) for pi in process_instances]
    }

@api_router.delete("/parts/{part_id}")
async def delete_part(part_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Check if part exists
    part = await db.parts.find_one({"id": part_id})
    if not part:
        raise HTTPException(status_code=404, detail="Part not found")
    
    # Delete all associated process instances
    await db.process_instances.delete_many({"part_id": part_id})
    
    # Delete the part
    result = await db.parts.delete_one({"id": part_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Part not found")
    
    return {"message": "Part deleted successfully"}

# QR Code Routes
@api_router.get("/parts/{part_id}/qr-codes")
async def get_part_qr_codes(part_id: str, current_user: User = Depends(get_current_user)):
    # Get the work order QR code
    work_order_qr = await db.work_order_qr_codes.find_one({"part_id": part_id})
    
    # If no QR code exists yet for this work order, create one
    if not work_order_qr:
        work_order_qr = WorkOrderQRCode(part_id=part_id)
        await db.work_order_qr_codes.insert_one(work_order_qr.dict())
        work_order_qr = await db.work_order_qr_codes.find_one({"part_id": part_id})
    
    # Get part and process information
    part = await db.parts.find_one({"id": part_id})
    if not part:
        raise HTTPException(status_code=404, detail="Part not found")
    
    process_instances = await db.process_instances.find({"part_id": part_id}).sort("step_index", 1).to_list(100)
    
    # Get current step information
    current_step_index = part["current_step_index"]
    current_step_name = "Not started"
    if process_instances and current_step_index < len(process_instances):
        current_step_name = process_instances[current_step_index]["step_name"]
    
    # Generate QR code image
    qr_image = generate_qr_code(work_order_qr["qr_code"])
    
    # Return the single QR code with work order information
    return [{
        "work_order": {
            "part_number": part["part_number"],
            "current_step_index": current_step_index,
            "total_steps": len(process_instances),
            "current_step_name": current_step_name,
            "status": part["status"]
        },
        "qr_code": {
            "code": work_order_qr["qr_code"],
            "image": qr_image
        },
        "process_steps": [
            {
                "step_name": pi["step_name"],
                "step_index": pi["step_index"],
                "status": pi["status"]
            } for pi in process_instances
        ]
    }]

# ---------------------------------------------------------------------------
# QR Code PDF Export Route
# This endpoint generates a single-page PDF containing all start and end QR codes
# for a given work order (part). The PDF is designed for printing on an A4 page
# so that operators can scan the codes directly from paper. Each process step
# appears as a separate row in the PDF with its start and end QR codes side by
# side, along with their respective codes.
@api_router.get("/parts/{part_id}/qr-codes/pdf")
async def get_part_qr_codes_pdf(part_id: str, current_user: User = Depends(get_current_user)):
    """
    Generate a PDF document containing the single QR code for the specified work order.

    This endpoint creates a PDF with the work order information and a single QR code
    that can be used throughout the entire lifecycle of the work order. The PDF is 
    formatted for A4 paper at 300 DPI and designed to be printed for operators to scan.

    The resulting file is named according to the pattern:
      "(<work_order_number>) - Work Order QR Code.pdf"

    where <work_order_number> is retrieved from the part's `part_number` field. If the
    part is not found, the `part_id` is used instead.
    """
    # Get the work order QR code
    work_order_qr = await db.work_order_qr_codes.find_one({"part_id": part_id})
    
    # If no QR code exists yet for this work order, create one
    if not work_order_qr:
        work_order_qr = WorkOrderQRCode(part_id=part_id)
        await db.work_order_qr_codes.insert_one(work_order_qr.dict())
        work_order_qr = await db.work_order_qr_codes.find_one({"part_id": part_id})
    
    # Get part information
    part = await db.parts.find_one({"id": part_id})
    if not part:
        raise HTTPException(status_code=404, detail="Part not found")
    
    # Get project information
    project = await db.projects.find_one({"id": part["project_id"]})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get process instances
    process_instances = await db.process_instances.find({"part_id": part_id}).sort("step_index", 1).to_list(100)
    if not process_instances:
        raise HTTPException(status_code=404, detail="No process instances found for this part")

    # Generate QR code image
    qr_data_url = generate_qr_code(work_order_qr["qr_code"])
    try:
        qr_base64 = qr_data_url.split(",", 1)[1]
        qr_bytes = base64.b64decode(qr_base64)
        qr_img = Image.open(BytesIO(qr_bytes)).convert("RGB")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to generate QR code image")

    # Download and process Velar Makine logo
    logo_img = None
    try:
        import urllib.request
        with urllib.request.urlopen("https://customer-assets.emergentagent.com/job_metalops/artifacts/i1dybgg7_Velar%20Makine%20Logo%20SVG.png") as response:
            logo_data = response.read()
            logo_img = Image.open(BytesIO(logo_data)).convert("RGBA")
    except Exception:
        # Logo loading failed, continue without logo
        pass

    # Define page dimensions (A4 at 300 DPI)
    page_width = 2480
    page_height = 3508
    margin = 120
    header_height = 150
    
    # Create a blank page
    page_img = Image.new('RGB', (page_width, page_height), 'white')
    draw_page = ImageDraw.Draw(page_img)
    
    # Load fonts with fallback to default
    try:
        font_title = ImageFont.truetype("DejaVuSans-Bold.ttf", 60)
        font_subtitle = ImageFont.truetype("DejaVuSans-Bold.ttf", 40)
        font_header = ImageFont.truetype("DejaVuSans-Bold.ttf", 36)  # For system title
        font_info = ImageFont.truetype("DejaVuSans.ttf", 32)
        font_steps_title = ImageFont.truetype("DejaVuSans-Bold.ttf", 48)  # ENLARGED from 36 to 48
        font_steps = ImageFont.truetype("DejaVuSans.ttf", 38)  # ENLARGED from 28 to 38
        font_date = ImageFont.truetype("DejaVuSans.ttf", 28)
    except Exception:
        font_title = ImageFont.load_default()
        font_subtitle = ImageFont.load_default()
        font_header = ImageFont.load_default()
        font_info = ImageFont.load_default()
        font_steps_title = ImageFont.load_default()
        font_steps = ImageFont.load_default()
        font_date = ImageFont.load_default()
    
    # Draw header section
    current_y = margin
    
    # Draw logo in top left corner (if available) - SIGNIFICANTLY ENLARGED
    if logo_img:
        logo_size = 160  # Height of logo - DOUBLED from 80 to 160
        # Calculate width maintaining aspect ratio
        logo_aspect_ratio = logo_img.width / logo_img.height
        logo_width = int(logo_size * logo_aspect_ratio)
        
        # Resize logo
        logo_resized = logo_img.resize((logo_width, logo_size), Image.LANCZOS)
        
        # Create a white background for the logo (in case it has transparency)
        logo_bg = Image.new('RGB', (logo_width, logo_size), 'white')
        if logo_resized.mode == 'RGBA':
            logo_bg.paste(logo_resized, (0, 0), logo_resized)
        else:
            logo_bg.paste(logo_resized, (0, 0))
        
        page_img.paste(logo_bg, (margin, current_y))
        logo_right_edge = margin + logo_width + 40  # Increased padding for larger logo
    else:
        logo_right_edge = margin
    
    # Draw system title next to logo
    system_title = "Velar Makine Üretim Takip Sistemi"
    draw_page.text((logo_right_edge, current_y + 25), system_title, fill=(0, 0, 0), font=font_header)
    
    # Draw current date in top right corner
    current_date = now_ist().strftime("%d/%m/%Y")
    date_text = f"Tarih: {current_date}"
    date_width = draw_page.textlength(date_text, font=font_date)
    draw_page.text((page_width - margin - date_width, current_y + 25), date_text, fill=(0, 0, 0), font=font_date)
    
    # Move down after header
    current_y += header_height
    
    # Draw work order title
    title = f"İş Emri: {part['part_number']}"
    draw_page.text((margin, current_y), title, fill=(0, 0, 0), font=font_title)
    current_y += 80
    
    # Draw project info
    project_info = f"Proje: {project['name']}"
    draw_page.text((margin, current_y), project_info, fill=(0, 0, 0), font=font_subtitle)
    current_y += 80
    
    # Draw QR code (large, centered)
    qr_size = 800
    try:
        resized_qr = qr_img.resize((qr_size, qr_size), resample=Image.NEAREST)
    except Exception:
        resized_qr = qr_img.resize((qr_size, qr_size))
    
    qr_x = (page_width - qr_size) // 2
    qr_y = current_y + 20
    page_img.paste(resized_qr, (qr_x, qr_y))
    
    # Draw QR code value
    qr_code_text = f"QR Kod: {work_order_qr['qr_code']}"
    text_width = draw_page.textlength(qr_code_text, font=font_info)
    qr_text_y = qr_y + qr_size + 40
    draw_page.text(((page_width - text_width) // 2, qr_text_y), qr_code_text, fill=(0, 0, 0), font=font_info)
    
    # Draw process steps with larger fonts
    steps_y = qr_text_y + 80
    steps_title = "İş Akış Adımları:"
    draw_page.text((margin, steps_y), steps_title, fill=(0, 0, 0), font=font_steps_title)
    
    # List all process steps with increased spacing and font size
    y_offset = steps_y + 70  # Increased from 60 to 70 for better spacing with larger title
    line_spacing = 55  # Increased from 45 to 55 for better readability with larger fonts
    for i, pi in enumerate(process_instances):
        step_text = f"{i+1}. {pi['step_name']}"
        draw_page.text((margin + 40, y_offset + i * line_spacing), step_text, fill=(0, 0, 0), font=font_steps)
    
    # Note: Removed the "Mevcut Adım" (current step) section as requested
    
    # Create PDF in memory
    pdf_buffer = BytesIO()
    page_img.save(pdf_buffer, format='PDF', resolution=300.0)
    pdf_buffer.seek(0)

    # Determine file name based on work order number (part_number)
    work_order_number = part.get("part_number") or part_id
    filename = f"{work_order_number} - Is Emri QR Kodu.pdf"

    return Response(
        content=pdf_buffer.getvalue(),
        media_type='application/pdf',
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# QR Scanning Routes with Session-Based Authentication
@api_router.post("/scan/work-order")
async def scan_work_order_qr(scan_data: WorkOrderScanRequest, current_user: User = Depends(get_current_user)):
    """
    Scan a work order QR code and return information about the work order and available processes.
    """
    # Use session user if password indicates session authentication
    if scan_data.password == "session_authenticated":
        user = {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role
        }
    else:
        # Authenticate user via username/password
        user_doc = await db.users.find_one({"username": scan_data.username})
        if not user_doc or not verify_password(scan_data.password, user_doc["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user = user_doc
    
    # Find work order QR code
    work_order_qr = await db.work_order_qr_codes.find_one({"qr_code": scan_data.qr_code})
    if not work_order_qr:
        raise HTTPException(status_code=404, detail="QR code not found")
    
    # Get part information
    part = await db.parts.find_one({"id": work_order_qr["part_id"]})
    if not part:
        raise HTTPException(status_code=404, detail="Work order not found")
    
    # Get process instances
    process_instances = await db.process_instances.find({"part_id": part["id"]}).sort("step_index", 1).to_list(100)
    
    # Get current step information
    current_step_index = part["current_step_index"]
    current_step_name = "Not started"
    if process_instances and current_step_index < len(process_instances):
        current_step_name = process_instances[current_step_index]["step_name"]
    
    # Determine which processes can be started or ended based on the workflow rules
    available_processes = []
    for pi in process_instances:
        process = ProcessInstance(**pi)
        can_start = False
        can_end = False
        
        # A process can be started if:
        # 1. It's the current step and in PENDING status
        # 2. All previous steps are COMPLETED
        if process.step_index == current_step_index and process.status == ProcessStatus.PENDING:
            # Check if all previous steps are completed
            all_previous_completed = True
            for prev_pi in process_instances:
                if prev_pi["step_index"] < process.step_index and prev_pi["status"] != ProcessStatus.COMPLETED:
                    all_previous_completed = False
                    break
            
            can_start = all_previous_completed
        
        # A process can be ended if it's in IN_PROGRESS status
        if process.status == ProcessStatus.IN_PROGRESS:
            can_end = True
        
        available_processes.append({
            "step_index": process.step_index,
            "step_name": process.step_name,
            "status": process.status,
            "can_start": can_start,
            "can_end": can_end
        })
    
    return {
        "work_order": {
            "id": part["id"],
            "part_number": part["part_number"],
            "current_step_index": current_step_index,
            "current_step_name": current_step_name,
            "status": part["status"],
            "total_steps": len(process_instances)
        },
        "processes": available_processes,
        "qr_code": work_order_qr["qr_code"],
        "operator": user["username"]
    }

@api_router.post("/scan/process-action")
async def process_action(action_data: ProcessActionRequest, current_user: User = Depends(get_current_user)):
    """
    Perform a start or end action on a specific process within a work order.
    """
    # Use session user if password indicates session authentication
    if action_data.password == "session_authenticated":
        user = {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role
        }
    else:
        # Authenticate user via username/password
        user_doc = await db.users.find_one({"username": action_data.username})
        if not user_doc or not verify_password(action_data.password, user_doc["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user = user_doc
    
    # Validate quantity
    if action_data.process_quantity <= 0:
        raise HTTPException(status_code=400, detail="Process quantity must be greater than 0")
    
    # Find work order QR code
    work_order_qr = await db.work_order_qr_codes.find_one({"qr_code": action_data.qr_code})
    if not work_order_qr:
        raise HTTPException(status_code=404, detail="QR code not found")
    
    # Get part information
    part = await db.parts.find_one({"id": work_order_qr["part_id"]})
    if not part:
        raise HTTPException(status_code=404, detail="Work order not found")
    
    # Get process instances
    process_instances = await db.process_instances.find({"part_id": part["id"]}).sort("step_index", 1).to_list(100)
    
    # Find the specific process instance
    target_process = None
    for pi in process_instances:
        if pi["step_index"] == action_data.process_index:
            target_process = ProcessInstance(**pi)
            break
    
    if not target_process:
        raise HTTPException(status_code=404, detail="Process not found")
    
    # Handle start action
    if action_data.action == "start":
        # Check if this step can be started (sequential enforcement)
        if target_process.step_index > 0:
            # Check if previous step is completed
            prev_process = None
            for pi in process_instances:
                if pi["step_index"] == target_process.step_index - 1:
                    prev_process = pi
                    break
            
            if not prev_process or prev_process["status"] != ProcessStatus.COMPLETED:
                raise HTTPException(status_code=400, detail="Previous step must be completed first")
        
        # Check if already started
        if target_process.status == ProcessStatus.IN_PROGRESS:
            raise HTTPException(status_code=400, detail="Process already started")
        
        if target_process.status == ProcessStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Process already completed")
        
        # Get part to check remaining quantity
        # Calculate total processed quantity so far
        all_process_instances = await db.process_instances.find({"part_id": part["id"]}).to_list(100)
        total_processed = 0
        for pi in all_process_instances:
            for record in pi.get("process_records", []):
                if record.get("action") == "start":
                    total_processed += record.get("process_quantity", 0)
        
        # Check if process quantity exceeds remaining quantity
        remaining_quantity = part["planned_quantity"] - total_processed
        if action_data.process_quantity > remaining_quantity:
            raise HTTPException(
                status_code=400, 
                detail=f"Process quantity ({action_data.process_quantity}) exceeds remaining quantity ({remaining_quantity})"
            )
        
        # Start the process
        now = now_ist()
        
        # Add process record
        process_record = {
            "action": "start",
            "process_quantity": action_data.process_quantity,
            "timestamp": now,
            "user": user["username"]
        }
        
        # Add the process record to the existing records
        await db.process_instances.update_one(
            {"id": target_process.id},
            {
                "$set": {
                    "status": ProcessStatus.IN_PROGRESS,
                    "operator_id": user["id"],
                    "start_time": now
                },
                "$push": {"process_records": process_record}
            }
        )
        
        # Update part status
        await db.parts.update_one(
            {"id": part["id"]},
            {
                "$set": {
                    "current_step_index": target_process.step_index,
                    "status": ProcessStatus.IN_PROGRESS
                }
            }
        )
        
        return {
            "message": "Process started successfully",
            "step_name": target_process.step_name,
            "operator": user["username"],
            "start_time": now,
            "process_quantity": action_data.process_quantity,
            "remaining_quantity": remaining_quantity - action_data.process_quantity
        }
    
    # Handle end action
    elif action_data.action == "end":
        # Check if process was started
        if target_process.status != ProcessStatus.IN_PROGRESS:
            raise HTTPException(status_code=400, detail="Process must be started first")
        
        # Calculate total started quantity for this process instance
        total_started = 0
        for record in target_process.process_records:
            if record.get("action") == "start":
                total_started += record.get("process_quantity", 0)
        
        # Calculate total finished quantity for this process instance
        total_finished = 0
        for record in target_process.process_records:
            if record.get("action") == "end":
                total_finished += record.get("process_quantity", 0)
        
        # Check if finish quantity exceeds remaining started quantity
        remaining_started = total_started - total_finished
        if action_data.process_quantity > remaining_started:
            raise HTTPException(
                status_code=400, 
                detail=f"Process quantity ({action_data.process_quantity}) exceeds remaining started quantity ({remaining_started})"
            )
        
        # Complete the process
        now = now_ist()
        
        # Add process record
        process_record = {
            "action": "end",
            "process_quantity": action_data.process_quantity,
            "timestamp": now,
            "user": user["username"]
        }
        
        # Check if all started quantity is now finished
        new_total_finished = total_finished + action_data.process_quantity
        update_data = {
            "end_time": now
        }
        
        if new_total_finished >= total_started:
            update_data["status"] = ProcessStatus.COMPLETED
        
        # Add the process record to the existing records
        await db.process_instances.update_one(
            {"id": target_process.id},
            {
                "$set": update_data,
                "$push": {"process_records": process_record}
            }
        )
        
        # Update part status
        if target_process.step_index == len(process_instances) - 1 and new_total_finished >= total_started:
            # This was the last step and it's fully completed
            await db.parts.update_one(
                {"id": part["id"]},
                {
                    "$set": {
                        "status": ProcessStatus.COMPLETED,
                        "current_step_index": target_process.step_index
                    }
                }
            )
        elif new_total_finished >= total_started:
            # Update current step index to the next step
            await db.parts.update_one(
                {"id": part["id"]},
                {
                    "$set": {
                        "current_step_index": target_process.step_index + 1,
                        "status": ProcessStatus.IN_PROGRESS
                    }
                }
            )
        
        return {
            "message": "Process completed successfully",
            "step_name": target_process.step_name,
            "operator": user["username"],
            "end_time": now,
            "process_quantity": action_data.process_quantity,
            "remaining_started_quantity": remaining_started - action_data.process_quantity
        }
    
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Must be 'start' or 'end'")

# Keep the old endpoints for backward compatibility
@api_router.post("/scan/start")
async def scan_start_qr(scan_data: QRScanRequest, current_user: User = Depends(get_current_user)):
    # Use session user if password indicates session authentication
    if scan_data.password == "session_authenticated":
        user = {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role
        }
    else:
        # Authenticate user via username/password
        user_doc = await db.users.find_one({"username": scan_data.username})
        if not user_doc or not verify_password(scan_data.password, user_doc["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user = user_doc
    
    # Find process instance
    process_instance = await db.process_instances.find_one({"start_qr_code": scan_data.qr_code})
    if not process_instance:
        # Try to find if this is a work order QR code
        work_order_qr = await db.work_order_qr_codes.find_one({"qr_code": scan_data.qr_code})
        if work_order_qr:
            raise HTTPException(status_code=400, detail="This is a work order QR code. Please use the new interface.")
        raise HTTPException(status_code=404, detail="QR code not found")
    
    process = ProcessInstance(**process_instance)
    
    # Check if this step can be started (sequential enforcement)
    if process.step_index > 0:
        # Check if previous step is completed
        prev_process = await db.process_instances.find_one({
            "part_id": process.part_id,
            "step_index": process.step_index - 1
        })
        if not prev_process or prev_process["status"] != ProcessStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Previous step must be completed first")
    
    # Check if already started
    if process.status == ProcessStatus.IN_PROGRESS:
        raise HTTPException(status_code=400, detail="Process already started")
    
    if process.status == ProcessStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Process already completed")
    
    # Start the process
    now = now_ist()
    await db.process_instances.update_one(
        {"id": process.id},
        {
            "$set": {
                "status": ProcessStatus.IN_PROGRESS,
                "operator_id": user["id"],
                "start_time": now
            }
        }
    )
    
    return {
        "message": "Process started successfully",
        "step_name": process.step_name,
        "operator": user["username"],
        "start_time": now
    }

@api_router.post("/scan/end")
async def scan_end_qr(scan_data: QRScanRequest, current_user: User = Depends(get_current_user)):
    # Use session user if password indicates session authentication
    if scan_data.password == "session_authenticated":
        user = {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role
        }
    else:
        # Authenticate user via username/password
        user_doc = await db.users.find_one({"username": scan_data.username})
        if not user_doc or not verify_password(scan_data.password, user_doc["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user = user_doc
    
    # Find process instance
    process_instance = await db.process_instances.find_one({"end_qr_code": scan_data.qr_code})
    if not process_instance:
        # Try to find if this is a work order QR code
        work_order_qr = await db.work_order_qr_codes.find_one({"qr_code": scan_data.qr_code})
        if work_order_qr:
            raise HTTPException(status_code=400, detail="This is a work order QR code. Please use the new interface.")
        raise HTTPException(status_code=404, detail="QR code not found")
    
    process = ProcessInstance(**process_instance)
    
    # Check if process was started
    if process.status != ProcessStatus.IN_PROGRESS:
        raise HTTPException(status_code=400, detail="Process must be started first")
    
    # Complete the process
    now = now_ist()
    await db.process_instances.update_one(
        {"id": process.id},
        {
            "$set": {
                "status": ProcessStatus.COMPLETED,
                "end_time": now
            }
        }
    )
    
    # Update part status if this was the last step
    part = await db.parts.find_one({"id": process.part_id})
    project = await db.projects.find_one({"id": part["project_id"]})
    
    if process.step_index == len(project["process_steps"]) - 1:
        # This was the last step
        await db.parts.update_one(
            {"id": process.part_id},
            {
                "$set": {
                    "status": ProcessStatus.COMPLETED,
                    "current_step_index": process.step_index
                }
            }
        )
    else:
        # Update current step index
        await db.parts.update_one(
            {"id": process.part_id},
            {
                "$set": {
                    "current_step_index": process.step_index + 1,
                    "status": ProcessStatus.IN_PROGRESS
                }
            }
        )
    
    return {
        "message": "Process completed successfully",
        "step_name": process.step_name,
        "operator": user["username"],
        "end_time": now
    }

# Dashboard Routes
@api_router.get("/dashboard/overview")
async def get_dashboard_overview(current_user: User = Depends(get_current_user)):
    # Get all parts with their current status
    parts = await db.parts.find().to_list(1000)
    projects = await db.projects.find().to_list(1000)
    
    # Create project lookup
    project_lookup = {p["id"]: p for p in projects}
    
    dashboard_data = []
    for part in parts:
        project = project_lookup.get(part["project_id"])
        if project:
            # Get the actual process instances for this part to determine current step
            process_instances = await db.process_instances.find({"part_id": part["id"]}).to_list(100)
            
            # Find current step from actual process instances (not project defaults)
            current_step = "Completed"
            if part["current_step_index"] < len(process_instances):
                # Sort process instances by step_index to ensure correct order
                process_instances.sort(key=lambda x: x["step_index"])
                current_step = process_instances[part["current_step_index"]]["step_name"]
            
            # Calculate total counts across all steps
            total_completed = sum(pi["completed_count"] for pi in process_instances)
            total_in_progress = sum(pi["in_progress_count"] for pi in process_instances)
            total_remaining = part.get("planned_quantity", 1) - total_completed - total_in_progress
            
            # Calculate progress percentage based on completed units
            progress_percentage = (total_completed / part.get("planned_quantity", 1)) * 100 if part.get("planned_quantity", 1) > 0 else 0
            
            # Calculate quantity progress
            total_planned = part.get("planned_quantity", 1)
            total_processed = 0
            total_completed_qty = 0
            
            for pi in process_instances:
                for record in pi.get("process_records", []):
                    if record.get("action") == "start":
                        total_processed += record.get("process_quantity", 0)
                    elif record.get("action") == "end":
                        total_completed_qty += record.get("process_quantity", 0)
            
            dashboard_data.append({
                "part": {
                    "id": part["id"],
                    "part_number": part["part_number"],
                    "planned_quantity": total_planned
                },
                "project": {
                    "id": project["id"],
                    "name": project["name"]
                },
                "current_step": current_step,
                "progress": {
                    "completed_steps": len([pi for pi in process_instances if pi["status"] == ProcessStatus.COMPLETED]),
                    "total_steps": len(process_instances),
                    "percentage": progress_percentage
                },
                "quantity_progress": {
                    "planned_quantity": total_planned,
                    "processed_quantity": total_processed,
                    "completed_quantity": total_completed_qty,
                    "remaining_quantity": total_planned - total_processed
                },
                "step_details": [
                    {
                        "step_name": pi["step_name"],
                        "step_index": pi["step_index"],
                        "remaining_count": pi["remaining_count"],
                        "in_progress_count": pi["in_progress_count"],
                        "completed_count": pi["completed_count"]
                    } for pi in process_instances
                ]
            })
    
    return dashboard_data

# Veriler (Data) Route - Manager Only
@api_router.get("/veriler")
async def get_process_durations(current_user: User = Depends(get_current_user)):
    # Check if user is manager or admin
    if current_user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Access denied. Manager privileges required.")
    
    # Get all completed process instances with timing data
    process_instances = await db.process_instances.find({
        "status": ProcessStatus.COMPLETED,
        "start_time": {"$ne": None},
        "end_time": {"$ne": None}
    }).to_list(1000)
    
    duration_data = []
    for process in process_instances:
        # Calculate duration in minutes
        start_time = process["start_time"]
        end_time = process["end_time"]
        duration_minutes = (end_time - start_time).total_seconds() / 60
        
        # Get part and project information
        part = await db.parts.find_one({"id": process["part_id"]})
        project = await db.projects.find_one({"id": part["project_id"]}) if part else None
        
        # Get operator information
        operator = await db.users.find_one({"id": process["operator_id"]}) if process.get("operator_id") else None
        
        duration_data.append({
            "id": process["id"],
            "step_name": process["step_name"],
            "part_number": part["part_number"] if part else "Unknown",
            "project_name": project["name"] if project else "Unknown",
            "operator_name": operator["username"] if operator else "Unknown",
            "duration_minutes": round(duration_minutes, 2),
            "start_time": start_time,
            "end_time": end_time
        })
    
    # Sort by end_time descending (most recent first)
    duration_data.sort(key=lambda x: x["end_time"], reverse=True)
    
    return duration_data

# User Routes
@api_router.post("/users/create")
async def admin_create_user(user_data: UserCreate, current_user: User = Depends(get_current_user)):
    """
    Admin-only endpoint to create a new user with role manager or operator.
    Returns standardized JSON: {"success": bool, "message": str, "user": {...}}
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Only allow creating manager or operator
    if user_data.role not in [UserRole.MANAGER, UserRole.OPERATOR]:
        raise HTTPException(status_code=400, detail="Invalid role. Only 'manager' or 'operator' can be created.")

    # Ensure unique username
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Create user
    hashed_password = hash_password(user_data.password)
    new_user = User(
        username=user_data.username,
        password_hash=hashed_password,
        role=user_data.role,
    )
    await db.users.insert_one(new_user.dict())

    return {
        "success": True,
        "message": "User created successfully",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "role": new_user.role,
        },
    }


@api_router.get("/users")
async def list_users(current_user: User = Depends(get_current_user)):
    """
    Admin-only endpoint to list all users except the current admin.
    Returns: {"success": true, "users": [{id, username, role, created_at}]}
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")

    users = await db.users.find({"id": {"$ne": current_user.id}}).to_list(10000)
    users_sanitized = [
        {
            "id": u["id"],
            "username": u["username"],
            "role": u["role"],
            "created_at": u.get("created_at"),
        }
        for u in users
    ]
    return {"success": True, "users": users_sanitized}


@api_router.delete("/users/{user_id}")
async def delete_user(user_id: str, current_user: User = Depends(get_current_user)):
    """
    Admin-only endpoint to delete a user by id. Does not delete any historical production data.
    Returns standardized JSON: {"success": bool, "message": str}
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Prevent deleting self just in case frontend filter is bypassed
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete the currently logged-in admin user")

    result = await db.users.delete_one({"id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    return {"success": True, "message": "User deleted successfully"}

@api_router.post("/users/change-password")
async def change_password(change_password_data: ChangePasswordRequest, current_user: User = Depends(get_current_user)):
    """
    Change the current user's password.
    """
    if not verify_password(change_password_data.current_password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    new_hashed_password = hash_password(change_password_data.new_password)
    
    await db.users.update_one(
        {"id": current_user.id},
        {"$set": {"password_hash": new_hashed_password}}
    )
    
    return {"message": "Password changed successfully"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
for handler in logging.getLogger().handlers:
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    try:
        # Use time.localtime which respects TZ we set above
        formatter.converter = _time.localtime
    except Exception:
        pass
    handler.setFormatter(formatter)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
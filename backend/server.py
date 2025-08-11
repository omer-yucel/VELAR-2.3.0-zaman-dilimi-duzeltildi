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
    current_step_index: int = 0
    status: ProcessStatus = ProcessStatus.PENDING
    created_at: datetime = Field(default_factory=now_ist)
    # NEW: total units for this work order (backward compatible default)
    total_quantity: int = 1

class PartWithStepInfo(BaseModel):
    id: str
    part_number: str
    project_id: str
    current_step_index: int
    status: ProcessStatus
    created_at: datetime
    total_steps: int  # Actual number of process instances for this work order
    current_step_name: Optional[str] = None  # Name of the current step

class PartCreate(BaseModel):
    part_number: str
    project_id: str
    process_steps: List[str]  # Required custom process steps for this work order
    # NEW: optional at creation time; default to 1 if not provided
    total_quantity: Optional[int] = 1

class ProcessInstance(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    part_id: str
    step_name: str
    step_index: int
    status: ProcessStatus = ProcessStatus.PENDING
    operator_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    start_qr_code: str = Field(default_factory=lambda: str(uuid.uuid4()))
    end_qr_code: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=now_ist)
    # NEW: quantity tracking for this step
    remaining_count: int = 0
    in_progress_count: int = 0
    completed_count: int = 0

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
    # NEW: number of units being started/finished (default 1)
    quantity: Optional[int] = 1

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
        
        # Create PartWithStepInfo object
        part_with_info = PartWithStepInfo(
            id=part["id"],
            part_number=part["part_number"],
            project_id=part["project_id"],
            current_step_index=part["current_step_index"],
            status=part["status"],
            created_at=part["created_at"],
            total_steps=len(process_instances),  # Actual number of steps for this work order
            current_step_name=current_step_name
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
    
    # Verify project exists
    project = await db.projects.find_one({"id": part_data.project_id})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Determine total quantity with backward-compatible default
    total_qty = part_data.total_quantity if part_data.total_quantity and part_data.total_quantity > 0 else 1
    
    # Create part
    part = Part(**part_data.dict(exclude={'process_steps'}), total_quantity=total_qty)
    await db.parts.insert_one(part.dict())
    
    # Create process instances using the custom process steps (not project's default steps)
    for i, step_name in enumerate(part_data.process_steps):
        # Initialize counts: step 0 remaining = total, others 0
        process_instance = ProcessInstance(
            part_id=part.id,
            step_name=step_name,
            step_index=i,
            remaining_count=total_qty if i == 0 else 0,
            in_progress_count=0,
            completed_count=0,
            status=ProcessStatus.PENDING
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
    """
    # Get work order QR code
    work_order_qr = await db.work_order_qr_codes.find_one({"part_id": part_id})
    if not work_order_qr:
        work_order_qr = WorkOrderQRCode(part_id=part_id)
        await db.work_order_qr_codes.insert_one(work_order_qr.dict())
        work_order_qr = await db.work_order_qr_codes.find_one({"part_id": part_id})
    
    # Get part and process information
    part = await db.parts.find_one({"id": part_id})
    if not part:
        raise HTTPException(status_code=404, detail="Part not found")
    
    process_instances = await db.process_instances.find({"part_id": part_id}).sort("step_index", 1).to_list(100)

    # Create a blank A4 page (at 300 DPI)
    dpi = 300
    width, height = int(8.27 * dpi), int(11.69 * dpi)  # A4 dimensions in pixels
    page_img = Image.new('RGB', (width, height), color=(255, 255, 255))
    draw_page = ImageDraw.Draw(page_img)

    # Fonts (using default PIL fonts)
    try:
        font_title = ImageFont.truetype("arial.ttf", 60)
        font_subtitle = ImageFont.truetype("arial.ttf", 36)
        font_steps_title = ImageFont.truetype("arial.ttf", 42)  # Larger title for steps
        font_steps = ImageFont.truetype("arial.ttf", 28)        # Larger font for steps
    except:
        font_title = ImageFont.load_default()
        font_subtitle = ImageFont.load_default()
        font_steps_title = ImageFont.load_default()
        font_steps = ImageFont.load_default()

    # Margins and layout
    margin = 80
    qr_size = 600
    qr_x = margin
    qr_y = margin

    # Draw QR code image
    qr_img_data = base64.b64decode(generate_qr_code(work_order_qr["qr_code"]).split(",")[1])
    qr_image = Image.open(BytesIO(qr_img_data))
    qr_image = qr_image.resize((qr_size, qr_size))
    page_img.paste(qr_image, (qr_x, qr_y))

    # Draw work order info
    text_x = qr_x + qr_size + 40
    text_y = qr_y
    draw_page.text((text_x, text_y), f"İş Emri: {part['part_number']}", fill=(0, 0, 0), font=font_title)
    draw_page.text((text_x, text_y + 80), f"Durum: {part['status']}", fill=(0, 0, 0), font=font_subtitle)

    # Additional Information under QR Code
    qr_text_y = qr_y + qr_size + 40
    draw_page.text((margin, qr_text_y), "Bu QR kodu iş emrini temsil eder.", fill=(0, 0, 0), font=font_subtitle)

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
    
    # Ensure total_quantity exists
    if "total_quantity" not in part or not part.get("total_quantity"):
        await db.parts.update_one({"id": part["id"]}, {"$set": {"total_quantity": 1}})
        part = await db.parts.find_one({"id": work_order_qr["part_id"]})
    total_qty = part.get("total_quantity", 1)
    
    # Get process instances
    process_instances = await db.process_instances.find({"part_id": part["id"]}).sort("step_index", 1).to_list(100)

    # Backward-compatibility: initialize counts if missing and there is no data yet
    if process_instances:
        sums = {"remaining": 0, "in_progress": 0, "completed": 0}
        missing_any_field = False
        for pi in process_instances:
            if "remaining_count" not in pi or "in_progress_count" not in pi or "completed_count" not in pi:
                missing_any_field = True
            sums["remaining"] += pi.get("remaining_count", 0)
            sums["in_progress"] += pi.get("in_progress_count", 0)
            sums["completed"] += pi.get("completed_count", 0)
        if missing_any_field or (sums["remaining"] + sums["in_progress"] + sums["completed"]) == 0:
            # initialize counts: step 0 gets all remaining
            for i, pi in enumerate(process_instances):
                await db.process_instances.update_one(
                    {"id": pi["id"]},
                    {"$set": {
                        "remaining_count": total_qty if i == 0 else 0,
                        "in_progress_count": 0,
                        "completed_count": 0,
                        "status": pi.get("status", ProcessStatus.PENDING)
                    }}
                )
            # re-fetch after init
            process_instances = await db.process_instances.find({"part_id": part["id"]}).sort("step_index", 1).to_list(100)
    
    # Determine dynamic current step index (earliest not fully completed step)
    dynamic_current_idx = 0
    for pi in process_instances:
        if pi.get("completed_count", 0) >= total_qty:
            dynamic_current_idx = pi["step_index"] + 1
        else:
            dynamic_current_idx = pi["step_index"]
            break
    dynamic_current_idx = min(dynamic_current_idx, max(0, len(process_instances) - 1)) if process_instances else 0

    current_step_index = dynamic_current_idx
    current_step_name = "Not started"
    if process_instances and current_step_index < len(process_instances):
        current_step_name = process_instances[current_step_index]["step_name"]
    
    # Determine which processes can be started or ended based on counts
    available_processes = []
    for pi in process_instances:
        remaining = pi.get("remaining_count", 0)
        in_prog = pi.get("in_progress_count", 0)
        completed = pi.get("completed_count", 0)
        process_status = pi.get("status", ProcessStatus.PENDING)

        can_start = remaining > 0
        can_end = in_prog > 0
        
        available_processes.append({
            "step_index": pi["step_index"],
            "step_name": pi["step_name"],
            "status": process_status,
            "can_start": can_start,
            "can_end": can_end,
            # NEW: expose counts so UI can show limits
            "remaining_count": remaining,
            "in_progress_count": in_prog,
            "completed_count": completed
        })
    
    return {
        "work_order": {
            "id": part["id"],
            "part_number": part["part_number"],
            "current_step_index": current_step_index,
            "current_step_name": current_step_name,
            "status": part["status"],
            "total_steps": len(process_instances),
            "total_quantity": total_qty
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
    
    # Find work order QR code
    work_order_qr = await db.work_order_qr_codes.find_one({"qr_code": action_data.qr_code})
    if not work_order_qr:
        raise HTTPException(status_code=404, detail="QR code not found")
    
    # Get part information
    part = await db.parts.find_one({"id": work_order_qr["part_id"]})
    if not part:
        raise HTTPException(status_code=404, detail="Work order not found")
    if "total_quantity" not in part or not part.get("total_quantity"):
        await db.parts.update_one({"id": part["id"]}, {"$set": {"total_quantity": 1}})
        part = await db.parts.find_one({"id": work_order_qr["part_id"]})
    total_qty = part.get("total_quantity", 1)
    
    # Get process instances
    process_instances = await db.process_instances.find({"part_id": part["id"]}).sort("step_index", 1).to_list(100)

    # Initialize counts if missing for backward compatibility
    if process_instances:
        sums = {"remaining": 0, "in_progress": 0, "completed": 0}
        missing_any_field = False
        for pi in process_instances:
            if "remaining_count" not in pi or "in_progress_count" not in pi or "completed_count" not in pi:
                missing_any_field = True
            sums["remaining"] += pi.get("remaining_count", 0)
            sums["in_progress"] += pi.get("in_progress_count", 0)
            sums["completed"] += pi.get("completed_count", 0)
        if missing_any_field or (sums["remaining"] + sums["in_progress"] + sums["completed"]) == 0:
            for i, pi in enumerate(process_instances):
                await db.process_instances.update_one(
                    {"id": pi["id"]},
                    {"$set": {
                        "remaining_count": total_qty if i == 0 else 0,
                        "in_progress_count": 0,
                        "completed_count": 0,
                        "status": pi.get("status", ProcessStatus.PENDING)
                    }}
                )
            process_instances = await db.process_instances.find({"part_id": part["id"]}).sort("step_index", 1).to_list(100)
    
    # Find the specific process instance
    target_process_doc = None
    for pi in process_instances:
        if pi["step_index"] == action_data.process_index:
            target_process_doc = pi
            break
    
    if not target_process_doc:
        raise HTTPException(status_code=404, detail="Process not found")

    # Normalize quantity
    qty = action_data.quantity if action_data.quantity and action_data.quantity > 0 else 1

    # Ensure counts fields exist (backward compatibility)
    target_remaining = target_process_doc.get("remaining_count", 0)
    target_in_progress = target_process_doc.get("in_progress_count", 0)
    target_completed = target_process_doc.get("completed_count", 0)

    # Handle start action
    if action_data.action == "start":
        # Validate available remaining
        if target_remaining < qty:
            raise HTTPException(status_code=400, detail=f"Insufficient remaining units to start. Available: {target_remaining}")

        now = now_ist()
        # Atomically update counts
        await db.process_instances.update_one(
            {"id": target_process_doc["id"]},
            {
                "$inc": {
                    "remaining_count": -qty,
                    "in_progress_count": qty
                },
                "$set": {
                    # Set status to IN_PROGRESS if any work started
                    "status": ProcessStatus.IN_PROGRESS,
                },
                "$setOnInsert": {"start_time": now}
            }
        )

        # Ensure start_time is set if it wasn't before
        await db.process_instances.update_one(
            {"id": target_process_doc["id"], "start_time": {"$exists": False}},
            {"$set": {"start_time": now, "operator_id": user["id"]}}
        )

        # Update part status pointer (earliest not fully complete step)
        # Re-fetch target and all steps to compute pointer
        updated_instances = await db.process_instances.find({"part_id": part["id"]}).sort("step_index", 1).to_list(100)
        new_idx = 0
        for idx_pi in updated_instances:
            if idx_pi.get("completed_count", 0) >= total_qty:
                new_idx = idx_pi["step_index"] + 1
            else:
                new_idx = idx_pi["step_index"]
                break
        new_idx = min(new_idx, max(0, len(updated_instances) - 1)) if updated_instances else 0
        await db.parts.update_one(
            {"id": part["id"]},
            {"$set": {"current_step_index": new_idx, "status": ProcessStatus.IN_PROGRESS}}
        )

        return {
            "message": "Process started successfully",
            "step_name": target_process_doc["step_name"],
            "operator": user["username"],
            "quantity": qty,
            "time": now
        }
    
    # Handle end action
    elif action_data.action == "end":
        # Validate in-progress available
        if target_in_progress < qty:
            raise HTTPException(status_code=400, detail=f"Insufficient in-progress units to complete. Available: {target_in_progress}")

        now = now_ist()
        # Complete units for this process
        await db.process_instances.update_one(
            {"id": target_process_doc["id"]},
            {
                "$inc": {
                    "in_progress_count": -qty,
                    "completed_count": qty
                },
                "$set": {
                    "status": ProcessStatus.IN_PROGRESS  # may change below if fully complete
                }
            }
        )

        # Move units to next step's remaining, if any
        next_step_index = target_process_doc["step_index"] + 1
        if next_step_index < len(process_instances):
            next_process = process_instances[next_step_index]
            await db.process_instances.update_one(
                {"id": next_process["id"]},
                {"$inc": {"remaining_count": qty}}
            )

        # Re-evaluate status for this process after update
        updated = await db.process_instances.find_one({"id": target_process_doc["id"]})
        updated_completed = updated.get("completed_count", 0)
        updated_remaining = updated.get("remaining_count", 0)
        updated_in_prog = updated.get("in_progress_count", 0)

        if updated_completed >= total_qty:
            # fully completed
            await db.process_instances.update_one(
                {"id": target_process_doc["id"]},
                {"$set": {"status": ProcessStatus.COMPLETED, "end_time": now}}
            )
        elif updated_in_prog > 0 or updated_completed > 0:
            await db.process_instances.update_one(
                {"id": target_process_doc["id"]},
                {"$set": {"status": ProcessStatus.IN_PROGRESS}}
            )
        else:
            await db.process_instances.update_one(
                {"id": target_process_doc["id"]},
                {"$set": {"status": ProcessStatus.PENDING}}
            )

        # Update part status and pointer
        updated_instances = await db.process_instances.find({"part_id": part["id"]}).sort("step_index", 1).to_list(100)
        last_index = len(updated_instances) - 1 if updated_instances else 0
        # Determine if fully done
        final_completed = updated_instances[last_index].get("completed_count", 0) if updated_instances else 0
        if updated_instances and final_completed >= total_qty:
            await db.parts.update_one(
                {"id": part["id"]},
                {"$set": {"status": ProcessStatus.COMPLETED, "current_step_index": last_index}}
            )
        else:
            # Move pointer to earliest not fully completed step
            new_idx = 0
            for idx_pi in updated_instances:
                if idx_pi.get("completed_count", 0) >= total_qty:
                    new_idx = idx_pi["step_index"] + 1
                else:
                    new_idx = idx_pi["step_index"]
                    break
            new_idx = min(new_idx, max(0, len(updated_instances) - 1)) if updated_instances else 0
            await db.parts.update_one(
                {"id": part["id"]},
                {"$set": {"current_step_index": new_idx, "status": ProcessStatus.IN_PROGRESS}}
            )
        
        return {
            "message": "Process completed successfully",
            "step_name": target_process_doc["step_name"],
            "operator": user["username"],
            "quantity": qty,
            "time": now
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
            process_instances = await db.process_instances.find({"part_id": part["id"]}).sort("step_index", 1).to_list(100)
            total_qty = part.get("total_quantity", 1)
            
            # Find current step from actual process instances (not project defaults)
            current_step = "Completed"
            # Compute dynamic current step index based on completion counts
            current_idx = 0
            for pi in process_instances:
                if pi.get("completed_count", 0) >= total_qty:
                    current_idx = pi["step_index"] + 1
                else:
                    current_idx = pi["step_index"]
                    break
            if process_instances and current_idx < len(process_instances):
                current_step = process_instances[current_idx]["step_name"]
            
            # Aggregate counts for dashboard
            total_remaining = 0
            total_in_progress = 0
            total_completed = 0
            per_step_counts = []
            for pi in process_instances:
                remaining = pi.get("remaining_count", 0)
                in_prog = pi.get("in_progress_count", 0)
                completed = pi.get("completed_count", 0)
                per_step_counts.append({
                    "step_index": pi["step_index"],
                    "step_name": pi["step_name"],
                    "remaining_count": remaining,
                    "in_progress_count": in_prog,
                    "completed_count": completed,
                })
                total_in_progress += in_prog
            # Overall remaining = units not yet started anywhere (step 0 remaining)
            if process_instances:
                total_remaining = process_instances[0].get("remaining_count", 0)
                # Overall completed = units completed at final step
                total_completed = process_instances[-1].get("completed_count", 0)
            
            dashboard_data.append({
                "part": Part(**part),
                "project": Project(**project),
                "current_step": current_step,
                "total_steps": len(process_instances),  # Actual number of steps for this work order
                "progress_percentage": (total_completed / total_qty) * 100 if total_qty > 0 else 0,
                # NEW summary counts
                "total_quantity": total_qty,
                "summary_counts": {
                    "remaining": total_remaining,
                    "in_progress": total_in_progress,
                    "completed": total_completed,
                },
                # NEW per-step counts
                "per_step_counts": per_step_counts,
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
        operator = await db.users.find_one({"id": process.get("operator_id")}) if process.get("operator_id") else None
        
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
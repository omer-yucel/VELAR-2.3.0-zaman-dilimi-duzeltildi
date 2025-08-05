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

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
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
    created_at: datetime = Field(default_factory=datetime.utcnow)

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
    created_at: datetime = Field(default_factory=datetime.utcnow)
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
    created_at: datetime = Field(default_factory=datetime.utcnow)

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
    created_at: datetime = Field(default_factory=datetime.utcnow)

class QRScanRequest(BaseModel):
    qr_code: str
    username: str
    password: str

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
        "exp": datetime.utcnow() + timedelta(hours=24)
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
        user = await db.users.find_one({"id": payload["user_id"]})
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return User(**user)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

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
    
    # Create part
    part = Part(**part_data.dict(exclude={'process_steps'}))
    await db.parts.insert_one(part.dict())
    
    # Create process instances using the custom process steps (not project's default steps)
    for i, step_name in enumerate(part_data.process_steps):
        process_instance = ProcessInstance(
            part_id=part.id,
            step_name=step_name,
            step_index=i
        )
        await db.process_instances.insert_one(process_instance.dict())
    
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
    process_instances = await db.process_instances.find({"part_id": part_id}).to_list(100)
    
    qr_codes = []
    for pi in process_instances:
        process = ProcessInstance(**pi)
        start_qr_data = generate_qr_code(process.start_qr_code)
        end_qr_data = generate_qr_code(process.end_qr_code)
        
        qr_codes.append({
            "step_name": process.step_name,
            "step_index": process.step_index,
            "status": process.status,
            "start_qr": {
                "code": process.start_qr_code,
                "image": start_qr_data
            },
            "end_qr": {
                "code": process.end_qr_code,
                "image": end_qr_data
            }
        })
    
    return qr_codes

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
    Generate a PDF document containing all QR codes for the specified part (work order).

    This endpoint dynamically lays out the QR codes across multiple pages if needed. Each
    process step is rendered on its own row with the step name, start QR code, end QR
    code, and their corresponding labels. The PDF is formatted for A4 paper at 300 DPI
    and designed to be printed for operators to scan.

    The resulting file is named according to the pattern:
      "(<work_order_number>) - Work Order QR Codes.pdf"

    where <work_order_number> is retrieved from the part's `part_number` field. If the
    part is not found, the `part_id` is used instead.
    """
    # Fetch all process instances for the specified part
    process_instances = await db.process_instances.find({"part_id": part_id}).to_list(100)
    if not process_instances:
        raise HTTPException(status_code=404, detail="No process instances found for this part")

    # Build a list of items with step name and generated QR images
    items = []  # Each entry: (step_name, start_code, end_code, start_img, end_img)
    for pi in process_instances:
        process = ProcessInstance(**pi)
        # Generate PIL images for start and end QR codes using the existing helper
        start_data_url = generate_qr_code(process.start_qr_code)
        end_data_url = generate_qr_code(process.end_qr_code)
        try:
            start_base64 = start_data_url.split(",", 1)[1]
            end_base64 = end_data_url.split(",", 1)[1]
            start_bytes = base64.b64decode(start_base64)
            end_bytes = base64.b64decode(end_base64)
            start_img = Image.open(BytesIO(start_bytes)).convert("RGB")
            end_img = Image.open(BytesIO(end_bytes)).convert("RGB")
        except Exception:
            # Skip this process step if decoding fails
            continue
        items.append((process.step_name, process.start_qr_code, process.end_qr_code, start_img, end_img))


    # Sort items by step index if available to preserve process order.
    # We assume that process_instances are in the correct order by default, but in case
    # they are not, we attempt to sort by the `step_index` attribute. We cannot
    # access `step_index` directly from `items`, so we build a mapping from
    # start_code/end_code to step_index based on the original `process_instances` list.
    try:
        # Create a lookup of start_qr_code to step_index
        index_lookup = {pi["start_qr_code"]: pi["step_index"] for pi in process_instances}
        items.sort(key=lambda t: index_lookup.get(t[1], 0))
    except Exception:
        pass  # If sorting fails, proceed with the existing order

    # ----------------------------------------------------------------------
    # New layout implementation: divide the page into two columns, each with
    # exactly 10 rows. This layout avoids overlapping of text and QR codes by
    # using fixed row heights and truncating long strings. QR code sizes and
    # font sizes are computed based on the row height, with upper bounds to
    # ensure readability. Each process step is drawn into the appropriate
    # column and row. If more than 20 process steps exist, additional pages
    # are created automatically.
    # ----------------------------------------------------------------------
    # Define page dimensions (A4 at 300 DPI)
    page_width = 2480
    page_height = 3508
    margin = 80
    rows_per_column = 10
    columns = 2
    available_height = page_height - 2 * margin
    row_height = available_height // rows_per_column

    # Compute font sizes. Title and label fonts are capped to avoid
    # becoming too large when there are fewer items. The QR size is
    # calculated so that the title, QR codes and labels fit within the row.
    tentative_title = max(16, int(row_height * 0.15))
    tentative_label = max(10, int(row_height * 0.08))
    title_font_size = min(32, tentative_title)
    label_font_size = min(18, tentative_label)
    vertical_padding = 40
    qr_size = row_height - (title_font_size + 2 * label_font_size + vertical_padding)
    if qr_size < 80:
        qr_size = 80
    line_spacing = max(2, int(label_font_size * 0.2))

    # Load fonts with fallback to default
    try:
        font_title = ImageFont.truetype("DejaVuSans-Bold.ttf", title_font_size)
    except Exception:
        font_title = ImageFont.load_default()
    try:
        font_label = ImageFont.truetype("DejaVuSans.ttf", label_font_size)
    except Exception:
        font_label = ImageFont.load_default()

    # Prepare the step name: truncate long names to a single line with ellipsis
    def prepare_step_name(name: str, max_chars: int = 30) -> str:
        if not name:
            return ""
        if len(name) <= max_chars:
            return name
        return name[:max_chars - 3] + '...'

    # Wrap codes into at most two lines. If the code is longer than
    # permitted, truncate and append an ellipsis. Only the first line
    # contains the prefix (e.g., 'Başlangıç:' or 'Bitiş:').
    def wrap_code(prefix: str, code: str, max_chars: int = 18, max_lines: int = 2) -> List[str]:
        if not code:
            return [prefix]
        lines: List[str] = []
        first_available = max_chars - len(prefix) - 1
        first_segment = code[:first_available]
        lines.append(f"{prefix} {first_segment}")
        remaining = code[first_available:]
        for i in range(0, len(remaining), max_chars):
            segment = remaining[i:i + max_chars]
            lines.append(segment)
            if len(lines) >= max_lines:
                if i + max_chars < len(remaining):
                    lines[-1] = lines[-1][:-3] + '...'
                break
        return lines

    # Generate pages
    pages: List[Image.Image] = []
    for page_start in range(0, len(items), rows_per_column * columns):
        page_items = items[page_start: page_start + rows_per_column * columns]
        # Create a blank page
        page_img = Image.new('RGB', (page_width, page_height), 'white')
        draw_page = ImageDraw.Draw(page_img)
        # Draw vertical separator line
        mid_x = page_width // 2
        line_thickness = 4
        draw_page.line([(mid_x, 0), (mid_x, page_height)], fill=(0, 0, 0), width=line_thickness)
        # Draw each item
        for idx, (step_name, start_code, end_code, start_img, end_img) in enumerate(page_items):
            col = idx // rows_per_column
            row = idx % rows_per_column
            x_offset = margin if col == 0 else mid_x + margin
            y_offset = margin + row * row_height
            # Draw the truncated step name
            name_display = prepare_step_name(step_name, max_chars=30)
            # Determine title height using font metrics if available
            if hasattr(font_title, 'getbbox'):
                bbox = font_title.getbbox(name_display)
                title_height = bbox[3] - bbox[1]
            else:
                title_height = title_font_size
            draw_page.text((x_offset, y_offset), name_display, fill=(0, 0, 0), font=font_title)
            # Position for QR codes
            y_qr = y_offset + title_height + 5
            # Draw start QR
            if start_img:
                try:
                    resized_start = start_img.resize((qr_size, qr_size), resample=Image.NEAREST)
                except Exception:
                    resized_start = start_img.resize((qr_size, qr_size))
                page_img.paste(resized_start, (x_offset, y_qr))
            # Draw end QR
            spacing_between_qrs = 10
            x_end = x_offset + qr_size + spacing_between_qrs
            if end_img:
                try:
                    resized_end = end_img.resize((qr_size, qr_size), resample=Image.NEAREST)
                except Exception:
                    resized_end = end_img.resize((qr_size, qr_size))
                page_img.paste(resized_end, (x_end, y_qr))
            # Prepare labels
            start_lines = wrap_code("Başlangıç:", start_code, max_chars=18, max_lines=2)
            end_lines = wrap_code("Bitiş:", end_code, max_chars=18, max_lines=2)
            max_label_lines = max(len(start_lines), len(end_lines))
            y_label_start = y_qr + qr_size + 5
            for line_idx in range(max_label_lines):
                st = start_lines[line_idx] if line_idx < len(start_lines) else ""
                et = end_lines[line_idx] if line_idx < len(end_lines) else ""
                draw_page.text((x_offset, y_label_start + line_idx * (label_font_size + line_spacing)), st, fill=(0, 0, 0), font=font_label)
                draw_page.text((x_end, y_label_start + line_idx * (label_font_size + line_spacing)), et, fill=(0, 0, 0), font=font_label)
        pages.append(page_img)

    # Create PDF in memory
    pdf_buffer = BytesIO()
    if pages:
        pages[0].save(pdf_buffer, format='PDF', save_all=True, append_images=pages[1:], resolution=300.0)
    else:
        blank_page = Image.new('RGB', (page_width, page_height), 'white')
        blank_page.save(pdf_buffer, format='PDF', resolution=300.0)
    pdf_buffer.seek(0)

    # Determine file name based on part number
    part_doc = await db.parts.find_one({"id": part_id})
    part_number = part_doc.get("part_number") if part_doc else None
    work_order_number = part_number or part_id
    filename = f"({work_order_number}) - Work Order QR Codes.pdf"

    return Response(
        content=pdf_buffer.getvalue(),
        media_type='application/pdf',
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# QR Scanning Routes with Session-Based Authentication
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
    now = datetime.utcnow()
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
        raise HTTPException(status_code=404, detail="QR code not found")
    
    process = ProcessInstance(**process_instance)
    
    # Check if process was started
    if process.status != ProcessStatus.IN_PROGRESS:
        raise HTTPException(status_code=400, detail="Process must be started first")
    
    # Complete the process
    now = datetime.utcnow()
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
            
            dashboard_data.append({
                "part": Part(**part),
                "project": Project(**project),
                "current_step": current_step,
                "total_steps": len(process_instances),  # Actual number of steps for this work order
                "progress_percentage": ((part["current_step_index"] + 1) / len(process_instances)) * 100 if len(process_instances) > 0 else 0
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

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
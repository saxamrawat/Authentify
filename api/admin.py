# Admin API Routers

# Libraries

from typing import Annotated
from fastapi import APIRouter, Depends
from models.models import Users

# Dependencies
from dependencies.database import db_dependency
from dependencies.auth import get_current_user
from dependencies.permissions import require_admin

# Schema
from schemas.maintenance_schema import CleanupResponse

# Services
from services.admin_service import AdminService
from services.maintenance_service import MaintenanceService

router = APIRouter(
    prefix="/admin",
    tags=["admin"]
)


@router.get("/users")
async def get_all_users(admin_user : Annotated[Users, Depends(require_admin)], db : db_dependency):
    return AdminService.get_all_users(db)

@router.post("/{username}/lock")
async def lock_user_account(admin_user : Annotated[Users, Depends(require_admin)], username : str, db : db_dependency):
    return AdminService.lock_user(
        db = db,
        username = username
    )

@router.post("/{username}/unlock")
async def unlock_user_account(admin_user : Annotated[Users, Depends(require_admin)], username : str, db : db_dependency):
    return AdminService.unlock_user(
        db = db,
        username = username
    )

@router.post("/{username}/role")
async def change_user_role(admin_user : Annotated[Users, Depends(require_admin)], username : str, role : str, db : db_dependency):
    return AdminService.change_role(
        db = db,
        admin_user = admin_user,
        username = username,
        role = role
    )

@router.post("/maintenance/cleanup", response_model=CleanupResponse)
def cleanup_system_data(db: db_dependency, admin_user: Annotated[Users, Depends(require_admin)]):

    return MaintenanceService.cleanup_system_data(
        db=db
    )
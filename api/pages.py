# Pages API Routers

# Libraries

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

router = APIRouter()

# Templates
templates = Jinja2Templates(directory="templates")

# Serve Pages
@router.get("/")
async def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
        }
    )

@router.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
        }
    )

@router.get("/dashboard")
async def dashboard_page(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
        }
    )

@router.get("/session-dashboard")
async def session_dashboard_page(request: Request):
    return templates.TemplateResponse(
        "session_dashboard.html",
        {
            "request": request
        }
    )

@router.get("/forgot-password")
async def forgot_password_page(request: Request):
    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request}
    )

@router.get("/reset-password")
async def reset_password_page(request: Request):
    return templates.TemplateResponse(
        "reset_password.html",
        {"request": request}
    )

@router.get("/verify-email")
async def verify_email_page(request: Request):
    return templates.TemplateResponse(
        "verify_email.html",
        {"request": request}
    )

@router.get("/admin")
async def admin_page(request: Request):
    return templates.TemplateResponse(
        "admin.html",
        {"request": request}
    )
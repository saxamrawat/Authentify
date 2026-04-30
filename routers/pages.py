from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

router = APIRouter()

#Templates
templates = Jinja2Templates(directory="templates")

#Serve Pages
@router.get("/")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request" : request})

@router.get("/register")
async def register_page(request : Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.get("/dashboard")
async def dashboard_page(request : Request):
    return templates.TemplateResponse("dashboard.html", {"request" : request})
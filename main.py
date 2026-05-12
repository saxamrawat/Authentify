from fastapi import FastAPI, Request
from routers import auth, pages
import models
from database import engine
from fastapi.staticfiles import StaticFiles

from dotenv import load_dotenv
import os

load_dotenv()

FRONTEND_URL = os.getenv("FRONTEND_URL")

app = FastAPI()

# Mount Static Files
app.mount("/static", StaticFiles(directory="static"), name="static")

models.Base.metadata.create_all(bind=engine)

app.state.frontend_url = FRONTEND_URL

app.include_router(auth.router)
app.include_router(pages.router)
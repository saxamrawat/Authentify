# Main

# Libraries

from fastapi import FastAPI
from api import auth, pages, admin, session
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# Mount Static Files
app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(pages.router)
app.include_router(session.router)
from fastapi import FastAPI, Request
from routers import auth, pages
import models
from database import engine, Base
from fastapi.staticfiles import StaticFiles


app = FastAPI()

#Mount Static Files
app.mount("/static", StaticFiles(directory="static"), name="static")

models.Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(pages.router)
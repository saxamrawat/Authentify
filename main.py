from fastapi import FastAPI
from routers import auth
import models
from database import engine, Base


app = FastAPI()

models.Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
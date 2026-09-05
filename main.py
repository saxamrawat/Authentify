# Main

# Libraries

from contextlib import asynccontextmanager
from fastapi import FastAPI
from api import auth, pages, admin, session, health
from fastapi.staticfiles import StaticFiles

# Infrastructure
from infrastructure.redis.client import RedisManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    redis_manager = RedisManager()

    try:
        await redis_manager.connect()

        app.state.redis = redis_manager.client

        yield

    finally:
        await redis_manager.close()


app = FastAPI(
    lifespan=lifespan
)

# Mount Static Files
app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(pages.router)
app.include_router(session.router)
app.include_router(health.router)
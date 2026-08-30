# Health API

from fastapi import APIRouter, Request
from starlette import status


router = APIRouter(
    prefix="/health",
    tags=["Health"]
)


@router.get("/redis")
async def redis_health(request: Request):
    redis = request.app.state.redis

    try:
        await redis.ping()

        return {
            "status": "healthy",
            "redis": "available"
        }

    except Exception:
        return {
            "status": "unhealthy",
            "redis": "unavailable"
        }
# Redis Dependencies

# Libraries

from fastapi import Request
from redis.asyncio import Redis

# Services
from services.revocation import RevocationStore
from services.rate_limiter import RateLimiter

# Infrastructure
from infrastructure.redis.revocation import RedisRevocationStore
from infrastructure.redis.rate_limiter import RedisRateLimiter


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_revocation_store(request: Request) -> RevocationStore:
    return RedisRevocationStore(
        request.app.state.redis
    )

def get_rate_limiter(request: Request) -> RateLimiter:
    return RedisRateLimiter(
        request.app.state.redis
    )
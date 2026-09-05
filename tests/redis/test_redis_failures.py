import pytest
from unittest.mock import AsyncMock, MagicMock
from redis.exceptions import ConnectionError

from infrastructure.redis.revocation import RedisRevocationStore
from infrastructure.redis.rate_limiter import RedisRateLimiter
from services.revocation import RevocationStoreError
from services.rate_limiter import RateLimiterError


@pytest.mark.asyncio
async def test_revocation_store_translates_redis_error():
    redis_client = AsyncMock()

    redis_client.exists.side_effect = ConnectionError(
        "Redis unavailable"
    )

    store = RedisRevocationStore(redis_client)

    with pytest.raises(RevocationStoreError):
        await store.is_jti_revoked("test-jti")


@pytest.mark.asyncio
async def test_rate_limiter_translates_redis_error():
    redis_client = MagicMock()

    script = AsyncMock(
        side_effect=ConnectionError(
            "Redis unavailable"
        )
    )

    redis_client.register_script.return_value = script

    rate_limiter = RedisRateLimiter(redis_client)

    with pytest.raises(RateLimiterError):
        await rate_limiter.is_allowed(
            key="test:key",
            limit=5,
            window_seconds=60,
        )
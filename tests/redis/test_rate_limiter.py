import pytest
from uuid import uuid4

from infrastructure.redis.rate_limiter import RedisRateLimiter


@pytest.fixture
def rate_limiter(redis_client):
    return RedisRateLimiter(redis_client)


@pytest.mark.asyncio
async def test_requests_are_allowed_under_limit(rate_limiter):
    key = f"test:ratelimit:{uuid4()}"

    for _ in range(5):
        allowed = await rate_limiter.is_allowed(
            key=key,
            limit=5,
            window_seconds=60,
        )

        assert allowed is True


@pytest.mark.asyncio
async def test_request_is_rejected_after_limit(rate_limiter):
    key = f"test:ratelimit:{uuid4()}"

    for _ in range(5):
        await rate_limiter.is_allowed(
            key=key,
            limit=5,
            window_seconds=60,
        )

    allowed = await rate_limiter.is_allowed(
        key=key,
        limit=5,
        window_seconds=60,
    )

    assert allowed is False


@pytest.mark.asyncio
async def test_rate_limit_counter_has_ttl(
    rate_limiter,
    redis_client,
):
    key = f"test:ratelimit:{uuid4()}"

    await rate_limiter.is_allowed(
        key=key,
        limit=5,
        window_seconds=60,
    )

    ttl = await redis_client.ttl(key)

    assert 0 < ttl <= 60


@pytest.mark.asyncio
async def test_rate_limit_uses_shared_counter(
    rate_limiter,
    redis_client,
):
    key = f"test:ratelimit:{uuid4()}"

    first = await rate_limiter.is_allowed(
        key=key,
        limit=2,
        window_seconds=60,
    )

    second = await rate_limiter.is_allowed(
        key=key,
        limit=2,
        window_seconds=60,
    )

    third = await rate_limiter.is_allowed(
        key=key,
        limit=2,
        window_seconds=60,
    )

    assert first is True
    assert second is True
    assert third is False

    value = await redis_client.get(key)

    assert int(value) == 3
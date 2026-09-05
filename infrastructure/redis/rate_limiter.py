# Redis Rate Limiter

from redis.asyncio import Redis
from redis.exceptions import RedisError
from services.rate_limiter import RateLimiter, RateLimiterError


RATE_LIMIT_SCRIPT = """
local current = redis.call("INCR", KEYS[1])

if current == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end

return current
"""

class RedisRateLimiter(RateLimiter):

    def __init__(self, redis: Redis):
        self._redis = redis
        self._script = redis.register_script(
            RATE_LIMIT_SCRIPT
        )

    async def is_allowed(self, key: str, limit: int, window_seconds: int) -> bool:

        try:
            current = await self._script(
                keys=[key],
                args=[window_seconds],
            )

            return int(current) <= limit

        except RedisError as exc:
            raise RateLimiterError(
                "Rate limiter unavailable."
            ) from exc
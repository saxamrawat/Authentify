# Rate Limiter Abstraction

from typing import Protocol


class RateLimiter(Protocol):

    async def is_allowed(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> bool:
        ...

class RateLimiterError(Exception):
    """
    Raised when the rate limiter cannot determine
    whether a request is allowed.
    """
    pass
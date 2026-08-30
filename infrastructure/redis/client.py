# Redis Infrastructure

import logging

from redis.asyncio import Redis, BlockingConnectionPool

# Core
from core.config import (
    REDIS_URL,
    REDIS_SOCKET_CONNECT_TIMEOUT,
    REDIS_SOCKET_TIMEOUT,
    REDIS_POOL_TIMEOUT,
    REDIS_MAX_CONNECTIONS,
    REDIS_HEALTH_CHECK_INTERVAL,
)


logger = logging.getLogger(__name__)


class RedisManager:
    """
    Manages the application-wide Redis client and connection pool.
    """

    def __init__(self):
        self._pool = BlockingConnectionPool.from_url(
            REDIS_URL,
            max_connections=REDIS_MAX_CONNECTIONS,
            timeout=REDIS_POOL_TIMEOUT,
            socket_connect_timeout=REDIS_SOCKET_CONNECT_TIMEOUT,
            socket_timeout=REDIS_SOCKET_TIMEOUT,
            health_check_interval=REDIS_HEALTH_CHECK_INTERVAL,
            decode_responses=True,
            protocol=3,
            legacy_responses=False,
        )

        self._client = Redis(
            connection_pool=self._pool
        )

    @property
    def client(self) -> Redis:
        return self._client

    async def connect(self) -> None:
        """
        Verify that Redis is reachable.
        """
        try:
            await self._client.ping()
            logger.info("Redis connection established.")

        except Exception:
            logger.exception("Failed to connect to Redis.")
            raise

    async def health_check(self) -> bool:
        """
        Check whether Redis is currently reachable.
        """
        try:
            await self._client.ping()
            return True

        except Exception:
            logger.exception("Redis health check failed.")
            return False

    async def close(self) -> None:
        """
        Close the Redis client and its connection pool.
        """
        await self._client.aclose(
            close_connection_pool=False
        )

        await self._pool.aclose()

        logger.info("Redis connection pool closed.")
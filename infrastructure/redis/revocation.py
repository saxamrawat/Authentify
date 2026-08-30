# Redis Revocation Store

# Libraries
from uuid import UUID

from redis.asyncio import Redis
from redis.exceptions import RedisError

# Services
from services.revocation import (
    RevocationStore,
    RevocationStoreError,
)


class RedisRevocationStore(RevocationStore):
    """
    Redis-backed implementation of the authentication
    revocation store.
    """

    JTI_PREFIX = "auth:revoked:jti:"
    SESSION_PREFIX = "auth:revoked:session:"

    def __init__(self, redis_client: Redis):
        self._redis = redis_client

    @staticmethod
    def _validate_ttl(ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")

    @staticmethod
    def _validate_jti(jti: str) -> None:
        if not jti:
            raise ValueError("jti must not be empty")

    @staticmethod
    def _validate_session_id(session_id: UUID) -> None:
        if not session_id:
            raise ValueError("session_id must not be empty")

    @classmethod
    def _jti_key(cls, jti: str) -> str:
        return f"{cls.JTI_PREFIX}{jti}"

    @classmethod
    def _session_key(cls, session_id: UUID) -> str:
        return f"{cls.SESSION_PREFIX}{session_id}"

    async def revoke_jti(
        self,
        jti: str,
        ttl_seconds: int,
    ) -> None:

        self._validate_jti(jti)
        self._validate_ttl(ttl_seconds)

        key = self._jti_key(jti)

        try:
            await self._redis.set(
                key,
                "1",
                ex=ttl_seconds,
                nx=True,
            )

        except RedisError as exc:
            raise RevocationStoreError(
                "Unable to revoke access-token JTI."
            ) from exc

    async def is_jti_revoked(
        self,
        jti: str,
    ) -> bool:

        self._validate_jti(jti)

        key = self._jti_key(jti)

        try:
            return bool(
                await self._redis.exists(key)
            )

        except RedisError as exc:
            raise RevocationStoreError(
                "Unable to check access-token JTI revocation."
            ) from exc

    async def revoke_session(
        self,
        session_id: UUID,
        ttl_seconds: int,
    ) -> None:

        self._validate_session_id(session_id)
        self._validate_ttl(ttl_seconds)

        key = self._session_key(session_id)

        try:
            await self._redis.set(
                key,
                "1",
                ex=ttl_seconds,
                nx=True,
            )

        except RedisError as exc:
            raise RevocationStoreError(
                "Unable to revoke session."
            ) from exc

    async def is_session_revoked(
        self,
        session_id: UUID,
    ) -> bool:

        self._validate_session_id(session_id)

        key = self._session_key(session_id)

        try:
            return bool(
                await self._redis.exists(key)
            )

        except RedisError as exc:
            raise RevocationStoreError(
                "Unable to check session revocation."
            ) from exc
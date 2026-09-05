# Revocation Store

# Libraries
from abc import ABC, abstractmethod
from uuid import UUID


class RevocationStoreError(Exception):
    """
    Raised when the revocation store cannot complete a
    security-critical operation.
    """
    pass


class RevocationStore(ABC):
    """
    Authentication-oriented abstraction for temporary
    token/session revocation state.
    """

    @abstractmethod
    async def revoke_jti(
        self,
        jti: str,
        ttl_seconds: int,
    ) -> None:
        """
        Mark a specific access-token JTI as revoked.

        The revocation entry must remain available for at least
        the remaining lifetime of the corresponding access token.
        """
        raise NotImplementedError

    @abstractmethod
    async def is_jti_revoked(
        self,
        jti: str,
    ) -> bool:
        """
        Return True if the access-token JTI is currently revoked.
        """
        raise NotImplementedError

    @abstractmethod
    async def revoke_session(
        self,
        session_id: UUID,
        ttl_seconds: int,
    ) -> None:
        """
        Mark a session as revoked.
        """
        raise NotImplementedError

    @abstractmethod
    async def is_session_revoked(
        self,
        session_id: UUID,
    ) -> bool:
        """
        Return True if the session is currently revoked.
        """
        raise NotImplementedError
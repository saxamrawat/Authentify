import pytest
from uuid import uuid4

from infrastructure.redis.revocation import RedisRevocationStore


@pytest.fixture
def revocation_store(redis_client):
    return RedisRevocationStore(redis_client)


@pytest.mark.asyncio
async def test_jti_not_revoked_initially(revocation_store):
    jti = str(uuid4())

    result = await revocation_store.is_jti_revoked(jti)

    assert result is False


@pytest.mark.asyncio
async def test_jti_can_be_revoked(revocation_store):
    jti = str(uuid4())

    await revocation_store.revoke_jti(
        jti=jti,
        ttl_seconds=60,
    )

    result = await revocation_store.is_jti_revoked(jti)

    assert result is True


@pytest.mark.asyncio
async def test_session_not_revoked_initially(revocation_store):
    session_id = uuid4()

    result = await revocation_store.is_session_revoked(
        session_id
    )

    assert result is False


@pytest.mark.asyncio
async def test_session_can_be_revoked(revocation_store):
    session_id = uuid4()

    await revocation_store.revoke_session(
        session_id=session_id,
        ttl_seconds=60,
    )

    result = await revocation_store.is_session_revoked(
        session_id
    )

    assert result is True


@pytest.mark.asyncio
async def test_jti_revocation_has_ttl(
    revocation_store,
    redis_client,
):
    jti = str(uuid4())

    await revocation_store.revoke_jti(
        jti=jti,
        ttl_seconds=60,
    )

    key = f"auth:revoked:jti:{jti}"

    ttl = await redis_client.ttl(key)

    assert 0 < ttl <= 60


@pytest.mark.asyncio
async def test_session_revocation_has_ttl(
    revocation_store,
    redis_client,
):
    session_id = uuid4()

    await revocation_store.revoke_session(
        session_id=session_id,
        ttl_seconds=60,
    )

    key = f"auth:revoked:session:{session_id}"

    ttl = await redis_client.ttl(key)

    assert 0 < ttl <= 60


@pytest.mark.asyncio
async def test_empty_jti_is_rejected(revocation_store):
    with pytest.raises(ValueError):
        await revocation_store.revoke_jti(
            jti="",
            ttl_seconds=60,
        )


@pytest.mark.asyncio
async def test_invalid_ttl_is_rejected(revocation_store):
    jti = str(uuid4())

    with pytest.raises(ValueError):
        await revocation_store.revoke_jti(
            jti=jti,
            ttl_seconds=0,
        )
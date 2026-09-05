import os
from pathlib import Path

import pytest
import pytest_asyncio
import redis.asyncio as redis
from dotenv import load_dotenv

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from dependencies.database import get_db
from main import app


TEST_ENV_FILE = Path(__file__).parent.parent / ".env.test"

load_dotenv(TEST_ENV_FILE)


# TEST REDIS SETUP

TEST_REDIS_URL = os.getenv("TEST_REDIS_URL")

if not TEST_REDIS_URL:
    raise RuntimeError(
        "TEST_REDIS_URL is not configured."
    )


@pytest_asyncio.fixture
async def redis_client():
    client = redis.Redis.from_url(
        TEST_REDIS_URL,
        decode_responses=True,
    )

    await client.flushdb()

    try:
        yield client

    finally:
        await client.flushdb()
        await client.aclose()


# TEST DATABASE SETUP

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")

if not TEST_DATABASE_URL:
    raise RuntimeError(
        "TEST_DATABASE_URL is not configured."
    )

if "authentication_project_test" not in TEST_DATABASE_URL:
    raise RuntimeError(
        "Tests must use the dedicated authentication_project_test database."
    )


test_engine = create_engine(TEST_DATABASE_URL)

TestSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
)


@pytest.fixture
def db_session():
    """Provide a database session and clean test data after each test."""

    db = TestSessionLocal()

    try:
        yield db

    finally:
        db.rollback()

        # Delete child records before parent records because of foreign keys.
        db.execute(
            text("DELETE FROM user_sessions")
        )
        db.execute(
            text("DELETE FROM refresh_tokens")
        )
        db.execute(
            text("DELETE FROM password_reset")
        )
        db.execute(
            text("DELETE FROM email_verification")
        )
        db.execute(
            text("DELETE FROM users")
        )

        db.commit()
        db.close()


@pytest.fixture
def client(db_session):
    """Provide a FastAPI test client using the isolated test database."""

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
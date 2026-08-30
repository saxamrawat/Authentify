import os
from pathlib import Path

import pytest_asyncio
import redis.asyncio as redis
from dotenv import load_dotenv


TEST_ENV_FILE = Path(__file__).parent.parent / ".env.test"

load_dotenv(TEST_ENV_FILE)

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
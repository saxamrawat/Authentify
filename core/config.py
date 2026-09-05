# Core Configs

# Libraries

import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

FRONTEND_URL = os.getenv("FRONTEND_URL")

RESEND_API_KEY = os.getenv("RESEND_API_KEY")

EMAIL_FROM = os.getenv("EMAIL_FROM")

# Redis
REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://localhost:6379/0"
)

REDIS_SOCKET_CONNECT_TIMEOUT = float(
    os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT", "2.0")
)

REDIS_SOCKET_TIMEOUT = float(
    os.getenv("REDIS_SOCKET_TIMEOUT", "2.0")
)

REDIS_POOL_TIMEOUT = float(
    os.getenv("REDIS_POOL_TIMEOUT", "1.0")
)

REDIS_MAX_CONNECTIONS = int(
    os.getenv("REDIS_MAX_CONNECTIONS", "20")
)

REDIS_HEALTH_CHECK_INTERVAL = int(
    os.getenv("REDIS_HEALTH_CHECK_INTERVAL", "30")
)

APP_NAME = "Authentify"

APP_VERSION = "3.0"
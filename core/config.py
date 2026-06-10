# app/core/config.py

import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

FRONTEND_URL = os.getenv("FRONTEND_URL")

RESEND_API_KEY = os.getenv("RESEND_API_KEY")

APP_NAME = "Authentify"

APP_VERSION = "3.0"
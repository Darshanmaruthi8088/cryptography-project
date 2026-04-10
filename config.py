"""Application configuration."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
OUTPUT_FOLDER = BASE_DIR / "output"
LOG_FOLDER = BASE_DIR / "logs"

MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB upload limit
MAX_TEXT_LENGTH = 100_000

ALLOWED_IMAGE_EXTENSIONS = {
    ".png",
    ".bmp",
    ".gif",
    ".tif",
    ".tiff",
    ".webp",
    ".jpg",
    ".jpeg",
    ".jfif",
}
ALLOWED_SCAN_EXTENSIONS = {".gif"}

APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", "CYBERKEY")
DEFAULT_PBKDF2_ITERATIONS = int(os.environ.get("PBKDF2_ITERATIONS", "3000"))

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_REQUESTS = 60

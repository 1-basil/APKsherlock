# backend/config.py

from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # API Keys
    MISTRAL_API_KEY:      Optional[str] = None
    OPENAI_API_KEY:       Optional[str] = None
    GEMINI_API_KEY:       Optional[str] = None
    VIRUSTOTAL_API_KEY:   Optional[str] = None
    ABUSEIPDB_API_KEY:    Optional[str] = None
    SHODAN_API_KEY:       Optional[str] = None

    # Database
    DATABASE_URL:         str = "postgresql://user:pass@localhost/forensicdroid"
    REDIS_URL:            str = "redis://localhost:6379"

    # Storage
    UPLOAD_DIR:           str = "./uploads"
    REPORTS_DIR:          str = "./reports"
    EXTRACTED_DIR:        str = "./extracted"

    # Emulator
    EMULATOR_HOST:        str = "localhost"
    EMULATOR_PORT:        int = 5554
    ADB_PATH:             str = "C:\\Users\\bbbba\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe"

    # Analysis
    MAX_APK_SIZE_MB:      int = 100
    ANALYSIS_TIMEOUT_SEC: int = 300

    class Config:
        env_file = ".env"

settings = Settings()

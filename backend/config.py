# backend/config.py

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    # API Keys
    MISTRAL_API_KEY:      Optional[str] = None
    OPENAI_API_KEY:       Optional[str] = None
    GEMINI_API_KEY:       Optional[str] = None
    GROQ_API_KEY:         Optional[str] = None
    VIRUSTOTAL_API_KEY:   Optional[str] = None
    ABUSEIPDB_API_KEY:    Optional[str] = None
    SHODAN_API_KEY:       Optional[str] = None
    ANYRUN_API_KEY:       Optional[str] = None

    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    OPENROUTER_MODEL: str = "google/gemini-2.5-flash"
    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

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

    # Forensic Evidence / Court Reporting Defaults
    EXAMINER_NAME:        str = "Senior Digital Forensics Analyst"
    CASE_NUMBER:          str = "CASE-2026-0705A"
    TOOL_VERSION:         str = "v2.4.1-Community"

    class Config:
        env_file = ".env"

settings = Settings()

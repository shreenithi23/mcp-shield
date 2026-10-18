"""Configuration settings for MCP Shield."""

import os
from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ENVIRONMENT: str = Field(default="development", description="Runtime environment")
    SERVER_HOST: str = Field(default="0.0.0.0")
    SERVER_PORT: int = Field(default=8000)
    BASE_URL: str = Field(default="http://localhost:8000")

    # Storage
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://shield:shield_secret@localhost:5432/mcp_shield"
    )
    SQLITE_FALLBACK_URL: str = Field(default="sqlite+aiosqlite:///./mcp_shield.db")
    USE_SQLITE_FALLBACK: bool = Field(default=True)
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    REDIS_ENABLED: bool = Field(default=True)

    # Logging
    ACCESS_LOG_PATH: str = Field(default="access.log")
    ACCESS_LOG_MAX_BYTES: int = Field(default=10 * 1024 * 1024)  # 10MB
    ACCESS_LOG_BACKUP_COUNT: int = Field(default=5)

    # Cryptography & JWT
    JWT_KEY_ID: str = Field(default="mcp-shield-rs256-v1")
    JWT_PRIVATE_KEY_PEM: Optional[str] = None
    JWT_PRIVATE_KEY_PATH: Optional[str] = None
    ACCESS_TOKEN_EXPIRE_SECONDS: int = Field(default=300)  # 5 minutes
    AUTH_CODE_EXPIRE_SECONDS: int = Field(default=300)     # 5 minutes

    # Upstream IdP
    IDP_PROVIDER: str = Field(default="mock")  # mock | google | entra
    IDP_CLIENT_ID: Optional[str] = None
    IDP_CLIENT_SECRET: Optional[str] = None
    IDP_DISCOVERY_URL: Optional[str] = None


settings = Settings()

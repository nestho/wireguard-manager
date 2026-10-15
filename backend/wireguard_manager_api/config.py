"""Typed configuration. Production secrets must be supplied through the environment."""
from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WGM_", env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./wireguard-manager.db"
    jwt_secret: str = Field(default="", repr=False)
    encryption_key: str = Field(default="", repr=False)
    access_token_minutes: int = 15
    bootstrap_admin_username: str = ""
    bootstrap_admin_password: str = Field(default="", repr=False)
    allowed_origins: str = "http://localhost:5173"
    allow_public_router_hosts: bool = False
    allow_public_linux_hosts: bool = False
    enable_peer_mutations: bool = False

@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.jwt_secret and len(settings.jwt_secret) < 32:
        raise ValueError("WGM_JWT_SECRET must be at least 32 characters")
    return settings

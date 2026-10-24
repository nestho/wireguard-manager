"""Typed configuration. Production secrets must be supplied through the environment."""
from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WGM_", env_file=".env", extra="ignore")
    environment: str = Field(default="development", validation_alias="WGM_ENV")
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
    enable_linux_mutations: bool = False
    enable_linux_optimizer_mutations: bool = False


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.jwt_secret and len(settings.jwt_secret) < 32:
        raise ValueError("WGM_JWT_SECRET must be at least 32 characters")
    if settings.environment.lower() == "production":
        if len(settings.jwt_secret) < 32:
            raise ValueError("WGM_JWT_SECRET is required and must be at least 32 characters in production")
        if not settings.encryption_key:
            raise ValueError("WGM_ENCRYPTION_KEY is required in production")
        if settings.enable_peer_mutations or settings.enable_linux_mutations or settings.enable_linux_optimizer_mutations:
            # Explicit opt-in remains possible, but deployment defaults deliberately keep all mutations disabled.
            pass
    return settings

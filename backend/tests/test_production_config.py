import pytest
from cryptography.fernet import Fernet

from wireguard_manager_api.config import get_settings


def _clear_settings_cache():
    get_settings.cache_clear()


def test_wgm_env_selects_production_and_requires_secrets(monkeypatch):
    monkeypatch.setenv("WGM_ENV", "production")
    monkeypatch.setenv("WGM_JWT_SECRET", "j" * 48)
    monkeypatch.setenv("WGM_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("WGM_ENVIRONMENT", raising=False)
    _clear_settings_cache()
    try:
        settings = get_settings()
        assert settings.environment == "production"
    finally:
        _clear_settings_cache()


def test_production_mode_fails_closed_without_jwt_secret(monkeypatch):
    monkeypatch.setenv("WGM_ENV", "production")
    monkeypatch.delenv("WGM_JWT_SECRET", raising=False)
    monkeypatch.setenv("WGM_ENCRYPTION_KEY", Fernet.generate_key().decode())
    _clear_settings_cache()
    try:
        with pytest.raises(ValueError, match="WGM_JWT_SECRET"):
            get_settings()
    finally:
        _clear_settings_cache()

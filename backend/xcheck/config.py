from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    data_dir: Path = Path("data")
    static_dir: Path = Path("static")
    database_url: str = "sqlite:///data/xcheck.db"
    whitelist_api_url: str = "http://host.docker.internal:8085/api/v1/whitelist/query"
    threatbook_api_url: str = "https://api.threatbook.cn/v3/scene/ip_reputation"
    threatbook_api_key: str = ""
    upload_max_bytes: int = 524_288_000
    zip_max_members: int = 20
    zip_max_uncompressed_bytes: int = 2_147_483_648
    threatbook_batch_size: int = Field(default=100, ge=1, le=100)
    threatbook_safe_ips_per_minute: int = Field(default=800, ge=1, le=1000)
    threatbook_daily_budget: int = Field(default=10_000, ge=1)
    threatbook_max_retries: int = Field(default=3, ge=0, le=3)
    app_timezone: str = "Asia/Shanghai"
    ui_language: Literal["en-US", "zh-CN"] = "en-US"
    theme_id: Literal[
        "threatbook-red",
        "intelligence-blue",
        "eye-care",
        "midnight-violet",
        "amber-sand",
        "ocean-mist",
    ] = "threatbook-red"
    homepage_mode: Literal["overview", "landscape", "operations"] = "overview"
    motion_intensity: Literal["off", "subtle", "medium", "strong"] = "medium"


@lru_cache
def get_settings() -> Settings:
    return Settings()

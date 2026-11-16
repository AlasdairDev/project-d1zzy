from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mode: str = "development"

    # Database
    database_url: str = "postgresql+asyncpg://d1zzy:d1zzy@db:5432/project_d1zzy_market"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # Security
    secret_key: str = "change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    cookie_secure: bool = False
    csrf_max_age_seconds: int = 28800
    rate_limit_per_minute: int = 60
    # Additional JWT secret keys for key rotation (comma-separated base64-encoded keys)
    additional_jwt_secrets: str = ""
    # Old JWT secret key for token validation during key rotation (base64-encoded)
    old_jwt_secret: str = ""
    # 32-byte base64 keys. MARKET_KEY encrypts listing/offer/rating blobs at rest;
    # SERVER_SIGNING_SEED signs writes made through the no-JS fallback forms.
    market_key: str = ""
    server_signing_seed: str = ""
    auto_hide_report_threshold: int = 5

    # Stripe
    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_currency: str = "usd"

    # PayMongo (GCash, Maya, Cards, Bank Transfer)
    paymongo_secret_key: str = ""
    paymongo_public_key: str = ""
    paymongo_webhook_secret: str = ""

    # BTCPay
    btcpay_url: str = ""
    btcpay_api_key: str = ""
    btcpay_store_id: str = ""
    btcpay_webhook_secret: str = ""

    # Monero
    monero_rpc_url: str = ""
    monero_daemon_url: str = "http://monerod:18081/json_rpc"
    monero_rpc_user: str = ""
    monero_rpc_password: str = ""
    monero_network: str = "testnet"
    monero_wallet_name: str = "d1zzy-market"
    monero_wallet_password: str = ""

    # IPFS
    ipfs_api_url: str = "http://ipfs:5001/api/v0"
    ipfs_gateway_url: str = "http://ipfs:8080/ipfs/"
    max_upload_bytes: int = 5 * 1024 * 1024

    # Email
    email_from: str = "noreply@d1zzy.local"
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_user: str = ""
    smtp_password: str = ""

    # Tor
    tor_hostname_file: str = "/run/tor-export/hostname"

    # App
    public_base_url: str = "http://localhost:8000"
    # Published in /.well-known/security.txt. Forks should point this at their own channel.
    security_contact: str = "https://github.com/AlasdairDev/project-d1zzy/security/advisories/new"
    seed_demo_data: bool = True
    log_level: str = "INFO"

    base_dir: Path = Field(default=Path(__file__).resolve().parent, exclude=True)

    @property
    def is_dev(self) -> bool:
        return self.mode == "development"

    @property
    def stripe_enabled(self) -> bool:
        return self.stripe_secret_key.startswith("sk_test_") and "..." not in self.stripe_secret_key

    @property
    def btcpay_enabled(self) -> bool:
        return bool(self.btcpay_url and self.btcpay_api_key and self.btcpay_api_key != "...")

    @property
    def monero_enabled(self) -> bool:
        return bool(self.monero_rpc_url)

    @property
    def paymongo_enabled(self) -> bool:
        return bool(self.paymongo_secret_key and self.paymongo_secret_key.startswith("sk_"))

    def assert_production_safe(self) -> None:
        """Fail fast when a production deployment still uses development defaults."""
        if self.mode != "production":
            return
        problems = []
        database = urlsplit(self.database_url)
        if not database.password or database.password == "d1zzy":
            problems.append("DATABASE_URL still uses the default database password")
        if self.secret_key in {"", "change-me"}:
            problems.append("SECRET_KEY is unset or the development default")
        if not self.market_key:
            problems.append("MARKET_KEY is unset")
        if not self.server_signing_seed:
            problems.append("SERVER_SIGNING_SEED is unset")
        if self.seed_demo_data:
            problems.append("SEED_DEMO_DATA is enabled")
        if not self.cookie_secure:
            problems.append("COOKIE_SECURE is false")
        if problems:
            raise RuntimeError("unsafe production configuration: " + "; ".join(problems))

    def onion_hostname(self) -> str | None:
        try:
            return Path(self.tor_hostname_file).read_text().strip() or None
        except OSError:
            return None


@lru_cache
def get_settings() -> Settings:
    return Settings()


def clear_settings_cache() -> None:
    """Clear the settings cache. Useful for testing when environment variables change."""
    get_settings.cache_clear()

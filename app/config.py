from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Customer NetBox: where discovered hosts are written, and where
    # site prefixes are read from.
    NETBOX_URL: str
    NETBOX_TOKEN: str
    NETBOX_CUSTOMER_NAME: str
    NETBOX_TENANT_ID: int
    NETBOX_SYNC_INTERVAL: int = 86400
    # Set false for dev/test NetBox instances with self-signed certificates.
    # Applies to both the customer and GT-T NetBox clients.
    NETBOX_VERIFY_SSL: bool = True

    # GT-T NetBox: read-only source of the managed-device list.
    GTT_NETBOX_URL: str
    GTT_NETBOX_TOKEN: str
    # Extra query string applied to the GTT device/VM list calls so ops can
    # scope the sync (e.g. "status=active&tag=halo&limit=0") without a code change.
    GTT_NETBOX_QUERY_PARAMS: str = "status=active&limit=0"

    # CMD GraphQL API — optional; cmd endpoints report "down" when unset.
    CMD_API_URL: str = ""
    CMD_TOKEN_URL: str = ""
    CMD_CLIENT_ID: str = ""
    CMD_CLIENT_SECRET: str = ""
    CMD_SCOPE: str = ""

    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None

    # Discovery / auto-registration pipeline. A "sighting" is one reporter
    # tick in which the host was active, not one raw event.
    DISCOVERY_MIN_SIGHTINGS: int = 5
    DISCOVERY_MIN_DURATION_SECONDS: int = 3600
    DISCOVERY_SIGHTING_TTL: int = 172800
    DISCOVERY_PROMOTE_INTERVAL: int = 300
    DISCOVERY_MAX_CREATES_PER_RUN: int = 20
    DISCOVERY_AUTOCREATE_ENABLED: bool = False


settings = Settings()

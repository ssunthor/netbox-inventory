from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Customer NetBox: where discovered hosts are written, and where
    # site prefixes are read from.
    NETBOX_URL: str
    NETBOX_TOKEN: str
    # Objects written to the customer NetBox are tenanted under a tenant
    # with this name, created if absent (numeric ids don't transfer
    # between instances, so NETBOX_TENANT_ID is never used for writes).
    NETBOX_CUSTOMER_NAME: str
    # The customer's tenant id in the GT-T NetBox — the fallback scope for
    # the managed-host sync when GTT_NETBOX_TENANT_ID is unset.
    NETBOX_TENANT_ID: int
    # Tenant group used only when the customer instance requires tenants to
    # have a group (stock NetBox does not); created if absent.
    NETBOX_TENANT_GROUP: str = "Customers"
    NETBOX_SYNC_INTERVAL: int = 86400
    # Set false for dev/test NetBox instances with self-signed certificates.
    # Applies to both the customer and GT-T NetBox clients.
    NETBOX_VERIFY_SSL: bool = True

    # GT-T NetBox: read-only source of the managed-device list.
    GTT_NETBOX_URL: str
    GTT_NETBOX_TOKEN: str
    # The customer's tenant id IN THE GT-T NETBOX. Only needed when it
    # differs from NETBOX_TENANT_ID (the customer-instance tenant), which is
    # used as the fallback — the sync is always tenant-scoped.
    GTT_NETBOX_TENANT_ID: int | None = None
    # Extra query string applied to the GTT device/VM list calls so ops can
    # scope the sync further (e.g. "status=active&tag=halo&limit=0").
    GTT_NETBOX_QUERY_PARAMS: str = "status=active&limit=0"
    # Mirror the GT-T managed set into the customer NetBox after each sync.
    # GT-T is the record of truth; the customer instance carries a synced
    # copy (objects tagged halo-managed; hosts that leave the managed set
    # are marked offline, never deleted).
    MIRROR_ENABLED: bool = True

    # CMD GraphQL API — optional; cmd endpoints report "down" when unset.
    CMD_API_URL: str = ""
    CMD_TOKEN_URL: str = ""
    CMD_CLIENT_ID: str = ""
    CMD_CLIENT_SECRET: str = ""
    CMD_SCOPE: str = ""

    # Nominatim-compatible geocoder used to place CMD-derived sites on the
    # dashboard map (results cached permanently in Redis). Set
    # GEOCODE_ENABLED=false for air-gapped deployments; sites then simply
    # have no coordinates and stay off the map.
    GEOCODE_ENABLED: bool = True
    GEOCODE_URL: str = "https://nominatim.openstreetmap.org/search"

    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    # Set REDIS_USERNAME for ACL-based auth (e.g. halo_app); leave unset to
    # authenticate as the default user via requirepass.
    REDIS_USERNAME: str | None = None
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

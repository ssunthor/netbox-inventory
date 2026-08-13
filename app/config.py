from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    NETBOX_URL: str 
    NETBOX_TOKEN: str
    NETBOX_CUSTOMER_NAME: str
    NETBOX_TENANT_ID: int 
    NETBOX_SYNC_INTERVAL: int = 86400
    
    GTT_NETBOX_URL: str
    GTT_NETBOX_TOKEN: str

    CMD_API_URL: str
    CMD_TOKEN_URL: str
    CMD_CLIENT_ID: str
    CMD_CLIENT_SECRET: str
    CMD_SCOPE: str

    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None


settings = Settings()
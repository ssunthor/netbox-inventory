from pydantic import BaseModel, Field


class Sighting(BaseModel):
    id: str = Field(description="Telemetry host id — must be a private IPv4 to be tracked")
    name: str | None = None
    sources: list[str] = Field(default_factory=list)
    last_seen: float | None = None
    events: int = 0


class SightingsRequest(BaseModel):
    sightings: list[Sighting] = Field(default_factory=list)


class SightingsResponse(BaseModel):
    accepted: int
    ignored: int
    managed: int
    tracked: int


class ImportRow(BaseModel):
    name: str
    ip: str
    site: str | None = None
    role: str | None = None
    manufacturer: str | None = None
    model: str | None = None


class ImportRequest(BaseModel):
    rows: list[ImportRow] = Field(default_factory=list)


class ImportResult(BaseModel):
    status: str
    name: str | None = None
    ip: str | None = None
    device_id: int | None = None
    reason: str | None = None


class ImportResponse(BaseModel):
    total: int
    created: int
    skipped: int
    failed: int
    results: list[ImportResult] = Field(default_factory=list)


class ImportedHostUpdate(BaseModel):
    """Fields an imported host can be edited on. IP is deliberately excluded -
    see update_imported_host in netbox_write.py."""
    name: str | None = None
    site: str | None = None
    role: str | None = None
    manufacturer: str | None = None
    model: str | None = None

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
    # When true, a row whose IP matches a previously-imported device updates
    # that device's fields instead of being skipped. Never applies to a
    # GTT-managed device match - that always skips regardless of this flag.
    overwrite: bool = False


class ImportResult(BaseModel):
    status: str
    name: str | None = None
    ip: str | None = None
    device_id: int | None = None
    reason: str | None = None


class ImportResponse(BaseModel):
    total: int
    created: int
    updated: int = 0
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
    platform: str | None = None
    os_version: str | None = None


class DiscoveredHostUpdate(BaseModel):
    """Fields a discovered (auto-registered) host can be edited on."""
    name: str | None = None
    site: str | None = None
    role: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    platform: str | None = None
    os_version: str | None = None


class SiteCreate(BaseModel):
    name: str
    status: str = "active"
    description: str | None = None


class SiteUpdate(BaseModel):
    status: str | None = None
    description: str | None = None


class NetworkLocationAssignment(BaseModel):
    """Manual subnet -> site labels from the dashboard's Destinations page.
    site (the slug) is derived from site_name when omitted."""
    prefixes: list[str] = Field(default_factory=list)
    site_name: str
    site: str | None = None


class CveMonitoringTarget(BaseModel):
    """One host to toggle. host_id is "device:N"/"vm:N": for
    source="managed" that is the GTT host_id (resolved to the customer
    NetBox through the mirror map); for source="imported" N is the customer
    NetBox device id as listed by /inventory/imported."""
    host_id: str
    source: str = "managed"


class CveMonitoringRequest(BaseModel):
    targets: list[CveMonitoringTarget] = Field(default_factory=list)
    enabled: bool

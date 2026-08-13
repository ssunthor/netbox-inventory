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

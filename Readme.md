# netbox-inventory

Standalone inventory microservice for the Defense Halo platform. NetBox is
the record of truth for hosts we manage; this service keeps that record in
sync and reconciles it with what telemetry actually sees.

## What it does

- **Managed-host sync** — periodically pulls the managed device/VM list from
  the GT-T NetBox (`GTT_NETBOX_URL`) and site prefixes from the customer
  NetBox (`NETBOX_URL`), normalizes them, and serves a versioned snapshot
  from Redis.
- **Customer-NetBox mirror** — after each sync, upserts the GT-T managed set
  into the customer NetBox (devices, VMs, sites, roles, types, platforms,
  clusters, IPs, primary IP) so the local instance carries a synced copy of
  the record of truth. Mirrored objects are tagged `halo-managed`; unchanged
  hosts are skipped via a stored fingerprint, and hosts that leave the GT-T
  set are marked offline (never deleted). Enabled by default; disable with
  `MIRROR_ENABLED=false`.
- **Sighting tracking** — the halo backend reports batches of
  telemetry-observed hosts. Private (RFC1918) IPv4 hosts that are not already
  managed are tracked as _discovered_.
- **Auto-registration** — discovered hosts that persist past a configurable
  threshold are created in the customer NetBox as placeholder devices (role
  `Discovered`, device type `Unknown`, tag `halo-discovered`, site inferred
  from IP prefix, IP attached and set as primary). Disabled by default via
  `DISCOVERY_AUTOCREATE_ENABLED`.
- **Network locations** — manual subnet→site labels saved from the
  dashboard's Destinations page. Stored in Redis (`inv:prefixes:manual`) so
  they survive syncs, and merged over the NetBox-synced prefix list in every
  served payload (a manual label wins on the same prefix). Each sync also
  rebuilds a site list (`inv:sites`) - the same sites the dashboard's
  Sites tab shows: every customer-created (`halo-site`) DCIM site plus any
  site a managed host is filed under - with
  best-effort coordinates for map plotting: a DCIM site record's own
  latitude/longitude when set, otherwise
  the site's street address geocoded through a Nominatim-compatible endpoint
  (`GEOCODE_URL`, cached permanently in `inv:geocode`; disable with
  `GEOCODE_ENABLED=false` for air-gapped deployments).

## API

All routes live under `/api/v1`.

| Route | Method | Purpose |
| --- | --- | --- |
| `/inventory/managed` | GET | Versioned managed-host snapshot (the backend polls this; `?since_version=` short-circuits unchanged polls) |
| `/inventory/sightings` | POST | Batched telemetry sightings from the backend |
| `/inventory/discovered` | GET | Discovered hosts with tracking/eligible/registered/failed status |
| `/inventory/discovered/{ip}` | DELETE | Delete a learned host: tag-guarded NetBox device delete plus tracking cleanup; 409 for GTT-managed IPs |
| `/inventory/cve-monitoring` | POST | Bulk-toggle the `cve_monitoring` NetBox custom field (record of truth; cached off-list stamps the payloads) |
| `/inventory/network-locations` | GET | Manual subnet→site labels, the merged prefix list, and known sites with coordinates |
| `/inventory/network-locations` | POST | Label subnets with a site (`{"prefixes": [...], "site_name": ...}`; upserts) |
| `/inventory/network-locations` | DELETE | Remove one manual label (`?prefix=CIDR`) |
| `/inventory/status` | GET | Sync and promoter health |
| `/inventory/sync` | POST | Trigger an immediate sync |
| `/inventory/hosts` | GET | Live customer-NetBox view (ops/debug) |
| `/cmd/segment/{id}` | GET | CMD segment-to-site lookup |
| `/health/` | GET | Dependency health (NetBox, CMD, Redis) |

## Running locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then fill in real values
uvicorn app.main:app --reload --port 8020
```

In the platform compose stack the service runs as `netbox-inventory` on port
8020 and uses Redis DB 1 (the halo backend owns DB 0).

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

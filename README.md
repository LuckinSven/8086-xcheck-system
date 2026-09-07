# XCheck IP Reputation Investigation System

[简体中文](README.zh-CN.md)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/LuckinSven/8086-xcheck-system)](https://github.com/LuckinSven/8086-xcheck-system/releases/latest)

XCheck is a self-hosted IP investigation workflow for trusted local networks. It accepts manual IP lists and common log files, streams and validates large inputs, removes duplicates, checks an existing whitelist service, and submits the remaining public IPs to the ThreatBook IP reputation API at a controlled rate.

The application keeps the original input, task history, step checkpoints, whitelist conclusions, ThreatBook batches, diagnostics, and intelligence results in local persistent storage. A 200,000-row CSV is the current acceptance baseline.

![XCheck Overview dashboard with demonstration data](docs/images/xcheck-homepage.png)

> The screenshot uses demonstration data and documentation-only IP address ranges.

## Highlights

- Three switchable live home dashboards: Overview, Threat Landscape, and Operations
- English-first interface with complete Simplified Chinese switching in System Settings
- Six themes, translucent surfaces, ambient light effects, and four motion levels
- Manual, CSV, XLS, XLSX, ZIP, LOG, and JSONL input
- Streaming parsing, IP validation, deduplication, and per-step progress
- Whitelist filtering before any ThreatBook query
- Explicit confirmation to remove current, historical, and inactive whitelist hits
- Adjustable batch size, safe rate, daily budget, and retry limits
- Server-side pagination and filtering for large ThreatBook task histories
- Bounded dashboard aggregates that never load an entire result set into the browser
- Localized TXT and XLSX exports at every processing stage
- Failed-node diagnostics and resumable task checkpoints
- Docker deployment on port `8086`

## Quick start

Requirements: Docker Engine with Docker Compose.

```bash
git clone https://github.com/LuckinSven/8086-xcheck-system.git
cd 8086-xcheck-system
cp .env.example .env
docker compose pull
docker compose up -d --no-build
```

The published image is `ghcr.io/luckinsven/8086-xcheck-system:latest`. To build from source instead, run `docker compose up -d --build`.

Open `http://<server-ip>:8086`. The container listens on `0.0.0.0:8086`, so hosts on the same local network can reach it when the server firewall permits the port.

Check service health:

```bash
curl --fail http://127.0.0.1:8086/api/health
```

## Initial configuration

Open **System Settings** after startup. This is the single place to configure:

- Interface language: English or Simplified Chinese
- Theme: ThreatBook Red (default), Intelligence Blue, Comfort Green, Midnight Violet, Amber Sand, or Ocean Mist
- Homepage: Overview, Threat Landscape, or Operations
- Motion: Off, Subtle, Medium, or Strong
- Whitelist and ThreatBook API endpoints
- ThreatBook API key
- Batch size, safe IP rate, local daily budget, and retry count

Both integrations have real connection tests. Test summaries retain only status, timestamp, latency, and a safe error identifier. The saved ThreatBook API key is never returned by the settings API or displayed in the interface.

`.env` supplies first-start defaults. Settings saved through the interface are stored in the local database and take precedence on later starts.

## Whitelist and ThreatBook workflow

Every task follows the same persisted sequence:

1. Archive the input.
2. Parse and validate IP addresses.
3. Deduplicate addresses while retaining occurrence evidence.
4. Query the whitelist service.
5. Exclude non-public addresses.
6. Ask the operator to remove current, historical, and inactive whitelist hits when any are found.
7. Wait for the operator to start the ThreatBook query.
8. Query ThreatBook in bounded batches and archive the results.

If no whitelist hit is found, the task advances to the ThreatBook confirmation step automatically. Missing, invalid, or unknown whitelist conclusions never bypass the gate. ThreatBook calls are not started automatically: an operator must select **Start ThreatBook query**.

The ThreatBook workspace displays persisted progress, elapsed time, an ETA when enough progress samples exist, the task's configuration snapshot, batch evidence, recent safe diagnostics, and paginated intelligence results. Failed or partially completed work can be retried from its last checkpoint.

## Input formats

The upload control does not restrict a file by its displayed extension; the processing step validates the actual supported format and records a diagnosable error when it cannot parse the input.

| Input type | Supported files | Recognized IP columns |
| --- | --- | --- |
| Attack log | CSV, XLS, XLSX, ZIP, LOG, JSONL | `srcAddress`, `Source Address`, `source_address` |
| Access log | CSV, XLS, XLSX, ZIP, LOG, JSONL | `访问源 IP`, `Source IP`, `source_ip` |

Manual input accepts new lines, spaces, commas, Chinese commas, and semicolons. IPv4 and IPv6 addresses are supported. The default single-file upload limit is 500 MB.

## Exports and history

Each user submission is one history record, regardless of its internal batch count. Task and ThreatBook history are filtered and paginated by the server. ThreatBook history supports IP, malicious status, threat label, country, province, city, severity, confidence, task status, and date filters.

TXT and XLSX exports are available for extracted, valid, invalid, deduplicated, whitelist, post-whitelist, non-public, ThreatBook-ready, completed, malicious, high-confidence malicious, non-malicious, and failed stages. Export headings, workbook names, public-address values, and processing-stage labels follow the current global language. IPs, filenames, request identifiers, external threat labels, locations, and evidence values remain unchanged.

## Data and backups

`compose.yaml` binds the host `./data` directory to `/app/data`. It contains the SQLite database and uploaded source files. Normal `up`, `restart`, and `down` operations preserve this directory. Version 1 intentionally has no history-deletion feature.

Back up the complete `data/` directory before upgrades. For a live SQLite backup, use a method that preserves WAL consistency; otherwise stop the container before copying `xcheck.db`, `xcheck.db-wal`, and `xcheck.db-shm`.

## Security boundary

XCheck intentionally has no login or role system. Only expose port `8086` to a trusted local network. Any user who can reach the service can inspect retained task data, change integration endpoints, and replace or clear the ThreatBook credential.

- Never commit `.env` or `data/`.
- Treat database and backup files as sensitive because the saved ThreatBook key is stored locally.
- Restrict the host firewall to trusted network ranges.
- Do not publish the service directly to the internet without adding authentication, authorization, TLS, and request protections in front of it.
- ZIP uploads are bounded by member count and expanded size and reject path traversal.
- Dashboard and result APIs expose allowlisted structured fields, not raw ThreatBook response JSON.

## Common operations

```bash
docker compose ps
docker compose logs -f --tail=200
docker compose restart
docker compose down
```

Update after backing up `data/`:

```bash
git pull --ff-only
docker compose pull
docker compose up -d --no-build
curl --fail http://127.0.0.1:8086/api/health
```

Use `XCHECK_IMAGE_TAG=v0.1.0 docker compose up -d --no-build` to pin a specific release. Version tags automatically publish matching AMD64 images and a GitHub Release.

Additional operational notes are available in [docs/operations.md](docs/operations.md) (Chinese).

## License

Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution and third-party service information.

ThreatBook and related names may be trademarks of their respective owners. This independent project integrates with third-party services but is not affiliated with or endorsed by those service providers. The license does not grant access to any third-party API or permission to use third-party trademarks beyond applicable law.

## Development checks

Backend:

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check backend tests
PYTHONPATH=backend .venv/bin/pytest -q
```

Frontend:

```bash
cd frontend
npm ci
npm test -- --run
npm run build
```

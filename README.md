# DMARC-analysis

[![CI](https://github.com/JoWe112/dmarc-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/JoWe112/dmarc-analysis/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/JoWe112/dmarc-analysis)](LICENSE)
![Node](https://img.shields.io/badge/node-22-339933?logo=node.js&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/postgresql-external-4169E1?logo=postgresql&logoColor=white)

A self-hosted, container-based analyser for **DMARC aggregate reports** (RFC 7489).
Drop `.xml`, `.zip` or `.gz` reports into the web page (UI in Swedish), and the app parses
them, stores every record **exactly once** in an external PostgreSQL database, alerts a
webhook when too much mail fails authentication, and visualises the history.

No Google Apps Script, no Gmail integration, no local SQLite, and no PVC.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick start (docker compose)](#quick-start-docker-compose)
- [Configuration](#configuration)
- [API reference](#api-reference)
- [Database schema and deduplication](#database-schema-and-deduplication)
- [Alerting](#alerting)
- [Kubernetes deployment](#kubernetes-deployment)
- [Verifying with curl](#verifying-with-curl)
- [Development and tests](#development-and-tests)
- [Security](#security)

---

## Features

| Area | What you get |
|------|--------------|
| **Ingestion** | Drag & drop or paste of `.xml` / `.zip` / `.gz`, unpacked **in the browser** (native `DecompressionStream`, no JS libraries). The API also accepts raw XML or pre-parsed JSON records. |
| **Deduplication** | Deterministic SHA-256 `record_hash` + `INSERT … ON CONFLICT (record_hash) DO NOTHING`, safe for re-ingestion and parallel requests. |
| **Alerting** | Webhook (Slack/Teams/generic JSON) when > 10 % of *newly inserted* mail fails both DKIM and SPF. |
| **Dashboard** | KPI cards (total mail, DMARC pass %, DKIM pass %, SPF pass %), stacked daily volume chart, searchable table with "failed only" and time-range quick filters. |
| **Operations** | `/healthz` with a DB check, idempotent schema migration at startup, graceful shutdown, OpenAPI + Swagger UI at `/docs`. |
| **Deployment** | Multi-stage non-root image (Trivy clean), `docker-compose.yml`, and Kubernetes manifests (Deployment, Service, ConfigMap, Secret, Ingress/HTTPRoute, NetworkPolicy). Works on OpenShift `restricted-v2`. |

## Architecture

```mermaid
flowchart LR
    U[Browser<br/>public/ UI] -- "unpack .zip/.gz<br/>POST /api/reports {xml:[…]}" --> GW
    U -- "GET /api/records" --> GW
    GW[Ingress / Gateway<br/>authentication] --> SVC[Service]
    SVC --> P1[Pod 1<br/>Express API + static UI]
    SVC --> P2[Pod 2<br/>Express API + static UI]
    P1 & P2 -- "pg pool<br/>ON CONFLICT DO NOTHING" --> DB[(External PostgreSQL<br/>dmarc_records)]
    P1 & P2 -. "failed share > 10 %" .-> WH[ALERT_WEBHOOK_URL]
```

```mermaid
sequenceDiagram
    participant B as Browser
    participant A as API
    participant D as PostgreSQL
    participant W as Webhook
    B->>B: unpack .zip/.gz → XML strings
    B->>A: POST /api/reports {xml:[…]}
    A->>A: parse XML → normalise → record_hash
    A->>D: INSERT … ON CONFLICT (record_hash) DO NOTHING RETURNING record_hash
    D-->>A: hashes of new rows
    A->>A: failed share among the NEW rows
    alt share > ALERT_THRESHOLD and webhook set
        A->>W: POST {summary, alerts[domain, policy, reportIds, topIps]}
    end
    A-->>B: {inserted, duplicates, failedPercent, alerts}
```

### Repository layout

| Path | Purpose |
|------|---------|
| `src/server.js` | Entry point: migrate, listen, graceful shutdown |
| `src/app.js` | Express app, routes, error envelope |
| `src/parser.js` | DMARC XML parsing, validation, `record_hash` (single source of truth) |
| `src/repository.js` | All SQL (insert with dedup, filtered history query) |
| `src/alerts.js` | Failure statistics and webhook delivery |
| `src/db.js` | Pool creation (DATABASE_URL or PG\*), idempotent schema |
| `src/config.js` | Environment configuration |
| `public/` | Swedish web UI (vanilla JS, no build step) |
| `db/migrations/001_init.sql` | Same schema as SQL, for manual migration |
| `docs/openapi.yaml` | OpenAPI 3 specification |
| `k8s/` | Kubernetes manifests + `kustomization.yaml` |
| `test/` | Unit tests; `test/integration/` runs against real PostgreSQL |
| `examples/sample-report.xml` | Sample aggregate report |

## Quick start (docker compose)

Prerequisites: Docker with Compose v2.

```bash
git clone https://github.com/JoWe112/dmarc-analysis.git && cd dmarc-analysis
```

```bash
docker compose up -d --build
```

```bash
curl -s localhost:8080/healthz
```

Open <http://localhost:8080> for the UI and <http://localhost:8080/docs> for Swagger UI.

`docker-compose.yml` starts a local PostgreSQL that stands in for the external database. The
app container runs with a read-only root filesystem, a `/tmp` tmpfs, all capabilities dropped,
and `no-new-privileges`, the same as in Kubernetes. To try alerting locally:

```bash
ALERT_WEBHOOK_URL=https://webhook.site/<your-id> docker compose up -d
```

Stop it with `docker compose down` (add `-v` to also delete the local database volume).

## Configuration

All configuration comes from environment variables.

| Variable | Default | K8s source | Description |
|----------|---------|------------|-------------|
| `PORT` | `8080` | ConfigMap | HTTP listen port (unprivileged) |
| `DATABASE_URL` | – | Secret (optional) | Full connection string; overrides the `PG*` variables |
| `PGHOST` / `PGPORT` / `PGDATABASE` | – / `5432` / – | ConfigMap | External PostgreSQL location |
| `PGUSER` / `PGPASSWORD` | – | Secret | Database credentials |
| `PGSSLMODE` | `disable` | ConfigMap | `disable`, `require`/`prefer`/`no-verify` (encrypt, no cert check), `verify-ca`/`verify-full` (verify against system CAs) |
| `PG_POOL_MAX` | `10` | ConfigMap | Connections per pod |
| `ALERT_WEBHOOK_URL` | – | Secret | Webhook for alerts; empty disables alerting |
| `ALERT_THRESHOLD` | `0.10` | ConfigMap | Alert when the failed share is **greater than** this ratio |
| `ALERT_TIMEOUT_MS` | `5000` | ConfigMap | Webhook timeout |
| `MAX_RECORDS` | `5000` | ConfigMap | Row cap for `GET /api/records` |
| `BODY_LIMIT` | `20mb` | ConfigMap | Max request body size |

## API reference

The full spec is in [`docs/openapi.yaml`](docs/openapi.yaml). The running app serves it at
`/openapi.yaml`, with Swagger UI at `/docs`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | `SELECT 1` against PostgreSQL → `200 {"status":"ok"}`, or `503` |
| `GET` | `/api/version` | `{"version":"1.0.0"}` |
| `POST` | `/api/reports` | Ingest records (see below) |
| `GET` | `/api/records` | History with `days` (`7`/`30`/`90`/`all`, default `30`), `failedOnly` (`true`/`false`), `q` (free text) |

### `POST /api/reports`

Accepted request bodies:

| Content-Type | Body |
|--------------|------|
| `application/xml` / `text/xml` | One raw DMARC aggregate report |
| `application/json` | `{"xml": "<feedback>…"}` or `{"xml": ["…", "…"]}` (up to 1000 docs) |
| `application/json` | `{"records": [{"report_date":"2026-11-20","report_id":"…","reporting_org":"…","domain":"…","policy":"…","source_ip":"…","mail_count":1,"disposition":"…","dkim_result":"pass","spf_result":"fail","header_from":"…"}]}` |

Response (`201` if anything new was inserted, otherwise `200`):

```json
{
  "received": 2, "inserted": 2, "duplicates": 0, "uniqueInRequest": 2,
  "failedMails": 30, "totalMails": 150, "failedRate": 0.2, "failedPercent": 20,
  "threshold": 0.1, "alertTriggered": true, "alertSent": true,
  "alerts": [{ "domain": "example.com", "policy": "reject", "reportIds": ["1234…"],
               "failedPercent": 20, "topIps": [{ "ip": "198.51.100.66", "failedMails": 30 }] }]
}
```

`GET /api/records` searches `q` case-insensitively as a literal substring (`%` and `_` are
escaped) across `report_id`, `source_ip`, `reporting_org`, `domain` and `policy`.

### Errors

Every error uses the same envelope:

```json
{ "error": { "code": "VALIDATION_FAILED", "message": "days must be one of 7, 30, 90, all" } }
```

| HTTP | Code | When |
|------|------|------|
| 400 | `VALIDATION_FAILED` / `MALFORMED_REQUEST` | Invalid parameters, malformed JSON, or input that is not a DMARC report |
| 404 | `NOT_FOUND` | Unknown `/api/*` path |
| 413 | `PAYLOAD_TOO_LARGE` | Body exceeds `BODY_LIMIT` |
| 500 | `INTERNAL_ERROR` | Unexpected error (no internals leaked) |
| 503 | `DATABASE_UNAVAILABLE` | PostgreSQL not reachable |

## Database schema and deduplication

The app creates the table and indexes **idempotently at startup**
(`CREATE … IF NOT EXISTS`). The migration runs under a PostgreSQL advisory lock, so several
replicas can start at the same time without racing. If you prefer to run migrations yourself,
apply [`db/migrations/001_init.sql`](db/migrations/001_init.sql):

```bash
psql "$DATABASE_URL" -f db/migrations/001_init.sql
```

The app role then only needs `CONNECT`, plus `SELECT, INSERT` on `dmarc_records` and
`USAGE` on its sequence. The startup migration becomes a no-op, but it still needs
`CREATE` on the schema unless the objects already exist.

| Column | Type |
|--------|------|
| `id` | `BIGSERIAL PRIMARY KEY` |
| `record_hash` | `TEXT NOT NULL UNIQUE` |
| `report_date` | `DATE NOT NULL` (start of the report's `date_range`, UTC) |
| `report_id`, `reporting_org`, `domain`, `policy`, `source_ip`, `disposition`, `dkim_result`, `spf_result`, `header_from` | `TEXT NOT NULL DEFAULT ''` |
| `mail_count` | `INTEGER NOT NULL DEFAULT 0` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT NOW()` |

Indexes: `report_date` and `(domain, source_ip)`.

**`record_hash`** = SHA-256 of the JSON-encoded, ordered array
`[report_id, report_date, reporting_org, domain, policy, source_ip, mail_count, disposition, dkim_result, spf_result, header_from]`.
Values are normalised first (trimmed; domain, policy and results lower-cased). JSON encoding
means a separator inside a value can never make two different records collide. Inserts use
`ON CONFLICT (record_hash) DO NOTHING RETURNING record_hash`, so the API knows exactly which
rows are new, even when the same report is uploaded concurrently.

**DKIM/SPF results** come from `policy_evaluated` (the DMARC-aligned verdict). When that is
missing, the app falls back to the first `auth_results` entry.

## Alerting

1. After each `POST /api/reports`, the API computes the **mail-weighted** failed share of the
   **newly inserted** records only (duplicates never re-trigger alerts). A record fails when
   `dkim_result !== "pass"` **and** `spf_result !== "pass"`.
2. If that share is greater than `ALERT_THRESHOLD` (10 %), `alerts` lists every
   (domain, policy) group that has failed mail. Each entry carries its report IDs, its own
   failure rate and its top 5 failing source IPs.
3. If `ALERT_WEBHOOK_URL` is set, the API POSTs:

```json
{
  "text": "DMARC-larm: 20 % underkända mejl bland nyinlagda poster (30 av 150, tröskel 10 %).\n• example.com (p=reject): 20 %, …",
  "source": "dmarc-analysis",
  "generatedAt": "2026-11-21T13:00:00.000Z",
  "summary": { "failedMails": 30, "totalMails": 150, "failedRate": 0.2, "failedPercent": 20, "threshold": 0.1 },
  "alerts": [{ "domain": "example.com", "policy": "reject", "reportIds": ["…"], "failedPercent": 20, "topIps": [ … ] }]
}
```

The `text` field works directly with Slack and Teams incoming webhooks. A failing webhook
never fails the ingest; the response's `alertSent` shows whether delivery succeeded.

## Kubernetes deployment

```mermaid
flowchart TB
    subgraph ns[Namespace]
      ING[Ingress or HTTPRoute] --> SVC[Service :80]
      SVC --> D[Deployment · replicas 2 · RollingUpdate]
      CM[ConfigMap] -. envFrom .-> D
      SEC[Secret] -. secretKeyRef .-> D
      NP[NetworkPolicy<br/>ingress only from gateway] -. guards .-> D
    end
    D --> PG[(External PostgreSQL)]
```

| Manifest | Notes |
|----------|-------|
| `k8s/deployment.yaml` | `replicas: 2`, `RollingUpdate` (`maxUnavailable: 0`), `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, seccomp `RuntimeDefault`, `/tmp` emptyDir, readiness and liveness probes on `/healthz`, no `runAsUser` (OpenShift assigns one) |
| `k8s/configmap.yaml` | Non-sensitive settings (DB host, SSL mode, threshold, …) |
| `k8s/secret.yaml` | **Example only**: `PGUSER`, `PGPASSWORD`, `ALERT_WEBHOOK_URL`, optional `DATABASE_URL` |
| `k8s/service.yaml` | ClusterIP, port 80 → 8080 |
| `k8s/ingress.yaml` / `k8s/httproute.yaml` | Pick one (Ingress is enabled in the kustomization) |
| `k8s/networkpolicy.yaml` | Pod ingress allowed only from the ingress/gateway namespace |

### 1. Build and push the image

```bash
docker build --build-arg VERSION=1.0.0 -t ghcr.io/jowe112/dmarc-analysis:1.0.0 .
```

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$HOME/.cache/trivy:/root/.cache/trivy" aquasec/trivy:0.69.3 image --severity HIGH,CRITICAL --exit-code 1 ghcr.io/jowe112/dmarc-analysis:1.0.0
```

```bash
docker push ghcr.io/jowe112/dmarc-analysis:1.0.0
```

### 2. Create the Secret (out-of-band, never committed)

```bash
kubectl -n dmarc create secret generic dmarc-analysis-secret --from-literal=PGUSER=dmarc --from-literal=PGPASSWORD='<password>' --from-literal=ALERT_WEBHOOK_URL='<https://hooks…>'
```

### 3. Adjust and apply

Edit `k8s/configmap.yaml` (`PGHOST`, `PGSSLMODE`, …), the hostname in `k8s/ingress.yaml`
or `k8s/httproute.yaml`, and the namespace label in `k8s/networkpolicy.yaml`. Then:

```bash
kubectl -n dmarc apply -k k8s/
```

```bash
kubectl -n dmarc rollout status deploy/dmarc-analysis
```

To use the Gateway API instead of Ingress, swap `ingress.yaml` for `httproute.yaml` in
`k8s/kustomization.yaml`.

> **OpenShift:** the image runs under any arbitrary UID with group 0 (files are `g=u`). Use a
> `Route`, or the commented `policy-group: ingress` selector in the NetworkPolicy.

## Verifying with curl

Set `BASE` to `http://localhost:8080` (compose), your ingress host, or a port-forward
(`kubectl -n dmarc port-forward svc/dmarc-analysis 8080:80`).

```bash
BASE=http://localhost:8080
```

Health check (expect HTTP 200 and `"database":"up"`):

```bash
curl -i "$BASE/healthz"
```

Ingest the sample report as raw XML (first run: `inserted: 2`, `alertTriggered: true`):

```bash
curl -s -X POST -H 'Content-Type: application/xml' --data-binary @examples/sample-report.xml "$BASE/api/reports"
```

Send it again; deduplication should give `inserted: 0, duplicates: 2`:

```bash
curl -s -X POST -H 'Content-Type: application/xml' --data-binary @examples/sample-report.xml "$BASE/api/reports"
```

Ingest a gzipped report (unpacked locally, sent as JSON):

```bash
gunzip -c report.xml.gz | jq -Rs '{xml: .}' | curl -s -X POST -H 'Content-Type: application/json' -d @- "$BASE/api/reports"
```

Ingest pre-parsed JSON records:

```bash
curl -s -X POST -H 'Content-Type: application/json' -d '{"records":[{"report_date":"2026-11-21","report_id":"manual-1","reporting_org":"test","domain":"example.com","policy":"none","source_ip":"192.0.2.1","mail_count":5,"disposition":"none","dkim_result":"pass","spf_result":"pass","header_from":"example.com"}]}' "$BASE/api/reports"
```

Query history:

```bash
curl -s "$BASE/api/records?days=30&failedOnly=true&q=198.51.100" | jq '.count, .records[0]'
```

Validation error (expect HTTP 400 with the error envelope):

```bash
curl -i "$BASE/api/records?days=5"
```

## Development and tests

```bash
npm ci
```

Unit tests (no database needed):

```bash
npm test
```

Integration tests run against a real PostgreSQL in an isolated, temporary schema. They cover
the health check, dedup on re-ingest, 8 parallel identical uploads producing exactly one copy,
filters, webhook delivery, and error envelopes.

```bash
docker compose up -d postgres
```

```bash
TEST_DATABASE_URL=postgres://dmarc:dmarc-local-only@localhost:5432/dmarc npm run test:integration
```

Run the API without Docker:

```bash
PGHOST=localhost PGUSER=dmarc PGPASSWORD=dmarc-local-only PGDATABASE=dmarc npm start
```

CI (`.github/workflows/ci.yml`) runs unit and integration tests against a PostgreSQL service
container, validates the manifests with kubeconform, builds the image, and scans it with Trivy.
Path filters skip irrelevant jobs on pull requests.

## Security

- **Authentication is offloaded** to the ingress controller / API gateway (e.g. oauth2-proxy;
  see the annotations in `k8s/ingress.yaml`). The app itself has no login. The NetworkPolicy
  ensures pods are only reachable through the gateway. Do **not** expose the Service directly.
- Secrets come from Kubernetes `Secret`s only and are never logged. Errors return generic
  messages, never stack traces or SQL errors.
- XML is parsed with entity expansion disabled, and bodies are size-limited (`BODY_LIMIT`).
  All SQL is parameterised. The UI renders report data with `textContent` only and sends a
  strict CSP.
- The image runs as non-root on a read-only root filesystem. npm, corepack and apk are
  removed from the runtime stage.

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## License

[Apache-2.0](LICENSE)

# DMARC-analysis

[![CI](https://github.com/JoWe112/dmarc-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/JoWe112/dmarc-analysis/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/JoWe112/dmarc-analysis)](LICENSE)
![Node](https://img.shields.io/badge/node-22-339933?logo=node.js&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/postgresql-external-4169E1?logo=postgresql&logoColor=white)

A self-hosted, container-based analyser for **DMARC aggregate reports** (RFC 7489).
Sign in with your OpenID Connect provider (e.g. Keycloak) and drop `.xml`, `.zip` or `.gz`
reports into the web page (UI in Swedish). The app parses them, stores every record
**exactly once** in an external PostgreSQL database, alerts a webhook when too much mail fails
authentication, and visualises the history.

No Google Apps Script, no Gmail integration, no local SQLite, and no PVC.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick start (docker compose)](#quick-start-docker-compose)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [API reference](#api-reference)
- [Database schema and deduplication](#database-schema-and-deduplication)
- [Alerting](#alerting)
- [Kubernetes deployment](#kubernetes-deployment)
- [Verifying with curl](#verifying-with-curl)
- [Development and tests](#development-and-tests)
- [Releasing](#releasing)
- [Security](#security)

---

## Features

| Area | What you get |
|------|--------------|
| **Ingestion** | Drag & drop or paste of `.xml` / `.zip` / `.gz`, unpacked **in the browser** (native `DecompressionStream`, no JS libraries). The API also accepts raw XML or pre-parsed JSON records. |
| **Deduplication** | Deterministic SHA-256 `record_hash` + `INSERT … ON CONFLICT (record_hash) DO NOTHING`, safe for re-ingestion and parallel requests. |
| **Alerting** | Webhook (Slack/Teams/generic JSON) when > 10 % of *newly inserted* mail fails both DKIM and SPF. |
| **Authentication** | Built-in OpenID Connect: authorization code flow with PKCE for the UI, bearer access tokens for the API, an optional required role, CSRF protection, and encrypted stateless sessions that work across replicas. See [docs/authentication.md](docs/authentication.md). |
| **Dashboard** | KPI cards (total mail, DMARC pass %, DKIM pass %, SPF pass %), stacked daily volume chart, searchable table with "failed only" and time-range quick filters. |
| **Operations** | `/healthz` with a DB check, idempotent schema migration at startup, graceful shutdown, OpenAPI + Swagger UI at `/docs`. |
| **Deployment** | Multi-stage non-root image (Trivy clean), `docker-compose.yml`, and Kubernetes manifests (Deployment, Service, ConfigMap, Secret, Ingress/HTTPRoute, NetworkPolicy). Works on OpenShift `restricted-v2`. |

## Architecture

```mermaid
flowchart LR
    U[Browser<br/>public/ UI] -- "unpack .zip/.gz<br/>POST /api/reports {xml:[…]}" --> GW
    U -- "GET /api/records" --> GW
    U <-. "sign in (OIDC code + PKCE)" .-> IDP[OIDC provider<br/>e.g. Keycloak]
    GW[Ingress / Gateway<br/>TLS] --> SVC[Service]
    SVC --> P1[Pod 1<br/>auth + Express API + UI]
    SVC --> P2[Pod 2<br/>auth + Express API + UI]
    P1 & P2 -. "discovery, token exchange, JWKS" .-> IDP
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
| `src/server.js` | Entry point: validate config, migrate, listen, graceful shutdown |
| `src/app.js` | Express app, routes, error envelope |
| `src/auth/` | OIDC login/callback/logout, bearer verification, encrypted sessions, CSRF check |
| `src/parser.js` | DMARC XML parsing, validation, `record_hash` (single source of truth) |
| `src/repository.js` | All SQL (insert with dedup, filtered history query) |
| `src/alerts.js` | Failure statistics and webhook delivery |
| `src/db.js` | Pool creation (DATABASE_URL or PG\*), idempotent schema |
| `src/config.js` | Environment configuration |
| `public/` | Swedish web UI (vanilla JS, no build step) |
| `db/migrations/001_init.sql` | Same schema as SQL, for manual migration |
| `docs/openapi.yaml` | OpenAPI 3 specification |
| `docs/authentication.md` | Authentication design and configuration |
| `dev/keycloak/` | Keycloak realm for local development (imported by docker-compose) |
| `k8s/` | Kubernetes manifests + `kustomization.yaml` |
| `test/` | Unit and auth tests (`test/helpers/` holds an in-process mock OIDC provider); `test/integration/` runs against real PostgreSQL |
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

Open <http://localhost:8080>. You're redirected to the local Keycloak; sign in as
**`analyst` / `changeme-analyst`**. The user `outsider` / `changeme-outsider` lacks the
`dmarc-viewer` role and is refused with 403. Swagger UI is at <http://localhost:8080/docs>
once you're signed in.

`docker-compose.yml` starts three services:

| Service | URL | Purpose |
|---------|-----|---------|
| `app` | <http://localhost:8080> | The application |
| `postgres` | `localhost:5432` | Stands in for the external database (named volume `pgdata`) |
| `keycloak` | <http://keycloak.localhost:8081> (admin: `admin` / `changeme-admin`) | OIDC provider with the realm from [`dev/keycloak/dmarc-realm.json`](dev/keycloak/dmarc-realm.json) |

Keycloak takes about 30 s to become healthy; the app waits for it. `*.localhost` resolves to
127.0.0.1 in browsers and in curl, and `keycloak.localhost` is also a network alias inside
compose. That way the browser and the app see the same issuer URL.

The app container runs with a read-only root filesystem, a `/tmp` tmpfs, all capabilities
dropped, and `no-new-privileges`, the same as in Kubernetes. All passwords and secrets in the
compose file are local-development values. To try alerting locally:

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
| `APP_BASE_URL` | – (**required**) | ConfigMap | Public origin of the app, e.g. `https://dmarc.example.com` |
| `OIDC_ISSUER_URL` | – (**required**) | ConfigMap | OIDC issuer URL |
| `OIDC_CLIENT_ID` | – (**required**) | ConfigMap | Confidential client ID |
| `OIDC_CLIENT_SECRET` | – (**required**) | Secret | Client secret |
| `SESSION_SECRET` | – (**required**) | Secret | ≥ 32 characters; encrypts session cookies |
| `OIDC_REQUIRED_ROLE` | – | ConfigMap | Required role/group; empty means any authenticated user |
| `OIDC_ROLE_CLAIM` | `realm_access.roles` | ConfigMap | Dotted claim path with roles/groups |
| `OIDC_AUDIENCE` | – | ConfigMap | Require this `aud` on bearer tokens (instead of `azp == client ID`) |
| `OIDC_SCOPES` | `openid profile email` | ConfigMap | Scopes requested at login |
| `SESSION_TTL_SECONDS` | `28800` | ConfigMap | Session lifetime |
| `ALERT_TIMEOUT_MS` | `5000` | ConfigMap | Webhook timeout |
| `MAX_RECORDS` | `5000` | ConfigMap | Row cap for `GET /api/records` |
| `BODY_LIMIT` | `20mb` | ConfigMap | Max request body size |

## Authentication

The application authenticates every request itself using **OpenID Connect**; no
authenticating proxy is needed. The full design is in
[docs/authentication.md](docs/authentication.md).

- **Web UI:** unauthenticated page loads redirect to `/auth/login`. That starts the
  authorization code flow with PKCE, and after `/auth/callback` the browser holds an
  encrypted, `HttpOnly` session cookie. The header shows the signed-in user and a
  **Logga ut** (log out) button.
- **API:** send the session cookie (the UI does this), or `Authorization: Bearer <access token>`
  for a token from the same provider. Bearer tokens must be issued to this client
  (`azp == OIDC_CLIENT_ID`), or carry `OIDC_AUDIENCE` in `aud` when that is set.
- **Authorization:** with `OIDC_REQUIRED_ROLE` set, users without the role get `403`.
- **Public:** only `/healthz` and the login endpoints.

There are no API keys: scripts call the API with a user's access token (see
[Verifying with curl](#verifying-with-curl)).

## API reference

The full spec is in [`docs/openapi.yaml`](docs/openapi.yaml). The running app serves it at
`/openapi.yaml`, with Swagger UI at `/docs`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/healthz` | public | `SELECT 1` against PostgreSQL → `200 {"status":"ok"}`, or `503` |
| `GET` | `/auth/login` | public | Start sign-in (`?returnTo=/local/path`) |
| `GET` | `/auth/callback` | public | OIDC redirect URI |
| `GET` | `/auth/me` | ✔ | The signed-in user `{sub, name, username, email, roles}` |
| `POST` | `/auth/logout` | ✔ | Clears the session; returns `{redirect}` (the provider's end-session URL) |
| `GET` | `/api/version` | ✔ | `{"version":"2.0.0"}` |
| `POST` | `/api/reports` | ✔ | Ingest records (see below) |
| `GET` | `/api/records` | ✔ | History with `days` (`7`/`30`/`90`/`all`, default `30`), `failedOnly` (`true`/`false`), `q` (free text) |

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
| 400 | `LOGIN_EXPIRED` | `/auth/callback` without a valid login transaction (expired after 10 min, or cookies blocked) |
| 401 | `UNAUTHENTICATED` | No session cookie or bearer token (response includes `WWW-Authenticate: Bearer`) |
| 401 | `INVALID_TOKEN` | Bearer token invalid, expired, not an access token, or issued to another client |
| 401 | `LOGIN_FAILED` | Code exchange or token validation failed during sign-in |
| 403 | `FORBIDDEN` | Authenticated, but missing `OIDC_REQUIRED_ROLE` |
| 403 | `CSRF_REJECTED` | Cookie-authenticated `POST` from another origin |
| 404 | `NOT_FOUND` | Unknown path |
| 413 | `PAYLOAD_TOO_LARGE` | Body exceeds `BODY_LIMIT` |
| 500 | `INTERNAL_ERROR` | Unexpected error (no internals leaked) |
| 503 | `DATABASE_UNAVAILABLE` | PostgreSQL not reachable |
| 503 | `IDENTITY_PROVIDER_UNAVAILABLE` | OIDC provider not reachable (discovery or JWKS) |

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
    D --> IDP[OIDC provider]
```

| Manifest | Notes |
|----------|-------|
| `k8s/deployment.yaml` | `replicas: 2`, `RollingUpdate` (`maxUnavailable: 0`), `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, seccomp `RuntimeDefault`, `/tmp` emptyDir, readiness and liveness probes on `/healthz`, no `runAsUser` (OpenShift assigns one) |
| `k8s/configmap.yaml` | Non-sensitive settings: DB host, SSL mode, threshold, and `APP_BASE_URL`, `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_REQUIRED_ROLE`, … |
| `k8s/secret.yaml` | **Example only**: `PGUSER`, `PGPASSWORD`, `OIDC_CLIENT_SECRET`, `SESSION_SECRET`, `ALERT_WEBHOOK_URL`, optional `DATABASE_URL` |
| `k8s/service.yaml` | ClusterIP, port 80 → 8080 |
| `k8s/ingress.yaml` / `k8s/httproute.yaml` | Pick one (Ingress is enabled in the kustomization) |
| `k8s/networkpolicy.yaml` | Defence in depth: pod ingress allowed only from the ingress/gateway namespace |

### 1. Get the image

Released images are published automatically to
`ghcr.io/jowe112/dmarc-analysis:<version>` (see [Releasing](#releasing)). To build and push
one manually instead:

```bash
docker build --build-arg VERSION=2.0.0 -t ghcr.io/jowe112/dmarc-analysis:2.0.0 .
```

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$HOME/.cache/trivy:/root/.cache/trivy" aquasec/trivy:0.69.3 image --severity HIGH,CRITICAL --exit-code 1 ghcr.io/jowe112/dmarc-analysis:2.0.0
```

```bash
docker push ghcr.io/jowe112/dmarc-analysis:2.0.0
```

### 2. Register the OIDC client

At your provider, create a **confidential** client with the standard (authorization code)
flow only, PKCE `S256`, the redirect URI `https://<your-host>/auth/callback`, and the
post-logout redirect URI `https://<your-host>/`. Create the role named in
`OIDC_REQUIRED_ROLE` and assign it to the users who need access. Step-by-step Keycloak
instructions are in [docs/authentication.md](docs/authentication.md#setting-up-the-provider-client-keycloak).

### 3. Create the Secret (out-of-band, never committed)

```bash
kubectl -n dmarc create secret generic dmarc-analysis-secret --from-literal=PGUSER=dmarc --from-literal=PGPASSWORD='<password>' --from-literal=OIDC_CLIENT_SECRET='<client secret>' --from-literal=SESSION_SECRET="$(openssl rand -base64 48)" --from-literal=ALERT_WEBHOOK_URL='<https://hooks…>'
```

### 4. Adjust and apply

Edit `k8s/configmap.yaml` (`PGHOST`, `PGSSLMODE`, `APP_BASE_URL`, `OIDC_ISSUER_URL`,
`OIDC_CLIENT_ID`, `OIDC_REQUIRED_ROLE`, …). Make sure the hostname in `k8s/ingress.yaml` or
`k8s/httproute.yaml` matches `APP_BASE_URL`, and set the namespace label in
`k8s/networkpolicy.yaml`. Then:

```bash
kubectl -n dmarc apply -k k8s/
```

```bash
kubectl -n dmarc rollout status deploy/dmarc-analysis
```

If a required auth setting is missing, the pod exits at startup and logs every problem, e.g.
`Invalid authentication configuration: SESSION_SECRET is required`.

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

Health check (public; expect HTTP 200 and `"database":"up"`):

```bash
curl -i "$BASE/healthz"
```

Without a token the API refuses the request (expect HTTP 401, `UNAUTHENTICATED`):

```bash
curl -i "$BASE/api/records"
```

Get a user access token. With the docker-compose Keycloak, use the password grant, which is
enabled only in the local dev realm. Against a real provider, use a flow it offers for users
of this client, e.g. the device authorization grant.

```bash
TOKEN=$(curl -s -d grant_type=password -d client_id=dmarc-analysis -d client_secret=local-dev-changeme-client-secret -d username=analyst -d password=changeme-analyst http://keycloak.localhost:8081/realms/dmarc/protocol/openid-connect/token | jq -r .access_token)
```

```bash
AUTH="Authorization: Bearer $TOKEN"
```

Check who you are:

```bash
curl -s -H "$AUTH" "$BASE/auth/me"
```

Ingest the sample report as raw XML (first run: `inserted: 2`, `alertTriggered: true`):

```bash
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/xml' --data-binary @examples/sample-report.xml "$BASE/api/reports"
```

Send it again; deduplication should give `inserted: 0, duplicates: 2`:

```bash
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/xml' --data-binary @examples/sample-report.xml "$BASE/api/reports"
```

Ingest a gzipped report (unpacked locally, sent as JSON):

```bash
gunzip -c report.xml.gz | jq -Rs '{xml: .}' | curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' -d @- "$BASE/api/reports"
```

Ingest pre-parsed JSON records:

```bash
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' -d '{"records":[{"report_date":"2026-11-21","report_id":"manual-1","reporting_org":"test","domain":"example.com","policy":"none","source_ip":"192.0.2.1","mail_count":5,"disposition":"none","dkim_result":"pass","spf_result":"pass","header_from":"example.com"}]}' "$BASE/api/reports"
```

Query history:

```bash
curl -s -H "$AUTH" "$BASE/api/records?days=30&failedOnly=true&q=198.51.100" | jq '.count, .records[0]'
```

Validation error (expect HTTP 400 with the error envelope):

```bash
curl -i -H "$AUTH" "$BASE/api/records?days=5"
```

## Development and tests

```bash
npm ci
```

Unit and authentication tests (no database needed). The auth tests run the full login flow,
bearer tokens, role checks, CSRF and open-redirect cases against an in-process mock OIDC
provider (`test/helpers/mock-idp.js`):

```bash
npm test
```

Integration tests run against a real PostgreSQL in an isolated, temporary schema. They cover
the health check, dedup on re-ingest, 8 parallel identical uploads producing exactly one copy,
filters, webhook delivery, and error envelopes. Requests authenticate with a bearer token from
the mock provider.

```bash
docker compose up -d postgres
```

```bash
TEST_DATABASE_URL=postgres://dmarc:dmarc-local-only@localhost:5432/dmarc npm run test:integration
```

Run the API without Docker, using the compose PostgreSQL and Keycloak:

```bash
docker compose up -d postgres keycloak
```

```bash
PGHOST=localhost PGUSER=dmarc PGPASSWORD=dmarc-local-only PGDATABASE=dmarc APP_BASE_URL=http://localhost:8080 OIDC_ISSUER_URL=http://keycloak.localhost:8081/realms/dmarc OIDC_CLIENT_ID=dmarc-analysis OIDC_CLIENT_SECRET=local-dev-changeme-client-secret OIDC_REQUIRED_ROLE=dmarc-viewer SESSION_SECRET=local-dev-changeme-session-secret-0123456789 npm start
```

CI (`.github/workflows/ci.yml`) runs unit and integration tests against a PostgreSQL service
container, validates the manifests with kubeconform, builds the image, and scans it with Trivy.
Path filters skip irrelevant jobs on pull requests.

## Releasing

Releases follow [SemVer](https://semver.org/).
[`.github/workflows/release.yml`](.github/workflows/release.yml) publishes the image when a
`vX.Y.Z` tag is pushed.

```mermaid
flowchart LR
    T[git push tag vX.Y.Z] --> V{tag == package.json version?}
    V -- no --> F[fail]
    V -- yes --> B[build linux/amd64] --> S{Trivy HIGH/CRITICAL}
    S -- findings --> F
    S -- clean --> P[build amd64 + arm64<br/>push to GHCR<br/>with SBOM + provenance]
```

1. Bump `version` in `package.json` (and `package-lock.json`). Also bump the image tag in
   `k8s/deployment.yaml` and `k8s/kustomization.yaml`, and the `VERSION` build arg in
   `docker-compose.yml`. Add the release to `CHANGELOG.md`, then merge via PR.
2. Tag the merge commit and push the tag:

```bash
git tag -a v1.1.0 -m "v1.1.0" && git push origin v1.1.0
```

The workflow pushes `ghcr.io/jowe112/dmarc-analysis:X.Y.Z`, `:X.Y` and `:latest`. Kubernetes
manifests must always pin `X.Y.Z`.

To publish a tag that already exists (for example `v1.0.0`, created before this workflow),
run the workflow manually:

```bash
gh workflow run release.yml -f tag=v1.0.0
```

> The workflow pushes with `GITHUB_TOKEN`, so the package is linked to this repository and
> **inherits its visibility**. The repository is public, so the image can be pulled
> anonymously and the cluster needs no `imagePullSecret`. If the repository is ever made
> private, add an `imagePullSecret` with `read:packages` access to the Deployment.

## Security

- **Authentication is built in** (OpenID Connect). Every endpoint except `/healthz` and the
  login flow needs a session or bearer token. The security controls (PKCE, encrypted
  `HttpOnly` sessions, CSRF origin check, open-redirect protection, https-only issuer) are
  described in [docs/authentication.md](docs/authentication.md). The NetworkPolicy stays as
  defence in depth.
- Secrets (`PGPASSWORD`, `OIDC_CLIENT_SECRET`, `SESSION_SECRET`, `ALERT_WEBHOOK_URL`) come from
  Kubernetes `Secret`s only and are never logged. Login events log only the user's `sub`. Errors return generic
  messages, never stack traces or SQL errors.
- XML is parsed with entity expansion disabled, and bodies are size-limited (`BODY_LIMIT`).
  All SQL is parameterised. The UI renders report data with `textContent` only and sends a
  strict CSP.
- The image runs as non-root on a read-only root filesystem. npm, corepack and apk are
  removed from the runtime stage.

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## License

[Apache-2.0](LICENSE)

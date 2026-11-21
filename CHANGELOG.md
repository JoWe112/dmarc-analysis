# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.0.0] - 2026-11-21

### Changed (breaking)
- **Authentication is now built into the application** (OpenID Connect) instead of being
  offloaded to the ingress/gateway. Every endpoint except `/healthz` and the login flow now
  requires a session cookie or a bearer access token; unauthenticated calls get `401`.
- New **required** configuration: `APP_BASE_URL`, `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`,
  `OIDC_CLIENT_SECRET`, `SESSION_SECRET`. The app refuses to start without them.
- `/api/version`, `/openapi.yaml` and `/docs` now require authentication.
- Minimum Node.js version is 22.12 (needed to `require()` the ES-module OIDC libraries).

### Added
- `/auth/login`, `/auth/callback`, `/auth/me` and `/auth/logout`: authorization code flow with
  PKCE, `state` and `nonce`, plus RP-initiated logout.
- Encrypted, stateless session cookies (JWE A256GCM), so no session store or sticky sessions
  are needed across replicas.
- Bearer access-token validation (JWKS, issuer, `azp`/`aud`, rejects ID and refresh tokens).
- Optional role requirement (`OIDC_REQUIRED_ROLE`, `OIDC_ROLE_CLAIM`), plus `OIDC_AUDIENCE`,
  `OIDC_SCOPES` and `SESSION_TTL_SECONDS`.
- CSRF protection (same-origin check) for cookie-authenticated state-changing requests.
- The UI shows the signed-in user and has a **Logga ut** (log out) button. Expired sessions
  restart the login flow and return to the same page.
- docker-compose now includes Keycloak with a ready-made dev realm (`dev/keycloak/`), and a
  named `pgdata` volume for PostgreSQL.
- `docs/authentication.md`; OpenAPI `bearerAuth` / `sessionCookie` security schemes and the
  401/403 responses.
- Auth tests against an in-process mock OIDC provider.
- Release workflow (`.github/workflows/release.yml`): on a `vX.Y.Z` tag (or manual run for an
  existing tag), it verifies the tag matches `package.json`, Trivy-scans the image, and pushes a
  multi-arch (`amd64`, `arm64`) image with SBOM and provenance to `ghcr.io/jowe112/dmarc-analysis`.

### Removed
- The oauth2-proxy annotations in `k8s/ingress.yaml`. The NetworkPolicy remains as defence in
  depth.

## [1.0.0] - 2026-11-21

### Added
- REST API (Express 5 + `pg`): `GET /healthz`, `POST /api/reports`, `GET /api/records`, `GET /api/version`.
- Server-side DMARC aggregate XML parsing; deterministic SHA-256 `record_hash` and
  `INSERT … ON CONFLICT (record_hash) DO NOTHING` deduplication.
- Idempotent schema initialisation at startup (advisory-locked) plus `db/migrations/001_init.sql`.
- Webhook alerting when the failed share of newly inserted mail exceeds `ALERT_THRESHOLD` (default 10 %).
- Swedish, responsive web UI: drag & drop / paste of `.xml`, `.zip`, `.gz`, in-browser unpacking,
  KPI cards, stacked daily volume chart, searchable/filterable table.
- OpenAPI 3 spec (`docs/openapi.yaml`) with Swagger UI at `/docs`.
- Multi-stage Dockerfile (non-root, read-only-FS compatible, OpenShift arbitrary UID), `docker-compose.yml`.
- Kubernetes manifests: Deployment, Service, ConfigMap, Secret (example), Ingress, HTTPRoute, NetworkPolicy, Kustomization.
- Unit and PostgreSQL integration tests, GitHub Actions CI with Trivy scan, Dependabot.

[Unreleased]: https://github.com/JoWe112/dmarc-analysis/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/JoWe112/dmarc-analysis/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/JoWe112/dmarc-analysis/releases/tag/v1.0.0

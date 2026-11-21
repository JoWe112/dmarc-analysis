# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/JoWe112/dmarc-analysis/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/JoWe112/dmarc-analysis/releases/tag/v1.0.0

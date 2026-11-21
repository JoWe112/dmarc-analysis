# Security Policy

## Supported versions

Only the latest released minor version receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue. Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/JoWe112/dmarc-analysis/security/advisories/new).

You can expect an acknowledgement within 5 working days. Please include steps to
reproduce, affected version, and impact.

## Security model (summary)

- The application **authenticates users itself with OpenID Connect**: an
  authorization code flow with PKCE for the UI, and bearer access tokens for the
  API. Everything except `/healthz` and the login endpoints requires
  authentication, and an optional role restricts access further. See
  [docs/authentication.md](docs/authentication.md).
- Sessions are encrypted (JWE A256GCM), `HttpOnly`, `SameSite=Lax` cookies.
  Over https they are also `Secure` and `__Host-` prefixed.
  Cookie-authenticated state-changing requests must be same-origin.
- `k8s/networkpolicy.yaml` additionally limits pod ingress to the ingress
  controller / gateway (defence in depth).
- Database credentials, the OIDC client secret, the session secret and the
  alert webhook URL are read from a Kubernetes `Secret` and are never logged.
- DMARC reports contain IP addresses and domain names of mail senders; treat the
  database as containing operational/personal data and restrict access to it.
- XML is parsed with entity processing disabled; request bodies are size-limited.

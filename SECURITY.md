# Security Policy

## Supported versions

Only the latest released minor version receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue. Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/JoWe112/dmarc-analysis/security/advisories/new).

You can expect an acknowledgement within 5 working days. Please include steps to
reproduce, affected version, and impact.

## Security model (summary)

- The application has **no built-in authentication**. It must run behind an
  authenticating ingress controller / API gateway; `k8s/networkpolicy.yaml`
  restricts pod ingress to that gateway.
- Database credentials and the alert webhook URL are read from a Kubernetes
  `Secret` and are never logged.
- DMARC reports contain IP addresses and domain names of mail senders; treat the
  database as containing operational/personal data and restrict access to it.
- XML is parsed with entity processing disabled; request bodies are size-limited.

# Security Policy

## Reporting a vulnerability

If you discover a potential security issue in this project, please notify AWS/Amazon Security through the
[AWS vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/) or by email to
[aws-security@amazon.com](mailto:aws-security@amazon.com).

Please do **not** create a public GitHub issue for a suspected vulnerability, and do not include exploit
details, tokens, or account identifiers in a public channel.

## What this repository is

This is sample code published for learning and evaluation. It is a reference for the authorization controls
described in [README §2](README.md#2-architecture) — allow-listed client identifier URLs, SSRF-guarded metadata
fetching, resource-bound tokens, key-rotation detection, fail-closed freshness and CSRF-protected consent — and
it is not an AWS service. Review it against your own requirements before running it in production.

## Before exposing a deployment to the internet

Two things in the default configuration are deliberately conservative and one is deliberately absent:

- `cimd.allowedClients` is **empty** by default. A deployment trusts no third-party client until an operator
  adds its client identifier URL. Only URLs on that list ever receive a Cognito app client, and only those app
  clients ever hold the MCP invoke scope.
- API Gateway request throttling (`api.throttle`, and the tighter `api.revalidatingRouteThrottle` on `GET /authorize`, `POST /consent` and `POST /token`)
  is the only rate control this sample deploys.
- **There is no AWS WAF web ACL.** AWS WAF cannot be associated with an API Gateway HTTP API; it supports
  REST APIs, Application Load Balancers, AppSync, Cognito user pools and CloudFront distributions. This sample
  uses an HTTP API because the `$default` stage passes `WWW-Authenticate` through unmodified and has no stage
  path, both of which MCP authorization discovery requires. Adding WAF therefore means fronting the API with
  CloudFront, which changes `publicBaseUrl` and so also `resourceUrl`, the token `aud` and the Cognito
  resource-server identifier. **Attach a WAF rate-based rule before exposing a deployment to untrusted
  traffic.** See [README §2](README.md#rate-limiting-and-waf).

## Supported versions

This sample is maintained on the `main` branch only. There are no released versions and no backports.

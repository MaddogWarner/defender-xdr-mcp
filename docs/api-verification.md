# API verification

Verified against Microsoft Learn on 29 August 2026.

## Microsoft Graph security

- `POST https://graph.microsoft.com/v1.0/security/runHuntingQuery` remains the current advanced-hunting endpoint. Its least-privileged delegated permission is `ThreatHunting.Read.All`.
- `GET https://graph.microsoft.com/v1.0/security/incidents` remains current. Its least-privileged delegated permission is `SecurityIncident.Read.All`.
- `GET https://graph.microsoft.com/v1.0/security/alerts_v2` remains current. Its least-privileged delegated permission is `SecurityAlert.Read.All`.

## Microsoft Defender for Endpoint

- The current commercial base URL is `https://api.security.microsoft.com`. Microsoft documents the regional prefixes `us`, `eu`, `uk`, `au`, `swa`, `ina`, and `aea`.
- The required least-privileged delegated permissions remain `Vulnerability.Read`, `Machine.Read`, `Software.Read`, and `SecurityRecommendation.Read`.
- Microsoft explicitly documents that these APIs may still require tokens issued for the legacy resource. Acquire the MDE token with `https://api.securitycenter.microsoft.com/.default`, including when the request host is `api.security.microsoft.com`; an audience mismatch can return HTTP 403.

## Limits used by this project

- Advanced hunting remains limited to 45 calls per minute and 1,500 calls per hour, 100,000 rows, 50 MB per result, 200 seconds per request, and 30 days of data in the legacy API documentation. Microsoft Graph does not publish an equivalent hourly figure, so this project retains its conservative 1,200 requests/hour guardrail.
- The machines API currently documents 100 calls per minute and 1,500 calls per hour. The project-wide MDE defaults of 45 requests/minute and 1,350 requests/hour remain conservative for the selected inventory endpoints.

## Deviations

No blocking API or permission drift was found. The documented machines API per-minute limit is now 100 rather than the approximate 50 used in the build plan; the lower project limit remains a safe, intentional guardrail.

## Primary sources

- [Run hunting query](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0)
- [List incidents](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0)
- [List alerts v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0)
- [Use Microsoft Defender for Endpoint APIs](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-nativeapp)
- [List machines](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines)
- [List vulnerabilities](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities)
- [List software](https://learn.microsoft.com/en-us/defender-endpoint/api/get-software)
- [List security recommendations](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-recommendations)
- [Advanced hunting API limits](https://learn.microsoft.com/en-us/defender-endpoint/api/run-advanced-query-api)

Step 4 correction verified 29/08/2026: the vulnerabilities endpoint supports `$filter` on `id`, `name`, `description`, `cvssV3`, `publishedOn`, `severity` and `updatedOn` only. `publicExploit`, `exploitVerified`, `exploitInKit`, `exploitTypes` and `epss` are response properties, not filterable fields.

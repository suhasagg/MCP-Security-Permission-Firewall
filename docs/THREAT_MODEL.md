# Threat Model

Assets: delegated identity, credentials, tenant data, tool authority, approval authority, audit integrity.

Threats: confused deputy, prompt injection, tool poisoning, malicious MCP server, approval replay/substitution, cross-tenant invocation, SSRF, credential leakage, data exfiltration, destructive writes, schema drift, oversized output, audit tampering.

Core controls: default deny, immutable tool identity, tenant/scope checks, integrity/confidentiality labels, DLP, argument-bound expiring approvals, endpoint governance, output limits, audit, network egress controls.

# MCP Security / Permission Firewall

A runnable, production-oriented security and governance reference implementation placed between AI agents and MCP tool execution.

Microsoft Agent Framework already exposes important security primitives: MCP `allowed_tools`, tool-specific approval modes, progressive disclosure, argument filtering, default-denied server-initiated sampling, bounded sampling, and security middleware. Microsoft's current security guidance also includes integrity/confidentiality controls and audit behavior. This project deliberately does **not** pretend those capabilities are absent. Instead, it demonstrates how to build a centralized enterprise policy-enforcement layer around MCP execution across agents, tenants and servers.

## Architecture

```text
                   Microsoft Agent Framework / Muse
                              |
                              v
                    MCP SECURITY FIREWALL
                              |
       +----------------------+----------------------+
       |                      |                      |
       v                      v                      v
   Identity/RBAC          ABAC/Policy          Data Security
       |                      |                 IFC + DLP
       +----------------------+----------------------+
                              |
                              v
                        Risk Engine
                              |
                   +----------+----------+
                   |                     |
                   v                     v
                ALLOW              APPROVAL/DENY
                                         |
                                         v
                               Bound Approval Token
                                         |
                                         v
                              Argument Validation
                                         |
                                         v
                               Credential Boundary
                                         |
                                         v
                                  Egress/SSRF
                                         |
                                         v
                                      MCP
                                         |
                                         v
                                 Output Controls
                                         |
                                         v
                               Audit + OTel/Metrics
```

## Security invariants

1. Model intent is never authorization.
2. MCP server metadata is never an authorization authority.
3. Search/disclosure is not execution permission.
4. Every consequential invocation is authorized immediately before execution.
5. Approval is bound to exact principal, tenant, immutable tool and canonical argument hash.
6. Untrusted content cannot silently flow into privileged sinks.
7. Confidentiality may only flow to tools authorized for that classification.
8. Credentials never enter the model context.
9. Arbitrary agent-supplied MCP endpoints are denied by control-plane governance.
10. Security failure defaults to deny for consequential operations.

## Repository

```text
app/
  main.py
  models.py
  security.py
  canonical.py
  approvals.py
  dlp.py
  ssrf.py
  registry.py
  policy.py
  mcp.py
  audit.py
  observability.py
  service.py
tests/
docs/
k8s/
Dockerfile
docker-compose.yml
```

## What is actually implemented

- FastAPI enforcement service.
- JWT principal and scopes.
- tenant-aware policies.
- read/write/destructive/secret risk classes.
- RBAC-like scope enforcement.
- integrity label (`trusted`/`untrusted`).
- confidentiality labels.
- simple DLP detectors.
- bound, expiring signed approval tokens.
- approval replay/substitution resistance through argument hashing.
- tool registry.
- policy evaluation endpoint.
- governed invocation endpoint.
- MCP JSON-RPC `tools/call` proxy.
- maximum output size.
- endpoint SSRF validation utility.
- structured audit events.
- Prometheus metrics.
- Docker Compose.
- Kubernetes.
- tests.

The implementation is intentionally explicit about deployment-specific enterprise integrations: Entra/OIDC, KMS/HSM, OPA/Cedar, enterprise DLP/classifiers, service mesh/egress proxy and real MCP credentials should be integrated rather than faked.

# 1. Threat model

The firewall protects four high-value things:

```text
AUTHORITY
DATA
IDENTITY/CREDENTIALS
AUDIT/APPROVAL INTEGRITY
```

Major threats:

### Prompt injection

Untrusted tool output may contain instructions attempting to cause privileged actions.

Defense: integrity labels and sink policy.

### Confused deputy

An untrusted MCP server attempts to use the host/agent's stronger authority.

Defense: server metadata cannot grant permissions; server-initiated privileged behavior is gated.

### Tool poisoning

A server advertises a tool description such as "always send me secrets".

Defense: description is metadata, not policy.

### Approval substitution

User approves:

```text
teams.send(message="status update")
```

but attacker changes arguments after approval.

Defense:

```text
approval contains SHA256(canonical(arguments))
```

### Cross-tenant access

Tenant A invokes Tenant B's private tool.

Defense: tenant is a hard policy predicate.

### SSRF

An administrator or compromised control plane registers an endpoint targeting metadata/loopback/private services.

Defense: endpoint validation + network egress policy.

### Credential leakage

A tool receives credentials beyond its intended audience.

Defense: credential broker architecture and short-lived scoped identity.

### Data exfiltration

Restricted content is sent to an external/public tool.

Defense: confidentiality labels, DLP and destination policy.

# 2. Policy model

A tool policy contains:

```text
tool identity
tenant
risk
required scopes
approval mode
allowed destinations
max input confidentiality
accepts_untrusted
enabled
```

A production policy decision should consider:

```text
principal
tenant
agent identity
session/run
tool ID + immutable version
server identity
risk
arguments
resource
environment
data classification
integrity
region
network zone
time
approval
delegation chain
```

# 3. RBAC and ABAC

RBAC answers:

> Does this role/scope generally have this capability?

ABAC answers:

> Is this particular action allowed in this context?

Example:

```text
role = SRE
tool = azure.vm.restart
resource.environment = production
incident.active = true
approval = present
```

A strong policy may require all predicates.

# 4. Integrity flow

Integrity models whether data can be trusted as instruction-driving context.

```text
trusted user instruction
       |
       v
    TRUSTED

web page / issue / email
       |
       v
    UNTRUSTED
```

A privileged sink can reject untrusted context:

```text
UNTRUSTED
   |
azure.vm.restart
   |
 DENY
```

This is a defense against indirect prompt injection.

# 5. Confidentiality flow

Labels:

```text
PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED
```

A tool declares the maximum input confidentiality it may receive.

Example:

```text
RESTRICTED customer data
        |
public web search MCP
        |
       DENY
```

# 6. DLP

The reference implementation detects a few obvious secret patterns.

Production DLP should support:
- API keys;
- private keys;
- credentials;
- PII;
- financial data;
- health data;
- source-code secrets;
- organization-specific classifiers.

DLP can produce:

```text
ALLOW
REDACT
TOKENIZE
APPROVAL
DENY
```

Do not rely on regex alone for enterprise classification.

# 7. Approval architecture

Approval is not a boolean.

A safe approval is a capability:

```text
principal
tenant
tool
tool_version
arguments_hash
expiry
nonce
```

Reference token:

```text
JWT(
  sub,
  tenant,
  tool_id,
  tool_version,
  args_hash,
  iat,
  exp,
  nonce
)
```

Production should use asymmetric KMS/HSM-backed signing.

# 8. Why arguments are bound

Without argument binding:

```text
approve teams.send
```

could authorize any message.

With binding:

```text
approve teams.send({
 "channel":"incident-42",
 "message":"Rollback completed"
})
```

Changing channel or message invalidates approval.

# 9. Approval scopes

Enterprise systems may support:

```text
single invocation
session
workflow node
resource
time window
```

The safest default for high-risk actions is single invocation.

# 10. Approval replay

A production approval store should track nonce consumption for single-use tokens.

State:

```text
ISSUED -> CONSUMED
       -> EXPIRED
       -> REVOKED
```

The compact reference signs a nonce; durable one-time consumption is a documented production extension.

# 11. Policy evaluation flow

```text
Invocation
    |
authenticate
    |
tool lookup
    |
tenant
    |
scopes
    |
integrity
    |
confidentiality
    |
DLP
    |
risk/approval
    |
ALLOW / DENY / APPROVAL_REQUIRED
```

# 12. Tool risk

Suggested taxonomy:

### READ
No intended external mutation.

### WRITE
Creates/modifies normal external state.

### DESTRUCTIVE
Deletes/restarts/deploys/changes critical state.

### SECRET
Reads or handles credentials/high-value secrets.

Risk metadata must be locally governed.

# 13. Allowed tools

The firewall complements SDK `allowed_tools`.

Use defense in depth:

```text
Agent Framework allowed_tools
        +
Firewall registry/policy
        +
MCP server-side authorization
```

No single layer should be assumed perfect.

# 14. Progressive disclosure

Progressive disclosure reduces model-visible surface.

The firewall remains necessary because:

```text
tool is visible
!=
tool is authorized
```

# 15. Sampling

Server-initiated model sampling creates a confused-deputy risk because an MCP server can ask the host to invoke model capacity.

A secure posture:
- deny by default;
- explicit approval callback;
- request cap;
- token cap;
- audit.

Microsoft Agent Framework currently implements this kind of default-deny/bounded behavior.

# 16. Argument filtering

Framework/runtime-only objects should never leak to an MCP server.

Maintain explicit forwarding rules:
- declared schema fields;
- approved runtime metadata;
- no model-controlled reserved metadata.

# 17. Reserved metadata

Treat `_meta`-like protocol/runtime metadata as privileged.

Model-supplied reserved metadata should not be allowed to impersonate host/runtime metadata.

# 18. Tool annotations

Server-provided annotations can be useful hints.

They must not relax local security.

Safe principle:

```text
remote annotation can add restriction
remote annotation cannot grant authority
```

# 19. Credential broker

Target:

```text
Firewall
  |
tool + principal
  |
Credential Broker
  |
short-lived token
  |
MCP Server
```

Support:
- Entra OBO;
- workload identity;
- OAuth token exchange;
- GitHub App token;
- Vault dynamic credentials.

# 20. Least privilege

A Teams messaging tool should not receive an Azure subscription-owner credential.

Credentials should be:
- audience bound;
- short lived;
- minimally scoped;
- resource constrained where possible.

# 21. SSRF

The included `ssrf.py` rejects non-HTTPS and resolved private/loopback/link-local/reserved addresses.

Production also requires:
- endpoint allowlist;
- DNS rebinding defenses;
- redirect revalidation;
- egress proxy;
- network policy;
- cloud metadata blocking.

Application validation alone is insufficient.

# 22. Output controls

MCP output is untrusted.

Apply:
- byte limit;
- schema validation;
- integrity label;
- confidentiality classification;
- DLP;
- provenance.

# 23. Output prompt injection

Never treat tool output as system instructions.

Preserve explicit provenance:

```text
source=MCP
server=github
tool=issue.read
integrity=untrusted
```

# 24. Audit

Audit:
- policy decision;
- approval issuance/use;
- tool invocation;
- policy change;
- registry change;
- emergency deny.

Avoid logging secrets.

# 25. Observability

Trace:

```text
agent
 |
firewall.evaluate
 |-- identity
 |-- policy
 |-- DLP
 |-- approval
 |
mcp.call
 |
provider
```

Metrics:
- decisions by outcome/tool;
- invocation status;
- policy latency;
- approval rate;
- DLP blocks;
- MCP latency;
- policy cache hit.

# 26. Policy caching

Cache only when inputs are stable.

Key includes:
- policy version;
- principal authorization fingerprint;
- tenant;
- tool version;
- relevant resource attributes.

Never cache past credential/approval expiry.

# 27. Default deny

Unknown tool:

```text
DENY
```

Missing policy:

```text
DENY
```

Invalid approval:

```text
DENY / APPROVAL_REQUIRED
```

Security subsystem unavailable for consequential operation:

```text
DENY
```

# 28. Emergency deny

Maintain a rapidly propagated deny plane for:
- tool;
- server;
- tenant;
- credential issuer.

Check it immediately before execution.

# 29. Policy versioning

Every decision should record:

```text
policy_version
```

This is essential for incident reconstruction.

# 30. Immutable tool versions

Policy should target immutable identity:

```text
azure.vm.restart@17
```

A changed schema should not silently inherit high-risk authorization.

# 31. Schema validation

Before execution:

```text
jsonschema.validate(arguments, tool.input_schema)
```

Production should enforce:
- types;
- bounds;
- enums;
- unknown-property policy;
- formats;
- resource constraints.

# 32. Semantic argument policy

Schema validity does not imply safety.

Example:

```text
repo.delete(repo="production")
```

may be schema-valid but policy-denied.

# 33. Resource policy

Parse important resource identity into policy context.

Example:

```text
tool=database.query
database=analytics
operation=SELECT
```

versus:

```text
database=payments
operation=DROP
```

# 34. Environment policy

Common:

```text
dev     -> automatic
staging -> write scope
prod    -> approval
```

# 35. Time policy

Example:

```text
production deployment
only within approved change window
```

# 36. Delegation chain

For multi-agent systems:

```text
user -> orchestrator -> specialist -> MCP tool
```

Audit the delegation chain and never let a specialist gain more authority than the delegator.

# 37. A2A integration

The same policy engine can govern remote agent invocation:

```text
agent A
 |
Firewall
 |
A2A Agent B
```

Treat remote agents as executable capabilities with identity, risk and data-boundary metadata.

# 38. Sandbox integration

High-risk code/CLI/browser tools should execute in a sandbox.

```text
Firewall
 |
Sandbox Manager
 |
ephemeral container/microVM
```

Use:
- read-only base FS;
- seccomp/AppArmor;
- CPU/memory/time limits;
- egress controls;
- no host Docker socket;
- short-lived credentials.

# 39. Browser security

Browser tools can exfiltrate through URLs/forms.

Policy should govern:
- allowed domains;
- uploads;
- downloads;
- clipboard;
- credential use;
- form submission;
- file access.

# 40. Data lineage

Track:

```text
source -> transformation -> tool sink
```

This enables information-flow decisions.

# 41. Policy language

The reference uses Python for readability.

Production options:
- OPA/Rego;
- Cedar;
- custom policy service.

The critical property is deterministic, independently testable policy.

# 42. OPA architecture

```text
Firewall
 |
policy input JSON
 |
OPA
 |
allow/deny/obligations
```

Input contains trusted attributes, not model assertions.

# 43. Cedar architecture

Useful when modeling:
- principal;
- action;
- resource;
- context.

Keep data-flow/DLP obligations as complementary controls.

# 44. Obligations

Policy result can include:

```text
require_approval
redact_fields
force_sandbox
limit_output
use_credential_profile
require_audit
```

# 45. Separation of policy decision and enforcement

PDP:

```text
What should happen?
```

PEP:

```text
Actually enforce it.
```

This service acts primarily as PEP and can embed/call a PDP.

# 46. TOCTOU

Avoid:

```text
evaluate tool v1
...
invoke tool v2
```

Bind decision to immutable tool version and argument hash.

# 47. Approval TOCTOU

Approval must bind to exact action and expire quickly.

Re-evaluate current emergency deny/policy before invocation even with a valid approval.

# 48. Idempotency

Writes should carry idempotency keys where supported.

Never retry ambiguous destructive operations automatically.

# 49. Retry policy

Safe reads:
- bounded retry.

Idempotent writes:
- bounded retry with same idempotency key.

Non-idempotent/ambiguous writes:
- reconcile before retry.

# 50. Rate limiting

Limit:
- tenant;
- principal;
- agent;
- tool;
- server;
- high-risk class.

# 51. Cost limits

Security can include economic boundaries:

```text
browser minutes
sandbox CPU
paid API calls
model sampling
```

# 52. Exfiltration budget

For sensitive workflows, cap:
- bytes sent externally;
- external domains;
- number of outbound calls.

# 53. Multi-tenant isolation

Use:
- tenant-scoped registry;
- tenant-scoped policy;
- tenant-scoped audit;
- tenant-scoped credential references.

Do not trust tenant supplied by the model/request body.

# 54. Control plane

Owns:
- tool registration;
- policies;
- server trust;
- credentials references;
- approval configuration;
- emergency deny.

# 55. Data plane

Owns:
- evaluate;
- invoke;
- DLP;
- approval verification;
- MCP forwarding;
- telemetry.

# 56. Production persistence

Recommended PostgreSQL tables:

```text
tools
tool_versions
policies
policy_versions
servers
approval_records
approval_consumptions
audit_events
emergency_denies
```

Redis:
- rate limits;
- nonce replay cache;
- short-lived decision cache.

# 57. KMS

Production approval signing:

```text
Firewall
 |
KMS/HSM Sign
```

Verification uses public key/key ID.

Support key rotation.

# 58. Approval revocation

Approval can be revoked before expiry.

Durable approval state:

```text
ISSUED
CONSUMED
REVOKED
EXPIRED
```

# 59. Human approval UX

Show:
- tool;
- server;
- arguments;
- resource;
- data classification;
- risk;
- reason.

Do not ask:

```text
Allow tool?
```

Ask:

```text
Allow Teams message to channel incident-42 with this exact content?
```

# 60. Approval fatigue

Too many prompts cause unsafe habitual approval.

Use policy to auto-approve genuinely low-risk reads while preserving hard gates for consequential actions.

# 61. DLP redaction

When policy permits redaction:

```text
original -> classifier -> redact -> tool
```

Approval must bind to the actual post-redaction payload sent.

# 62. Secret references

Prefer:

```text
credential_ref="github-prod-app"
```

not raw secrets in arguments.

# 63. MCP server trust

Trust levels:

```text
internal
approved_vendor
community
untrusted
```

Trust can only constrain policy, not bypass user/tenant authorization.

# 64. Server-initiated requests

Treat server-initiated behaviors as inbound requests from an untrusted peer.

Gate:
- sampling;
- elicitation;
- resource requests;
- any future capability with host-side authority.

# 65. Supply chain

For deployed firewall:
- pinned dependencies;
- SBOM;
- image signing;
- provenance;
- vulnerability scanning;
- minimal base image.

# 66. CI/CD

```text
lint
unit tests
policy tests
security tests
MCP integration
container build
SBOM
scan
sign
staging
canary
production
```

# 67. Policy-as-code tests

Every policy change should include:

```text
allow cases
deny cases
boundary cases
cross-tenant cases
approval cases
```

# 68. Security regression suite

Test:
- approval substitution;
- expired approval;
- wrong principal;
- wrong tenant;
- changed arguments;
- DLP;
- untrusted-to-privileged flow;
- confidentiality downgrade;
- tool disabled;
- endpoint SSRF;
- output oversize.

# 69. Fuzzing

Fuzz:
- JSON schemas;
- arguments;
- tool names;
- endpoint URLs;
- approval tokens;
- MCP responses.

# 70. Load testing

Measure:
- policy p50/p95/p99;
- DLP cost;
- KMS signing latency;
- invocation overhead;
- audit throughput.

# 71. Chaos testing

Inject:
- policy backend outage;
- Redis outage;
- KMS outage;
- audit sink outage;
- MCP timeout;
- credential broker outage.

Define fail-open/fail-closed explicitly. High-risk actions should fail closed.

# 72. SLO examples

Illustrative:
- policy availability 99.99%;
- p99 policy evaluation <25 ms excluding external DLP;
- emergency deny propagation <30 s;
- audit durability 99.999%.

These are design targets, not measured claims for this repository.

# 73. Capacity

At 20K tool calls/sec:

```text
20K policy evaluations/sec
+ audit
+ DLP
+ approval verification
```

Keep hot-path decisions deterministic and cheap.

# 74. Cell architecture

```text
Global policy control plane
          |
   +------+------+
   |             |
 EU firewall   US firewall
   |             |
 local MCP     local MCP
```

Keep sensitive data and credentials in region.

# 75. Multi-region policy

Global policy definitions can replicate.

Tenant-specific data/approvals may remain regional.

# 76. Disaster recovery

Back up:
- policy versions;
- registry;
- approvals where durable;
- audit.

Practice restore.

# 77. Privacy

Audit only what is necessary.

Arguments may contain sensitive data; prefer hashes/classification and secure restricted logs when full payload retention is necessary.

# 78. Compliance

The architecture can support evidence for:
- access control;
- least privilege;
- approval;
- change management;
- audit;
- data handling.

Compliance mapping remains organization-specific.

# 79. Application: SRE

```text
logs.query -> auto allow
deployment.inspect -> auto allow
vm.restart(prod) -> approval
cluster.delete -> deny
```

# 80. Application: coding agent

```text
repo.search -> allow
pr.create -> scoped write + approval policy
branch.force_delete -> deny
```

# 81. Application: M365 assistant

```text
mail.search -> read
sharepoint.search -> read
teams.send -> exact-message approval
mail.send_external -> stronger approval/DLP
```

# 82. Application: browser operator

```text
navigate trusted domain -> allow
download -> inspect
upload confidential file -> policy
submit payment -> approval/deny
```

# 83. Application: security agent

```text
siem.query -> allow
endpoint.isolate -> approval
identity.disable -> approval
keyvault.secret.read -> restricted policy
```

# 84. Application: data agent

```text
SELECT analytics -> allow
export customer PII -> deny/DLP
DROP TABLE -> deny
```

# 85. Integration with MCP Tool Discovery Engine

```text
intent
 |
Discovery Engine
 |
top-K relevant tools
 |
Firewall
 |
authorized executable subset
 |
MCP
```

Discovery maximizes relevance.

Firewall minimizes authority.

# 86. Integration with Workflow Compiler

Each workflow node contains immutable tool version and expected risk.

Firewall independently re-evaluates at execution time.

# 87. Integration with Agent Memory Server

Memory can provide context but cannot grant permission.

Never derive authorization from remembered model text.

# 88. Integration with Microsoft Agent Tool Fabric

```text
Microsoft Agent Framework
 |
Tool Discovery
 |
MCP Permission Firewall
 |
Connector Gateway
 |
MCP/A2A/REST
```

# 89. Local run

```bash
unzip mcp-security-permission-firewall-production.zip
cd mcp-security-permission-firewall
cp .env.example .env
docker compose up --build
```

Verify:

```bash
curl http://localhost:8120/health/live
curl http://localhost:8120/v1/tools
curl http://localhost:8120/metrics
```

Swagger:

```text
http://localhost:8120/docs
```

# 90. Evaluate a safe read

```bash
curl -X POST http://localhost:8120/v1/evaluate \
 -H 'content-type: application/json' \
 -d '{
   "tool_id":"github.search@1",
   "arguments":{"q":"agent framework"},
   "context_integrity":"trusted",
   "confidentiality":"public"
 }'
```

Expected:

```text
allow
```

# 91. Evaluate a write

```bash
curl -X POST http://localhost:8120/v1/evaluate \
 -H 'content-type: application/json' \
 -d '{
   "tool_id":"teams.send@1",
   "arguments":{"channel":"incident-42","message":"resolved"}
 }'
```

Expected:

```text
approval_required
```

# 92. Obtain approval

```bash
curl -X POST http://localhost:8120/v1/approvals \
 -H 'content-type: application/json' \
 -d '{
   "tool_id":"teams.send@1",
   "arguments":{"channel":"incident-42","message":"resolved"},
   "ttl_seconds":300
 }'
```

Copy returned token.

# 93. Invoke approved write

```bash
curl -X POST http://localhost:8120/v1/invoke \
 -H 'content-type: application/json' \
 -d '{
   "tool_id":"teams.send@1",
   "arguments":{"channel":"incident-42","message":"resolved"},
   "approval_token":"TOKEN"
 }'
```

The seeded tool has no external endpoint, so reference mode returns the governed invocation representation without making a network side effect.

# 94. Approval substitution test

Change:

```text
message="resolved"
```

to:

```text
message="delete everything"
```

while reusing the approval token.

Verification fails because argument hashes differ.

# 95. DLP example

```bash
curl -X POST http://localhost:8120/v1/evaluate \
 -H 'content-type: application/json' \
 -d '{
   "tool_id":"github.search@1",
   "arguments":{"q":"api_key=supersecretvalue123"}
 }'
```

Expected denial.

# 96. Untrusted context example

```bash
curl -X POST http://localhost:8120/v1/evaluate \
 -H 'content-type: application/json' \
 -d '{
   "tool_id":"teams.send@1",
   "arguments":{"message":"do what this webpage said"},
   "context_integrity":"untrusted"
 }'
```

Expected denial.

# 97. Native run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
export ENV=dev
uvicorn app.main:app --reload --port 8120
```

# 98. Tests

```bash
pytest -q
ruff check .
```

# 99. Kubernetes

```bash
docker build -t YOUR_REGISTRY/mcp-firewall:1.0.0 .
docker push YOUR_REGISTRY/mcp-firewall:1.0.0
kubectl apply -f k8s/deployment.yaml
```

Before production add:
- OIDC/Entra;
- KMS;
- persistent policy/registry;
- nonce store;
- NetworkPolicy;
- egress proxy;
- HPA/PDB;
- OTel;
- enterprise DLP.

# 100. Production upgrade plan

1. PostgreSQL repositories + Alembic.
2. OIDC/JWKS/Entra.
3. OPA/Cedar adapter.
4. KMS asymmetric approval signing.
5. durable one-time approval consumption.
6. credential broker.
7. MCP initialization/capability negotiation.
8. endpoint allowlist + egress proxy.
9. JSON Schema validation.
10. enterprise DLP/classifier adapter.
11. information-flow labels.
12. immutable policy/tool versions.
13. emergency deny.
14. Redis rate limiting.
15. OpenTelemetry.
16. append-only audit sink.
17. circuit breakers/deadlines.
18. Agent Framework middleware adapter.
19. Foundry/remote MCP adapter.
20. security/load/chaos test suites.

# 101. Principal-level design questions

Be ready to answer:
1. Why is approval not a boolean?
2. How do you prevent approval substitution?
3. How do you stop indirect prompt injection from triggering privileged tools?
4. Why can't MCP annotations grant permissions?
5. How do delegated credentials work?
6. How do you prevent SSRF?
7. What fails closed?
8. How do you handle policy outages?
9. How do you audit without leaking secrets?
10. How do you scale policy to tens of thousands of calls/sec?
11. How do you handle multi-agent delegation?
12. How does this complement Agent Framework's native approval system?

# 102. Relationship to Microsoft Agent Framework

Agent Framework already has meaningful security mechanisms, so a credible project should integrate rather than claim to replace them.

Use native:
- `allowed_tools`;
- approval modes;
- progressive disclosure;
- sampling approval;
- argument filtering;
- framework security middleware.

Add centralized enterprise concerns:
- cross-agent policy;
- tenant policy;
- DLP;
- credential brokerage;
- exact-action signed approval;
- egress;
- organization audit;
- emergency deny;
- multi-server governance.

# 103. Why this is a separate service

Centralization enables:
- consistent policy across agent languages/frameworks;
- independent security deployment;
- policy change without agent redeploy;
- common audit;
- common approval semantics;
- shared credential/egress controls.

# 104. When not to centralize

Very low-latency local tools may enforce policy in-process.

Still maintain a shared policy model and audit contract.

# 105. Production-readiness statement

This repository is a **production-oriented reference implementation**, not a claim that a ZIP can supply an organization's production identity provider, KMS, network boundaries, DLP classifiers or compliance policy.

The included code is real and runnable. The README identifies exactly where organization-specific production services must replace development implementations.

# 106. Final architecture principle

```text
Agent reasoning
      |
      v
UNTRUSTED REQUEST FOR AUTHORITY
      |
      v
Authenticate
      |
Authorize
      |
Classify data/integrity
      |
Validate exact action
      |
Approval if needed
      |
Issue least privilege
      |
Execute through controlled egress
      |
Classify output
      |
Audit
```

An AI agent should never *possess* ambient enterprise authority merely because it can describe an action.

It should request a narrowly scoped capability for an exact operation, and the security plane should independently decide whether that capability may be exercised.

# Professional Complete Engineering Guide

This section extends the runnable repository into a complete Principal/Staff-level design, security, operations, deployment, testing, scaling, and integration guide.

---

## 107. Executive system design

The firewall is a policy enforcement point between probabilistic reasoning and deterministic authority.

```text
                       USER / APPLICATION
                              |
                              v
                  MICROSOFT AGENT FRAMEWORK
                              |
                      requested action
                              |
                              v
                MCP SECURITY / PERMISSION FIREWALL
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
      Identity            Policy PDP          Data Security
  OIDC / Entra / JWT     RBAC + ABAC         IFC + DLP
          |                   |                   |
          +-------------------+-------------------+
                              |
                              v
                     Risk Classification
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
            ALLOW       APPROVAL_REQUIRED     DENY
                              |
                              v
                   Exact-Action Approval
                              |
                              v
                    Argument Validation
                              |
                              v
                     Credential Broker
                              |
                              v
                     Controlled Egress
                              |
                              v
                         MCP SERVER
                              |
                              v
                       Output Security
                              |
                 +------------+------------+
                 |            |            |
                 v            v            v
                DLP       Classification  Limits
                              |
                              v
                  AUDIT / TRACE / METRICS
```

The security boundary is intentionally independent of the model. A model can request authority; it cannot grant itself authority.

---

## 108. Code execution path

For `/v1/invoke`:

```text
FastAPI
  |
security.principal()
  |
registry.get(tool_id)
  |
Firewall.evaluate()
  |
PolicyEngine.evaluate()
  |-- enabled?
  |-- tenant?
  |-- scopes?
  |-- integrity?
  |-- confidentiality?
  |-- DLP?
  |-- approval?
  |
  +--> deny / approval_required
  |
  +--> allow
        |
        v
     MCPProxy.call()
        |
        v
   bounded MCP output
        |
        v
    audit + metrics
```

The code is intentionally small enough to audit while preserving clear seams for enterprise replacements.

---

## 109. Module-by-module source walkthrough

### `app/main.py`

API/PEP boundary. It exposes liveness, tool listing, policy evaluation, invocation, approval issuance, administrative tool registration and Prometheus metrics.

Keep business security rules out of route handlers. HTTP code should translate requests into trusted internal objects and delegate.

### `app/security.py`

Authenticates a principal.

Trusted principal attributes:

```text
subject
tenant
scopes
roles
```

The development fallback exists only to make local execution frictionless. Production should replace symmetric development JWT handling with OIDC/JWKS validation, normally Microsoft Entra ID in a Microsoft-oriented deployment.

### `app/models.py`

Defines the security contract.

`ToolPolicy` contains locally governed attributes. These are more trustworthy than model-generated or remote MCP descriptions.

`InvocationRequest` contains the proposed action plus information-flow labels.

`Decision` returns one of:

```text
allow
deny
approval_required
```

and may include obligations.

### `app/registry.py`

Seeds representative tools:
- safe read;
- normal write;
- destructive action;
- secret access.

Production uses a durable, versioned registry rather than mutable in-memory state.

### `app/policy.py`

The central deterministic decision engine.

Evaluation order matters. Hard denials happen before approval so approval cannot override fundamental policy such as tenant mismatch or forbidden information flow.

### `app/canonical.py`

Produces stable canonical JSON and SHA-256 hashes.

This is used to bind approval to exact arguments.

### `app/approvals.py`

Issues and verifies signed approval capabilities.

The compact implementation uses HMAC JWT for runnable local development. Production should use asymmetric KMS/HSM signing, key IDs, revocation, and durable nonce consumption.

### `app/dlp.py`

Contains lightweight secret detectors.

This is deliberately an adapter seam, not a claim that regex equals enterprise DLP.

### `app/ssrf.py`

Validates HTTPS endpoints and rejects private, loopback, link-local, multicast and reserved destinations after DNS resolution.

Production must add network enforcement because application-only SSRF checks are insufficient.

### `app/mcp.py`

The MCP execution adapter. It sends JSON-RPC `tools/call`, applies timeout, refuses redirects, and bounds response size.

A mature implementation adds MCP initialization, capability negotiation, session lifecycle, cancellation, task semantics and authentication.

### `app/audit.py`

Emits structured security events.

Production routes these to an append-only/tamper-evident security event pipeline.

### `app/observability.py`

Prometheus decision/invocation/policy-latency metrics.

Production adds OpenTelemetry spans, logs, exemplars and security dashboards.

### `app/service.py`

Coordinates registry lookup, policy evaluation, audit, metrics and MCP invocation.

This is the PEP orchestration layer.

---

## 110. Security decision precedence

Recommended precedence:

```text
1. authentication
2. emergency deny
3. tool/server enabled
4. tenant/resource boundary
5. hard data-flow constraints
6. authorization
7. argument/resource policy
8. DLP
9. risk
10. approval
11. rate/cost limits
12. execution
```

An approval must never override steps 1–8 unless a specific policy explicitly defines a controlled exception.

---

## 111. Production policy input

A mature PDP receives:

```json
{
  "principal": {
    "subject": "...",
    "tenant": "...",
    "roles": ["..."],
    "scopes": ["..."]
  },
  "agent": {
    "id": "...",
    "version": "...",
    "delegation_chain": ["..."]
  },
  "tool": {
    "id": "...",
    "version": "...",
    "server": "...",
    "risk": "write",
    "trust": "internal"
  },
  "resource": {
    "type": "...",
    "id": "...",
    "environment": "production"
  },
  "data": {
    "integrity": "untrusted",
    "confidentiality": "confidential"
  },
  "request": {
    "arguments_hash": "...",
    "region": "...",
    "time": "..."
  }
}
```

The model does not populate trusted identity or policy attributes.

---

## 112. Policy output

A scalable contract is:

```json
{
  "decision": "allow",
  "policy_version": "2026-10-02.17",
  "obligations": [
    "force_sandbox",
    "limit_output:262144",
    "audit:full"
  ]
}
```

Obligations allow policy to prescribe enforcement rather than only returning a boolean.

---

## 113. OPA/Rego adapter

Recommended deployment:

```text
Firewall PEP
    |
trusted policy input
    |
OPA PDP
    |
decision + obligations
```

Advantages:
- policy-as-code;
- deterministic evaluation;
- testability;
- independent policy release.

Do not allow the LLM to generate active Rego dynamically.

---

## 114. Cedar adapter

Cedar is useful for principal/action/resource/context authorization.

Example conceptual policy:

```text
permit(
  principal,
  action == Tool::"github.search",
  resource
)
when {
  context.tenant == resource.tenant &&
  context.integrity != "forbidden"
};
```

Information-flow, DLP and egress controls remain complementary.

---

## 115. Entra/OIDC production authentication

Production validation should verify:
- signature through JWKS;
- issuer;
- audience;
- expiry/not-before;
- tenant;
- authorized client/application;
- key rotation.

Do not accept a tenant from request JSON as authoritative.

---

## 116. Workload identity

Machine-to-machine calls should prefer workload identity over stored client secrets.

```text
Agent Runtime
   |
workload identity
   |
Firewall
```

For downstream services, use token exchange/on-behalf-of where appropriate.

---

## 117. Delegated identity

For user-delegated operations:

```text
User
 |
Agent
 |
Firewall
 |
Credential Broker
 |
downstream delegated token
```

The downstream token should be scoped to the destination and requested operation.

---

## 118. Credential broker contract

Input:

```text
principal
tool
resource
requested scopes
```

Output:

```text
short-lived credential handle/token
expiry
audience
scope
```

Credentials must not be placed into prompts, tool descriptions or normal audit logs.

---

## 119. KMS-backed approval

Production approval issuance:

```text
approval payload
      |
      v
 canonical encoding
      |
      v
 KMS/HSM signing
      |
      v
 signed capability
```

Include a `kid` for key rotation.

---

## 120. One-time approval consumption

For high-risk actions:

```text
ISSUED
  |
atomic consume
  |
CONSUMED
```

A replay attempt observes `CONSUMED` and is denied.

Use a durable store or strongly consistent cache depending on risk.

---

## 121. Approval canonicalization

Canonicalize:
- object key order;
- numeric representation;
- Unicode normalization policy;
- omitted/default fields.

The verifier and issuer must hash exactly the same semantic request.

---

## 122. Approval scope minimization

Prefer:

```text
one principal
one tool version
one resource
one exact argument set
one short expiry
one use
```

Broad approvals increase blast radius.

---

## 123. Approval UX

Show the human:

```text
Action: Send Teams message
Destination: incident-42
Message: "Rollback completed"
Identity: Suhas / delegated agent
Risk: Write
Data: Internal
Expiry: 5 minutes
```

A human should understand the actual effect.

---

## 124. Approval fatigue control

Do not require confirmation for every harmless read.

Use:
- automatic low-risk reads;
- approval for meaningful writes;
- stronger approval for destructive/secret operations;
- hard denial for prohibited actions.

This preserves attention for important decisions.

---

## 125. Integrity labels

Suggested lattice:

```text
TRUSTED
  |
MIXED
  |
UNTRUSTED
```

Examples:
- explicit user instruction: trusted;
- retrieved corporate document: policy-dependent;
- arbitrary webpage/email/tool output: untrusted.

A transformation does not automatically make untrusted data trusted.

---

## 126. Integrity propagation

If a workflow combines trusted and untrusted values:

```text
trusted + untrusted -> untrusted/mixed
```

A privileged sink can require trusted provenance for fields that control the side effect.

---

## 127. Field-level integrity

Instead of labeling the entire request:

```text
channel = trusted
message = untrusted
```

Policy may permit sending untrusted text to a fixed trusted destination, while denying an untrusted value from choosing the destination.

This is significantly more precise than request-level labeling.

---

## 128. Confidentiality lattice

```text
PUBLIC
  <
INTERNAL
  <
CONFIDENTIAL
  <
RESTRICTED
```

A destination has a maximum accepted classification and residency/trust attributes.

---

## 129. Field-level confidentiality

Example:

```text
customer_id = INTERNAL
medical_note = RESTRICTED
```

Policy can redact the restricted field before an approved external call.

---

## 130. DLP pipeline

```text
arguments
  |
structured classifiers
  |
secret scanner
  |
PII classifiers
  |
organization rules
  |
decision
```

Possible outcomes:

```text
pass
redact
tokenize
require approval
deny
```

---

## 131. DLP false-positive handling

Never globally disable a detector to fix one false positive.

Use:
- scoped exception;
- policy version;
- owner;
- expiry;
- audit.

---

## 132. DLP false-negative defense

DLP is one layer.

Also use:
- destination allowlists;
- confidentiality policy;
- credential scoping;
- egress controls;
- output/input byte budgets.

---

## 133. Exfiltration controls

Per workflow/session:
- allowed domains;
- allowed MCP servers;
- maximum external bytes;
- maximum calls;
- maximum sensitive records.

This limits blast radius even after a policy mistake.

---

## 134. Tool registration security

Tool registration should require:
- authenticated administrator/service;
- owner;
- server identity;
- immutable version;
- risk review;
- data boundary;
- credential profile;
- endpoint class;
- schema;
- provenance.

Registration is a control-plane action, not an agent action.

---

## 135. Server trust levels

```text
INTERNAL
APPROVED_VENDOR
COMMUNITY
UNTRUSTED
```

Trust only restricts. It never grants user authority.

---

## 136. Endpoint allowlists

Production endpoint records should be pre-approved.

The invocation request references `server_id`; it should not contain arbitrary URLs.

---

## 137. DNS rebinding

SSRF protection must account for DNS changes between validation and connection.

Strong solutions:
- controlled egress proxy;
- DNS pinning/resolution policy;
- network firewall.

---

## 138. Redirect handling

The reference MCP client disables redirects.

If redirects are ever supported, validate every hop against the egress policy.

---

## 139. Cloud metadata protection

Explicitly block:
- link-local metadata IPs;
- metadata hostnames;
- internal control-plane endpoints.

Enforce at network layer.

---

## 140. mTLS

Internal MCP servers may use mTLS:

```text
Firewall workload identity
       |
       v
service mesh / mTLS
       |
       v
MCP server
```

This authenticates both ends.

---

## 141. MCP protocol negotiation

A production client should:

```text
connect
 |
initialize
 |
negotiate protocol/capabilities
 |
establish session
 |
invoke
```

Never assume every server supports the same feature set.

---

## 142. MCP sampling governance

Server-initiated sampling can consume model authority/cost.

Policy input should include:
- server trust;
- requested model;
- token limit;
- request count;
- purpose;
- data classification.

Default-deny is a strong baseline.

---

## 143. MCP elicitation governance

If a server requests additional user input, treat it as an untrusted request.

Never allow it to solicit secrets unless policy explicitly permits the field and destination.

---

## 144. MCP resource governance

Resource reads can expose sensitive data.

Apply the same tenant, classification and trust policies as tool calls.

---

## 145. MCP task governance

Long-running tasks need:
- task identity;
- cancellation;
- authorization continuity;
- output classification;
- audit.

Do not assume initial authorization grants unlimited future actions.

---

## 146. Long-running authorization

For a 2-hour workflow, re-evaluate before consequential steps.

Policy or emergency deny may have changed since workflow start.

---

## 147. Tool schema validation

Production:

```python
jsonschema.validate(arguments, tool.input_schema)
```

Also enforce:
- maximum string length;
- array limits;
- unknown fields;
- URI/domain constraints;
- numeric bounds.

---

## 148. Semantic policy validation

Example:

```text
schema permits:
environment = any string

policy permits:
environment in ["dev", "staging"]
```

Schema and policy solve different problems.

---

## 149. Resource extraction

Normalize important resource identifiers:

```text
subscription
resource_group
cluster
namespace
repository
branch
mail_recipient
channel
database
table
```

Policy can then reason structurally instead of parsing arbitrary text.

---

## 150. Destination policy

Example:

```text
teams.send
  internal tenant channel -> normal write
  external federation     -> stronger DLP/approval
```

---

## 151. Email policy

Possible rules:

```text
mail.search -> read
mail.draft -> write
mail.send internal -> approval
mail.send external -> DLP + approval
mail.send restricted data -> deny
```

---

## 152. GitHub policy

Possible:

```text
repo.search -> allow
issue.comment -> scoped write
pr.create -> approval depending on repo
merge main -> stronger approval
delete repo -> deny
```

---

## 153. Azure operations policy

Possible:

```text
logs.query -> allow
resource.inspect -> allow
restart dev -> scoped write
restart prod -> approval
delete production resource -> deny
```

---

## 154. Browser policy

Separate:
- navigation;
- data entry;
- file upload;
- download;
- credential entry;
- purchase/submission.

High-level browser effects need policy, not only low-level click permissions.

---

## 155. Sandbox policy

Obligation:

```text
force_sandbox
```

for:
- arbitrary code;
- CLI;
- downloaded files;
- unknown scripts.

The sandbox itself must enforce network and filesystem limits.

---

## 156. Command policy

Never pass arbitrary shell strings through the firewall.

Prefer:

```text
executable
argv[]
working_directory_ref
```

and execute without `shell=True`.

---

## 157. File policy

Track:
- source;
- classification;
- MIME/type;
- malware scan;
- destination.

A downloaded file is untrusted until validated.

---

## 158. Output schema validation

If a tool declares an output schema, validate it.

Malformed output should not silently become trusted agent context.

---

## 159. Output classification

Classify output based on:
- tool metadata;
- source;
- content classifier;
- resource classification.

Propagate label downstream.

---

## 160. Output size controls

Bound:
- response bytes;
- nested depth;
- number of records;
- attachments.

This protects memory, token budget and downstream model context.

---

## 161. Audit event schema

Recommended:

```json
{
  "event":"tool.policy_decision",
  "timestamp":"...",
  "trace_id":"...",
  "tenant":"...",
  "principal":"...",
  "agent":"...",
  "tool_id":"...",
  "tool_version":"...",
  "arguments_hash":"...",
  "decision":"approval_required",
  "policy_version":"...",
  "data_classification":"internal",
  "integrity":"trusted"
}
```

Avoid raw secret-bearing arguments.

---

## 162. Tamper-evident audit

Options:
- append-only storage;
- WORM retention;
- hash chaining;
- signed batches;
- SIEM ingestion.

Audit integrity is itself a security asset.

---

## 163. Trace design

```text
agent.run
  |
  +-- firewall.evaluate
  |     +-- authz
  |     +-- dlp
  |     +-- approval.verify
  |
  +-- credential.resolve
  |
  +-- mcp.call
        +-- connect
        +-- request
        +-- response.classify
```

Never put credentials into trace attributes.

---

## 164. Metrics

Security:
- deny rate;
- approval-required rate;
- DLP blocks;
- integrity violations;
- confidentiality violations;
- replay attempts.

Operations:
- policy p95/p99;
- MCP latency;
- credential latency;
- KMS latency;
- output bytes;
- server errors.

---

## 165. Alerting

High-severity alerts:
- cross-tenant attempt spike;
- approval replay;
- emergency-denied tool invocation attempt;
- DLP spike;
- credential broker anomaly;
- audit pipeline loss;
- unexpected external destination.

---

## 166. Rate-limit hierarchy

```text
global
tenant
principal
agent
tool
server
risk class
```

Use the narrowest useful limiter plus global protection.

---

## 167. Token-bucket example

Redis-backed token bucket can protect hot paths.

High-risk operations may have very low quotas independent of ordinary read traffic.

---

## 168. Cost governance

Policy can enforce:
- daily tool spend;
- browser/sandbox minutes;
- paid API call limits;
- server-initiated sampling tokens.

Economic abuse is a security/reliability concern.

---

## 169. Circuit breakers

A failing MCP server should trip a circuit breaker.

States:

```text
CLOSED -> OPEN -> HALF_OPEN -> CLOSED
```

Circuit state must not weaken authorization.

---

## 170. Timeouts

Use:
- connect timeout;
- read timeout;
- overall deadline.

Propagate remaining workflow deadline rather than stacking independent timeouts.

---

## 171. Retry ownership

Reads can often retry.

Writes require idempotency knowledge.

Destructive operations should generally reconcile before retry after an ambiguous failure.

---

## 172. Idempotency record

Recommended:

```text
tenant
tool_version
idempotency_key
request_hash
state
result_ref
created_at
expires_at
```

States:

```text
IN_PROGRESS
SUCCEEDED
FAILED
UNKNOWN
```

---

## 173. Unknown outcome

If connection breaks after a write may have reached provider:

```text
UNKNOWN
```

Do not blindly execute again.

Use provider reconciliation.

---

## 174. Emergency deny plane

A tiny, fast path:

```text
denied_tool_ids
denied_server_ids
denied_tenants
denied_credential_profiles
```

Check immediately before side effect.

---

## 175. Policy rollout

```text
draft
 |
tests
 |
shadow
 |
canary
 |
active
```

Version every decision.

---

## 176. Shadow policy

Evaluate new policy without enforcing it.

Compare:

```text
current=allow
candidate=deny
```

before rollout.

---

## 177. Break-glass access

If required:
- explicit privileged role;
- reason;
- short TTL;
- stronger authentication;
- full audit;
- post-event review.

Break-glass should not mean "disable firewall."

---

## 178. Policy conflict resolution

Define deterministic precedence:

```text
explicit deny
>
mandatory compliance restriction
>
resource restriction
>
role allow
>
default deny
```

Avoid ambiguous policy merging.

---

## 179. Multi-agent delegation

Track:

```text
human
 -> orchestrator
 -> specialist
 -> tool
```

Effective authority should be intersection/minimum, not union.

A child agent cannot exceed delegated authority.

---

## 180. Delegation token

A delegation capability can bind:
- parent;
- child;
- scopes;
- tool classes;
- expiry;
- run ID.

This enables auditable multi-agent authority.

---

## 181. Agent identity

Authenticate the agent/runtime separately from the human user.

Policy can then say:

```text
user may write
AND
agent build-v17 is approved for this tool
```

---

## 182. Tool identity

Use immutable:

```text
tenant/server/tool/version
```

Do not authorize only by display name.

---

## 183. Server identity

Bind:
- server ID;
- endpoint;
- certificate/workload identity;
- owner;
- trust;
- region.

Endpoint changes should trigger review for sensitive servers.

---

## 184. Policy data model

Recommended tables:

```text
principals/roles
tools/tool_versions
servers
policies/policy_versions
resource_bindings
approval_records
approval_consumptions
emergency_denies
audit_events
```

---

## 185. PostgreSQL isolation

For strong tenant boundaries:
- tenant column on every relevant row;
- RLS where appropriate;
- separate service credentials;
- migration tests.

Application filtering alone should not be the only tenant boundary for critical data.

---

## 186. Redis use

Good uses:
- rate limits;
- short decision cache;
- nonce replay cache;
- circuit state.

Do not make Redis the sole durable audit store.

---

## 187. Database migrations

Use Alembic.

Rules:
- backward-compatible expand;
- deploy code;
- migrate/backfill;
- contract later.

Avoid destructive schema changes during mixed-version deployment.

---

## 188. Secrets management

Use:
- Azure Key Vault;
- Vault;
- KMS/HSM;
- workload identity.

Never commit production secrets into `.env`.

---

## 189. Key rotation

Approval signing keys:
- publish new key;
- start signing with new `kid`;
- continue verifying old until expiry;
- retire old.

Credential encryption keys require similar rotation planning.

---

## 190. Kubernetes production topology

```text
Ingress/API
   |
Firewall replicas
   |
+-- PDP/OPA
+-- Redis
+-- PostgreSQL
+-- Credential Broker
+-- OTel Collector
   |
Egress Proxy
   |
MCP servers
```

---

## 191. Kubernetes hardening

Use:
- `runAsNonRoot`;
- read-only root filesystem;
- seccomp RuntimeDefault;
- dropped capabilities;
- NetworkPolicy;
- dedicated ServiceAccount;
- workload identity;
- resource limits;
- topology spread.

---

## 192. Egress NetworkPolicy

Firewall pods should not have unrestricted Internet access.

Allow only:
- credential services;
- approved egress proxy;
- telemetry;
- required internal dependencies.

---

## 193. HPA

Scale on:
- CPU;
- request rate;
- policy latency;
- queue depth if asynchronous.

Keep enough warm capacity for approval bursts/incidents.

---

## 194. PDB

A PodDisruptionBudget protects availability during maintenance.

Do not combine PDB with insufficient capacity such that upgrades deadlock.

---

## 195. Multi-region cells

```text
             Global Policy Control
                    |
        +-----------+-----------+
        |                       |
      EU Cell                 US Cell
        |                       |
 Firewall/PDP              Firewall/PDP
        |                       |
 regional MCP             regional MCP
```

Sensitive payloads stay in region.

---

## 196. Policy replication

Replicate immutable policy versions globally.

Emergency deny needs a faster propagation channel.

---

## 197. Approval locality

For residency-sensitive tenants, store approvals and audit in-region.

Global systems may store only hashes/metadata.

---

## 198. Disaster recovery

Define RPO/RTO for:
- policy;
- registry;
- approvals;
- audit;
- credential configuration.

Test restore rather than only documenting backups.

---

## 199. Graceful degradation

### Metrics unavailable
Continue enforcement; buffer/drop metrics according to policy.

### Audit unavailable
For high-risk actions, organization may choose fail-closed.

### Redis unavailable
Disable caches/rate-limit fast paths or fail closed depending on operation.

### PDP unavailable
Consequential operations fail closed. A tightly bounded last-known policy cache may be acceptable for explicitly approved low-risk reads.

### MCP unavailable
Return provider error; do not bypass firewall.

---

## 200. Production error taxonomy

```text
AUTHENTICATION_FAILED
AUTHORIZATION_DENIED
APPROVAL_REQUIRED
APPROVAL_INVALID
APPROVAL_EXPIRED
APPROVAL_REPLAYED
TOOL_NOT_FOUND
TOOL_DISABLED
TENANT_MISMATCH
INTEGRITY_VIOLATION
CONFIDENTIALITY_VIOLATION
DLP_VIOLATION
SCHEMA_INVALID
RATE_LIMITED
COST_LIMIT_EXCEEDED
CREDENTIAL_UNAVAILABLE
EGRESS_DENIED
MCP_TIMEOUT
MCP_PROTOCOL_ERROR
OUTPUT_POLICY_VIOLATION
INTERNAL_ERROR
```

Stable error classes make workflow handling predictable.

---

## 201. API design

Recommended production endpoints:

```text
POST /v1/evaluate
POST /v1/invoke
POST /v1/approvals
POST /v1/approvals/{id}/revoke
GET  /v1/decisions/{id}
GET  /v1/tools
PUT  /v1/admin/tools/{id}
PUT  /v1/admin/policies/{id}
POST /v1/admin/emergency-deny
GET  /health/live
GET  /health/ready
GET  /metrics
```

Administrative APIs should use a separate authorization plane.

---

## 202. Evaluate vs invoke

`evaluate` is useful for UX/planning.

`invoke` **must re-evaluate**.

Never rely on an earlier allow response as durable authorization.

---

## 203. Dry-run mode

A dry-run can show:

```text
would allow
would require approval
would redact
would force sandbox
```

Dry-run never performs the side effect.

---

## 204. Policy explanation

Return human-readable reasons without exposing sensitive internal policy details.

Good:

```text
production restart requires approval
```

Avoid leaking security internals that aid bypass.

---

## 205. Application: Microsoft 365 copilot-style agent

```text
mail.search                -> allow read
calendar.read              -> allow read
teams.send                 -> approval
mail.send_external         -> DLP + approval
sharepoint.download_secret -> classification policy
```

---

## 206. Application: Azure SRE agent

```text
monitor.logs.query -> allow
resource.get       -> allow
vm.restart(dev)    -> scoped write
vm.restart(prod)   -> approval
subscription.delete -> deny
```

---

## 207. Application: GitHub engineering agent

```text
code.search       -> allow
issue.comment     -> scoped write
pr.create         -> repo policy
pr.merge(main)    -> approval
repo.delete       -> deny
```

---

## 208. Application: Playwright/browser agent

```text
navigate approved site -> allow
download file          -> sandbox/scan
upload internal file   -> destination policy
submit purchase        -> approval
enter password         -> credential broker only
```

---

## 209. Application: database agent

```text
SELECT analytics -> allow
SELECT restricted PII -> classification policy
UPDATE -> write scope/approval
DROP -> deny
```

---

## 210. Application: autonomous incident commander

Reads:
- logs;
- traces;
- deployments;
- alerts.

Writes:
- post incident updates;
- rollback;
- restart;
- feature flag.

Firewall differentiates read investigation from remediation authority.

---

## 211. Application: software engineering agent

The agent can:
- inspect code;
- run tests in sandbox;
- create branch;
- propose PR.

Merging/releasing can require human approval.

---

## 212. Application: customer support agent

```text
customer.lookup -> allow
order.status -> allow
refund.preview -> allow
refund.execute -> amount/risk-based approval
```

---

## 213. Application: security response agent

```text
SIEM search -> allow
endpoint inspect -> allow
isolate endpoint -> approval
disable identity -> approval
read secret -> restricted
```

---

## 214. Application: research agent

Web/search tools receive only data allowed for external disclosure.

Internal confidential context can be used locally while external queries are redacted/generalized.

---

## 215. Application: multi-agent platform

```text
Orchestrator
  |
delegation
  |
Specialist Agent
  |
Firewall
  |
MCP/A2A capability
```

Every hop preserves identity/delegation provenance.

---

## 216. Integration with Tool Discovery & Routing Engine

Recommended order:

```text
intent
  |
Discovery Engine
  |
authorized-to-disclose candidate tools
  |
model selects exact capability
  |
Firewall re-evaluates exact invocation
  |
execute
```

Discovery-time filtering reduces unsafe exposure; invocation-time enforcement is authoritative.

---

## 217. Integration with Connector Gateway

```text
Firewall
  |
authorized invocation
  |
Connector Gateway
  |
MCP / REST / GraphQL / CLI
```

The firewall decides authority. The gateway normalizes transport/execution.

---

## 218. Integration with Workflow Compiler

Compiler pins:

```text
tool_version
risk expectation
resource selector
```

Runtime firewall independently validates the actual action.

---

## 219. Integration with Memory Server

Memory may influence context but never authorization.

A remembered statement such as:

```text
"user said I can always restart prod"
```

has no security authority.

---

## 220. Integration with Sandbox Manager

Policy obligation:

```text
force_sandbox
```

routes dangerous computation to isolated execution.

---

## 221. Full Microsoft Agent Tool Fabric

```text
                   Microsoft Agent Framework
                              |
                              v
                     Tool Discovery
                              |
                              v
                 MCP Permission Firewall
                              |
             +----------------+----------------+
             |                                 |
             v                                 v
      Connector Gateway                 Sandbox Manager
             |
      +------+-------+
      |      |       |
     MCP    A2A     REST
      |
  Azure / M365 / GitHub / Playwright

Memory Server <-> Workflow Compiler <-> Agent runtime

Observability across every layer
```

---

## 222. Local Docker run

```bash
unzip mcp-security-permission-firewall-professional-complete.zip
cd mcp-security-permission-firewall
cp .env.example .env
docker compose up --build
```

Check:

```bash
curl http://localhost:8120/health/live
curl http://localhost:8120/v1/tools
curl http://localhost:8120/metrics
```

Open API documentation:

```text
http://localhost:8120/docs
```

---

## 223. Docker background mode

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f firewall
```

Stop:

```bash
docker compose down
```

Reset local state:

```bash
docker compose down -v
```

---

## 224. Native Python run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
export ENV=dev
uvicorn app.main:app --host 0.0.0.0 --port 8120 --reload
```

---

## 225. Run tests

```bash
pytest -q
```

Lint:

```bash
ruff check .
```

---

## 226. Safe read test

```bash
curl -s -X POST http://localhost:8120/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "tool_id":"github.search@1",
    "arguments":{"q":"agent framework"},
    "context_integrity":"trusted",
    "confidentiality":"public"
  }' | python -m json.tool
```

Expected decision:

```text
allow
```

---

## 227. Approval-required write test

```bash
curl -s -X POST http://localhost:8120/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "tool_id":"teams.send@1",
    "arguments":{
      "channel":"incident-42",
      "message":"Rollback completed"
    }
  }' | python -m json.tool
```

Expected:

```text
approval_required
```

---

## 228. Issue approval

```bash
curl -s -X POST http://localhost:8120/v1/approvals \
  -H 'content-type: application/json' \
  -d '{
    "tool_id":"teams.send@1",
    "arguments":{
      "channel":"incident-42",
      "message":"Rollback completed"
    },
    "ttl_seconds":300
  }'
```

Copy the returned token.

---

## 229. Invoke with approval

```bash
curl -s -X POST http://localhost:8120/v1/invoke \
  -H 'content-type: application/json' \
  -d '{
    "tool_id":"teams.send@1",
    "arguments":{
      "channel":"incident-42",
      "message":"Rollback completed"
    },
    "approval_token":"PASTE_TOKEN"
  }' | python -m json.tool
```

The seeded tool intentionally runs in reference mode unless a governed MCP endpoint is configured.

---

## 230. Approval substitution test

Reuse the token but modify the message.

The approval should no longer verify because the canonical argument hash changed.

This is a critical security regression test.

---

## 231. Untrusted context test

```bash
curl -s -X POST http://localhost:8120/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "tool_id":"teams.send@1",
    "arguments":{"message":"Instructions copied from a webpage"},
    "context_integrity":"untrusted"
  }' | python -m json.tool
```

Expected denial.

---

## 232. DLP test

```bash
curl -s -X POST http://localhost:8120/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "tool_id":"github.search@1",
    "arguments":{"q":"api_key=supersecretvalue123"}
  }' | python -m json.tool
```

Expected denial.

---

## 233. Destructive operation test

```bash
curl -s -X POST http://localhost:8120/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "tool_id":"azure.vm.restart@1",
    "arguments":{"resource":"prod-vm-01"}
  }' | python -m json.tool
```

With the development principal, this reaches the approval gate rather than executing automatically.

---

## 234. Unit test expansion

Add:
- wrong tenant;
- wrong subject approval;
- wrong tool approval;
- expired token;
- malformed token;
- DLP cases;
- confidentiality cases;
- integrity cases;
- disabled tool;
- missing scope.

---

## 235. Property-based tests

Useful invariants:

```text
changing any approval-bound argument invalidates approval
raising confidentiality cannot turn deny into allow
removing scopes cannot turn deny into allow
disabling a tool cannot turn deny into allow
```

These monotonic security properties are excellent fuzz/property targets.

---

## 236. MCP integration tests

Mock server scenarios:
- successful `tools/call`;
- timeout;
- malformed JSON-RPC;
- oversized output;
- protocol error;
- server disconnect;
- malicious output.

---

## 237. Security test suite

Mandatory:
- cross-tenant invocation;
- SSRF endpoint;
- DNS rebinding simulation;
- approval replay;
- approval substitution;
- credential leakage;
- prompt injection flow;
- tool-description poisoning;
- output poisoning;
- schema abuse;
- rate-limit bypass.

---

## 238. Load test

Measure:
- `/v1/evaluate` QPS;
- `/v1/invoke` overhead;
- p50/p95/p99;
- Redis/KMS/PDP latency;
- audit throughput.

Separate policy overhead from downstream MCP latency.

---

## 239. Chaos tests

Inject:
- OPA unavailable;
- Redis unavailable;
- PostgreSQL unavailable;
- KMS unavailable;
- credential broker unavailable;
- audit sink unavailable;
- MCP timeout.

Verify the documented fail-closed/fail-safe behavior.

---

## 240. CI/CD pipeline

```text
checkout
  |
dependency lock validation
  |
ruff
  |
unit/property tests
  |
policy tests
  |
security tests
  |
MCP integration tests
  |
container build
  |
SBOM
  |
SAST/dependency/image scan
  |
sign image
  |
staging
  |
shadow/canary
  |
production
```

---

## 241. Production migration roadmap

### Phase 1
Current runnable FastAPI/reference policy.

### Phase 2
PostgreSQL + Alembic + immutable tool/policy versions.

### Phase 3
Entra OIDC/JWKS + workload identity.

### Phase 4
OPA/Cedar PDP.

### Phase 5
KMS approvals + durable one-time nonce consumption.

### Phase 6
Credential broker + controlled egress.

### Phase 7
Enterprise DLP/classification.

### Phase 8
Full MCP negotiation/tasks/cancellation.

### Phase 9
OTel + SIEM + tamper-evident audit.

### Phase 10
Regional cells, DR, chaos/load maturity.

---

## 242. Production readiness checklist

- [ ] Entra/OIDC/JWKS
- [ ] workload identity
- [ ] durable registry
- [ ] immutable tool versions
- [ ] immutable policy versions
- [ ] OPA/Cedar adapter
- [ ] KMS/HSM approval signing
- [ ] one-time approval consumption
- [ ] approval revocation
- [ ] credential broker
- [ ] JSON Schema validation
- [ ] semantic resource policy
- [ ] enterprise DLP
- [ ] field-level information-flow labels
- [ ] endpoint allowlists
- [ ] egress proxy
- [ ] NetworkPolicy
- [ ] MCP initialization/negotiation
- [ ] tasks/cancellation/deadlines
- [ ] idempotency/reconciliation
- [ ] rate/cost limits
- [ ] emergency deny
- [ ] OpenTelemetry
- [ ] tamper-evident audit
- [ ] SIEM integration
- [ ] HPA/PDB/topology spread
- [ ] SBOM/signing/scanning
- [ ] property/security/load/chaos tests
- [ ] backup/restore drills
- [ ] documented incident response

---

## 243. Troubleshooting: unexpected deny

Check:
1. authenticated principal;
2. tenant;
3. scopes;
4. tool enabled;
5. integrity;
6. confidentiality;
7. DLP;
8. approval.

Use the structured decision reasons and trace ID.

---

## 244. Troubleshooting: approval invalid

Verify:
- same principal;
- same tenant;
- same tool ID/version;
- exact same arguments;
- token not expired;
- signing key valid.

Canonicalization differences are a common source of bugs.

---

## 245. Troubleshooting: DLP false positive

Inspect detector/classifier result.

Create a narrow tested exception if justified. Do not globally disable DLP.

---

## 246. Troubleshooting: MCP timeout

Check:
- endpoint reachability;
- egress policy;
- TLS;
- authentication;
- server health;
- negotiated protocol;
- deadline.

Do not retry destructive calls blindly.

---

## 247. Troubleshooting: policy latency

Trace:
- local policy;
- remote PDP;
- DLP;
- KMS;
- Redis;
- credential service.

Cache only safe/stable inputs.

---

## 248. Incident: compromised MCP server

```text
1. emergency deny server
2. block egress
3. revoke credentials
4. preserve audit
5. identify affected calls/data
6. rotate secrets
7. inspect tool/output poisoning
8. remediate
9. controlled re-registration
```

---

## 249. Incident: approval signing key compromise

```text
1. stop accepting affected kid
2. rotate KMS key
3. revoke outstanding approvals
4. inspect approval/invocation audit
5. reissue required approvals
```

---

## 250. Incident: policy misconfiguration

```text
1. activate previous immutable policy
2. emergency deny affected capability if necessary
3. invalidate caches
4. analyze decisions
5. add regression test
6. canary corrected policy
```

---

## 251. Incident: suspected data exfiltration

```text
1. deny affected destination/tool
2. revoke credential
3. preserve DLP/audit/network logs
4. determine data classification/volume
5. follow organization incident process
6. remediate policy
```

---

## 252. Principal-level tradeoff: centralized firewall vs SDK-only controls

SDK controls are close to the agent and useful.

Centralized firewall adds:
- cross-framework consistency;
- independent security release;
- shared DLP;
- shared credentials;
- shared audit;
- organization policy;
- emergency deny.

A mature system uses defense in depth rather than choosing only one.

---

## 253. Principal-level tradeoff: local PDP vs remote PDP

Local:
- low latency;
- fewer dependencies.

Remote:
- centralized updates;
- common governance.

A common design embeds a policy runtime locally while distributing signed/versioned policy bundles centrally.

---

## 254. Principal-level tradeoff: fail-open vs fail-closed

For consequential actions, fail closed.

For telemetry, fail open.

For low-risk reads, a last-known validated policy may be acceptable depending on organization requirements.

Document each dependency explicitly.

---

## 255. Principal-level tradeoff: synchronous DLP vs asynchronous DLP

Synchronous:
- blocks before disclosure;
- adds latency.

Asynchronous:
- useful for audit/post-processing;
- too late to prevent initial leak.

Sensitive egress requires synchronous enforcement.

---

## 256. Principal-level tradeoff: human approval vs automated policy

Human approval handles ambiguous/high-impact intent.

Automated policy handles repetitive deterministic constraints.

Do not use human approval as a substitute for tenant isolation or hard security controls.

---

## 257. Principal-level tradeoff: policy granularity

Too coarse:

```text
allow GitHub
```

Too fine:
millions of brittle one-off rules.

Good:
resource/action/environment/data attributes with reusable policies.

---

## 258. Principal-level tradeoff: full payload audit vs privacy

Full payload improves forensics but increases sensitive-data risk.

Prefer:
- hashes;
- metadata;
- classifications;
- restricted payload vault only when required.

---

## 259. Narrative

> I treat every agent tool invocation as an untrusted request for authority. The firewall authenticates the human/workload identity, resolves immutable tool policy, applies tenant and information-flow constraints, performs DLP and resource-aware authorization, and then either denies, allows, or requests an exact-action approval cryptographically bound to the arguments. Credentials are issued just in time and scoped to the destination. MCP traffic exits only through governed egress, outputs remain untrusted and classified, and every decision is versioned and auditable. Native Agent Framework controls remain the first layer; the firewall supplies organization-wide governance across frameworks and MCP servers.

---

## 260. Key question: why isn't approval enough?

Because approval cannot safely override:
- tenant mismatch;
- prohibited data exfiltration;
- invalid identity;
- disabled/compromised tool;
- forbidden destination.

Approval is one policy input, not root authority.

---

## 261. Key question: how do you stop prompt injection?

Not by trying to perfectly detect malicious language.

Instead:
- label external content untrusted;
- propagate integrity;
- restrict privileged sinks;
- bind approvals to exact actions;
- keep credentials outside model context;
- enforce policy outside the model.

---

## 262. Key question: how do you scale?

Keep hot-path policy deterministic.

At large scale:
- stateless firewall replicas;
- local policy bundle;
- Redis for rate/replay;
- regional credential service;
- append-only async audit;
- regional cells;
- bounded synchronous DLP.

---

## 263. Key question: what is the hardest correctness problem?

Authority continuity across a multi-step agent workflow:

```text
identity
delegation
tool version
arguments
data provenance
approval
policy version
credential
side effect
```

All must refer to the same intended action despite retries, replanning and concurrent execution.

---

## 264. Key question: how do you handle unknown write outcomes?

Never blindly retry.

Record `UNKNOWN`, query provider/reconcile using idempotency/resource state, then decide whether retry is safe.

---

## 265. Key question: what does the model control?

The model may propose:
- tool;
- arguments;
- reason.

It does not control:
- principal;
- tenant;
- policy;
- risk;
- trust;
- credentials;
- emergency deny;
- approval validity.

---

## 266. Repository evolution

```text
mcp-security-firewall/
├── api/
├── auth/
├── domain/
├── registry/
├── policy/
│   ├── opa/
│   └── cedar/
├── approvals/
├── dlp/
├── information_flow/
├── credentials/
├── egress/
├── mcp/
├── sandbox/
├── audit/
├── telemetry/
├── persistence/
├── migrations/
├── tests/
│   ├── unit/
│   ├── property/
│   ├── policy/
│   ├── integration/
│   ├── security/
│   ├── load/
│   └── chaos/
├── deploy/
└── docs/
```

---

## 267. Professional production statement

The repository contains real runnable security code, not empty placeholder classes. However, no generic ZIP can honestly provide an organization's actual Entra tenant, production KMS keys, enterprise DLP classifiers, network boundaries, compliance rules or MCP credentials.

Those are represented as explicit integration seams and production upgrade steps rather than insecure fake implementations.

---

## 268. Final design principle

**Agents should request capabilities, not possess ambient authority.**

The system should transform:

```text
"I want to restart production"
```

into:

```text
authenticated principal
+ exact immutable tool
+ exact resource
+ exact arguments
+ trusted policy context
+ data-flow classification
+ exact approval when required
+ least-privilege credential
+ controlled network path
+ auditable side effect
```

That transformation—from probabilistic intent to narrowly scoped deterministic authority—is the core purpose of the MCP Security / Permission Firewall.

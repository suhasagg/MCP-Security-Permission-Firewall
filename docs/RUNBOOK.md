# Runbook

## Compromised server
Disable tool/server, block egress, revoke credentials, preserve audit, identify affected calls, rotate secrets.

## Policy outage
Fail closed for consequential operations. A narrowly defined cached policy may be allowed only if organization policy explicitly permits it.

## Approval-key compromise
Rotate signing key, revoke outstanding approvals, inspect audit, reissue approvals.

## DLP false positive
Do not bypass globally. Investigate pattern/classifier, add scoped policy exception with audit.

# Architecture

The firewall is an independent policy enforcement point between agent reasoning and MCP execution.

`agent -> authenticated principal -> policy context -> RBAC/ABAC/IFC/DLP -> approval -> argument validation -> credential/egress boundary -> MCP -> output controls -> audit`.

See README for the full Principal-level design.

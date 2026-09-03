# ADR 009: Agent Relay is an optional future MCP client

Status: accepted design boundary.

## Decision

Continuum remains a separate repository and runtime with no Agent Relay dependency. Relay
may later use the generic MCP contract under a project/provider capability. Relay owns
routing, limits, execution, transient checkpoints, current intent, and action authorization.
Continuum owns durable memory semantics.

Relay may persist opaque memory/version/recall IDs and projection watermarks, never durable
claim/evidence bodies. It must preserve citations, conflict/status fields, and
`authority=data`; it cannot convert memory into current authorization. Deletion watermarks
dominate stale Relay checkpoints. Integration is gated on conformance, isolation,
capability rotation, echo-loop prevention, and independent action-authorization tests.

See `docs/AGENT_RELAY_INTEGRATION.md` for the complete future contract.

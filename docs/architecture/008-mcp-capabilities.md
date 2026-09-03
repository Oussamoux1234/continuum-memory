# ADR 008: Six scoped MCP capabilities, no administration

Status: accepted.

## Decision

The generic stdio bridge exposes exactly `memory_context`, `memory_search`, `memory_get`,
`memory_propose`, `memory_feedback`, and `memory_status`. It supports the stateless
`2026-07-28` envelope and a pinned legacy initialization path for fixture compatibility.
Tool schemas are JSON Schema 2020-12-shaped objects with `additionalProperties:false` and
bounded values. The implementation independently validates unknown fields, types, enums,
lengths, and ranges.

The bridge receives project, provider, and a least-privilege capability-file path at
startup. None is accepted in tool arguments. Read methods require `read`; propose requires
`propose`. Search cards omit evidence bodies. `get` accepts only scoped opaque IDs.
Status contains no out-of-scope counts. Typed errors avoid content and unauthorized IDs.

Returned context begins with a machine-readable `historical_untrusted_data` contract and
cannot perform any external action. Generic hosts may still misuse the data; universal
host-side enforcement is impossible without host support.

# Implementation Plans

## Documents

- `ARCH1.md` - High-level architecture and module structure
- `IMPL1.md` - Cryptographic primitives (Prim module)
- `IMPL2.md` - Types and codec (Types, Codec modules)
- `IMPL3.md` - Packet construction (Construct module)
- `IMPL4.md` - Packet processing (Process module)
- `IMPL5.md` - Error handling (Error module)
- `IMPL6.md` - Route blinding (Blinding module) [optional]

## Dependency Graph

```
            ┌──────────┐
            │  IMPL1   │──────────────────┐
            │  Prim    │                  │
            └────┬─────┘                  │
                 │                        │
            ┌────┴─────┐                  │
            │  IMPL2   │                  │
            │  Types   │                  │
            │  Codec   │                  │
            └────┬─────┘                  │
                 │                        │
     ┌───────────┼───────────┬───────────┤
     │           │           │           │
┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐
│  IMPL3  │ │  IMPL4  │ │  IMPL5  │ │  IMPL6  │
│Construct│ │ Process │ │  Error  │ │Blinding │
└─────────┘ └─────────┘ └─────────┘ └─────────┘
```

## Parallelism Opportunities

**Phase 1** (can run in parallel):
- IMPL1: Cryptographic primitives
- IMPL2: Types and codec

**Phase 2** (after Phase 1, can run in parallel):
- IMPL3: Packet construction
- IMPL4: Packet processing
- IMPL5: Error handling
- IMPL6: Route blinding

## Suggested Execution

1. Start IMPL1 and IMPL2 concurrently
2. Once both complete, start IMPL3, IMPL4, IMPL5 concurrently
3. IMPL6 is optional and lower priority; can be deferred

## Testing Strategy

Each module should have:
- Unit tests against BOLT4 spec test vectors
- Property tests for round-trip serialization
- Integration tests combining modules

Final integration test: construct packet, process at each hop,
verify intermediate values match spec vectors.

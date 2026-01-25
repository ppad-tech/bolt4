# Review: IMPL5 Error Handling (94936a9)

## Status: Approved with minor suggestions

## Issues

### 1. Duplicate helpers

`Error.hs` duplicates `constantTimeEq` and `word16BE` from other modules.

**Suggestion:** Export `constantTimeEq` from Prim, `word16BE` from Codec,
and import in Error.hs.

**Files:**
- `Prim.hs`: export `constantTimeEq`
- `Codec.hs`: export `word16BE`
- `Error.hs`: remove local definitions, import from above

**Priority:** Low (cosmetic, reduces maintenance burden)

### 2. Consider verifyHmac reuse

`verifyErrorHmac` in Error.hs computes HMAC and does constant-time
comparison. Could potentially reuse `computeHmac` and `verifyHmac` from
Prim, though the signature differs slightly (um key vs mu key usage).

**Priority:** Low (current implementation is clear and correct)

## No blocking issues

# Review: IMPL1 Cryptographic Primitives (6f3327f)

## Status: Approved with minor suggestions

## Issues

### 1. Manual modular arithmetic in blindSecKey

`Prim.hs:161-176`

`blindSecKey` manually converts to Integer, multiplies, reduces mod q,
and converts back. This works but is verbose and potentially slower than
using secp256k1's native operations.

**Suggestion:** Check if `ppad-secp256k1` exposes `mul_secret` or similar
for scalar multiplication mod curve order. If so, use it.

**Priority:** Low (correctness is fine, micro-optimization)

### 2. Duplicate helper could be consolidated

`constantTimeEq` is defined here but also duplicated in Error.hs.
Consider exporting from Prim to avoid duplication.

**Priority:** Low (cosmetic)

## No blocking issues

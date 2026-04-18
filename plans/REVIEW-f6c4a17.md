# Review: IMPL6 Route Blinding (f6c4a17)

## Status: Needs fix for key derivation

## Critical Issue

### 1. Wrong key-type in deriveBlindingRho

**File:** `Blinding.hs:113`

Current:
```haskell
deriveBlindingRho (SharedSecret !ss) =
  let SHA256.MAC !result = SHA256.hmac "blinded_node_id" ss
  in  DerivedKey result
```

Per BOLT4 spec, the rho key for encrypting blinded hop data should use
`"rho"` as the HMAC key, not `"blinded_node_id"`. The `"blinded_node_id"`
key-type is only for deriving the blinded node ID scalar.

**Fix:**
```haskell
deriveBlindingRho (SharedSecret !ss) =
  let SHA256.MAC !result = SHA256.hmac "rho" ss
  in  DerivedKey result
```

**Priority:** High - affects interoperability with other implementations

## Minor Issues

### 2. Duplicate helper functions

`Blinding.hs` duplicates these from `Codec.hs`:
- `word16BE`, `word32BE`
- `encodeWord64TU`, `decodeWord64TU`
- `encodeWord32TU`, `decodeWord32TU`
- `toStrict`

**Suggestion:** Export from Codec, import in Blinding.

**Priority:** Low (cosmetic)

### 3. Silent empty return on encrypt error

**File:** `Blinding.hs:173`

```haskell
case AEAD.encrypt BS.empty rho nonce plaintext of
  Left _ -> BS.empty  -- Should not happen with valid key
  Right (!ciphertext, !mac) -> ciphertext <> mac
```

Returning empty ByteString masks potential bugs.

**Suggestion:** Either return `Maybe BS.ByteString` or use `error` with
clear message for truly impossible cases (if key is always 32 bytes).

**Priority:** Low (defensive)

### 4. Manual modular arithmetic in mulSecKey

Same pattern as Prim.hs - manual Integer arithmetic for scalar
multiplication mod q. Works correctly but could potentially use
secp256k1 primitives.

**Priority:** Low (micro-optimization)

## Test Coverage

Tests are comprehensive:
- TLV encoding/decoding roundtrips
- Encryption/decryption roundtrips
- Path creation with 2-3 hops
- Chain processing through multiple hops
- Error cases (empty path, invalid seed, wrong key)
- `next_path_key_override` handling
- Determinism checks

## Summary

Fix the `deriveBlindingRho` key-type from `"blinded_node_id"` to `"rho"`.
Other issues are low priority.

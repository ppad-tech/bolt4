# IMPL1: Cryptographic Primitives

**Module**: `Lightning.Protocol.BOLT4.Prim`

**Dependencies**: ppad-secp256k1, ppad-sha256, ppad-hmac-sha256, ppad-chacha

**Can run in parallel with**: IMPL2 (Types/Codec)

## Overview

Implement the low-level cryptographic operations used throughout BOLT4.

## Types

```haskell
-- | 32-byte shared secret derived from ECDH.
newtype SharedSecret = SharedSecret BS.ByteString

-- | 32-byte derived key (rho, mu, um, pad, ammag).
newtype DerivedKey = DerivedKey BS.ByteString

-- | 32-byte blinding factor for ephemeral key updates.
newtype BlindingFactor = BlindingFactor BS.ByteString
```

## Functions to Implement

### Key Derivation

Derive keys from shared secret using HMAC-SHA256 with key-type prefix:

```haskell
-- | Derive rho key for obfuscation stream generation.
-- rho = HMAC-SHA256(key="rho" (0x72686f), data=shared_secret)
deriveRho :: SharedSecret -> DerivedKey

-- | Derive mu key for HMAC computation.
-- mu = HMAC-SHA256(key="mu" (0x6d75), data=shared_secret)
deriveMu :: SharedSecret -> DerivedKey

-- | Derive um key for return error HMAC.
-- um = HMAC-SHA256(key="um" (0x756d), data=shared_secret)
deriveUm :: SharedSecret -> DerivedKey

-- | Derive pad key for filler generation.
-- pad = HMAC-SHA256(key="pad" (0x706164), data=shared_secret)
derivePad :: SharedSecret -> DerivedKey

-- | Derive ammag key for error obfuscation.
-- ammag = HMAC-SHA256(key="ammag" (0x616d6d6167), data=shared_secret)
deriveAmmag :: SharedSecret -> DerivedKey
```

### Shared Secret Computation

```haskell
-- | Compute shared secret from ECDH.
-- shared_secret = SHA256(ECDH(priv, pub))
-- where ECDH result is serialized as compressed point (33 bytes).
computeSharedSecret
  :: Secp256k1.SecKey  -- ^ private key
  -> Secp256k1.PubKey  -- ^ public key
  -> SharedSecret
```

### Blinding Factor

```haskell
-- | Compute blinding factor for ephemeral key updates.
-- blinding_factor = SHA256(ephemeral_pubkey || shared_secret)
computeBlindingFactor
  :: Secp256k1.PubKey  -- ^ ephemeral public key (33 bytes compressed)
  -> SharedSecret
  -> BlindingFactor
```

### Ephemeral Key Blinding

```haskell
-- | Blind a public key by multiplying with blinding factor.
-- new_pubkey = pubkey * blinding_factor
blindPubKey
  :: Secp256k1.PubKey
  -> BlindingFactor
  -> Maybe Secp256k1.PubKey

-- | Blind a private key by multiplying with blinding factor.
-- new_seckey = seckey * blinding_factor
blindSecKey
  :: Secp256k1.SecKey
  -> BlindingFactor
  -> Maybe Secp256k1.SecKey
```

### Pseudo-Random Stream

```haskell
-- | Generate pseudo-random byte stream using ChaCha20.
-- Uses derived key as ChaCha20 key, 96-bit zero nonce, counter=0.
-- Encrypts zeros to produce keystream.
generateStream
  :: DerivedKey  -- ^ rho or ammag key
  -> Int         -- ^ desired length
  -> BS.ByteString
```

### HMAC Operations

```haskell
-- | Compute HMAC-SHA256 for packet integrity.
computeHmac
  :: DerivedKey      -- ^ mu key
  -> BS.ByteString   -- ^ hop_payloads
  -> BS.ByteString   -- ^ associated_data
  -> BS.ByteString   -- ^ 32-byte HMAC

-- | Constant-time HMAC comparison.
verifyHmac
  :: BS.ByteString  -- ^ expected
  -> BS.ByteString  -- ^ computed
  -> Bool
```

## Implementation Notes

1. The key-type strings are ASCII: "rho", "mu", "um", "pad", "ammag".
   These become the HMAC key, shared secret is the message.

2. For ECDH, use `Secp256k1.ecdh` if available, otherwise multiply
   the public key by the private key and serialize compressed.

3. Blinding factor is used as a scalar for EC multiplication. Parse it
   as a secret key (mod curve order) then use tweak operations.

4. ChaCha20 zero nonce: `BS.replicate 12 0`.

5. All operations should be strict to avoid space leaks.

## Test Vectors

From BOLT4 spec, using session key 0x4141...41 (32 bytes of 0x41):

```
hop 0 pubkey: 02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
hop 0 shared secret: 53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66
hop 0 blinding factor: 2ec2e5da605776054187180343287683aa6a51b4...
```

Verify shared secret and blinding factor computations match spec.

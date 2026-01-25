# IMPL3: Packet Construction

**Module**: `Lightning.Protocol.BOLT4.Construct`

**Dependencies**: IMPL1 (Prim), IMPL2 (Types, Codec)

**Can run in parallel with**: IMPL4, IMPL5 (after IMPL1 and IMPL2 complete)

## Overview

Implement onion packet construction from the sender's perspective.

## Types

```haskell
-- | Route information for a single hop.
data Hop = Hop
  { hopPubKey  :: !Secp256k1.PubKey  -- node's public key
  , hopPayload :: !HopPayload        -- routing data for this hop
  } deriving (Eq, Show)

-- | Session state accumulated during packet construction.
data SessionState = SessionState
  { ssEphemeralSec    :: !Secp256k1.SecKey    -- current ephemeral private
  , ssEphemeralPub    :: !Secp256k1.PubKey    -- current ephemeral public
  , ssSharedSecrets   :: ![SharedSecret]      -- accumulated secrets (reverse)
  , ssBlindingFactors :: ![BlindingFactor]    -- accumulated factors (reverse)
  } deriving (Eq, Show)
```

## Main Functions

### Packet Construction

```haskell
-- | Construct an onion packet for a payment route.
--
-- Takes a session key (32 bytes random), list of hops, and optional
-- associated data (typically payment_hash).
--
-- Returns the onion packet and list of shared secrets (for error
-- attribution).
construct
  :: BS.ByteString       -- ^ 32-byte session key (random)
  -> [Hop]               -- ^ route (first hop to final destination)
  -> BS.ByteString       -- ^ associated data
  -> Either Error (OnionPacket, [SharedSecret])

-- | Errors during packet construction.
data Error
  = InvalidSessionKey
  | EmptyRoute
  | TooManyHops         -- > 20 hops typically
  | PayloadTooLarge Int -- payload exceeds available space
  | InvalidHopPubKey Int
  deriving (Eq, Show)
```

## Internal Functions

### Session Initialization

```haskell
-- | Initialize session state from session key.
-- Derives initial ephemeral keypair.
initSession
  :: BS.ByteString  -- ^ 32-byte session key
  -> Maybe SessionState

-- | Compute shared secrets and blinding factors for entire route.
-- Iterates through hops, computing ECDH and blinding at each step.
computeSessionData
  :: SessionState
  -> [Secp256k1.PubKey]  -- ^ hop public keys
  -> Maybe SessionState  -- ^ with all secrets/factors populated
```

### Filler Generation

```haskell
-- | Generate filler bytes that compensate for per-hop shifts.
--
-- As each intermediate node shifts the payload left, the filler
-- ensures the packet maintains constant size without leaking
-- information about route position.
generateFiller
  :: [SharedSecret]  -- ^ shared secrets (excluding final hop)
  -> [Int]           -- ^ payload sizes per hop (excluding final)
  -> BS.ByteString   -- ^ filler bytes
```

Algorithm:
1. Start with empty filler
2. For each hop (forward order, excluding final):
   - Extend filler by hop's payload size (zeros)
   - Generate rho stream of length (filler size)
   - XOR filler with stream
3. Result is filler that will "appear" after final hop processes

### Payload Wrapping

```haskell
-- | Wrap a single hop's payload into the onion.
--
-- Called in reverse order (final hop first, origin last).
wrapHop
  :: SharedSecret    -- ^ shared secret for this hop
  -> BS.ByteString   -- ^ serialized payload (without length prefix)
  -> BS.ByteString   -- ^ current HMAC (32 bytes)
  -> BS.ByteString   -- ^ current hop_payloads (1300 bytes)
  -> BS.ByteString   -- ^ associated data
  -> (BS.ByteString, BS.ByteString)  -- ^ (new hop_payloads, new HMAC)
```

Algorithm:
1. Compute shift_size = bigsize_len(payload_len) + payload_len + 32
2. Right-shift hop_payloads by shift_size (drop rightmost bytes)
3. Prepend: bigsize(payload_len) || payload || hmac
4. Generate rho stream (1300 bytes)
5. XOR entire buffer with stream
6. Compute new HMAC = HMAC-SHA256(mu_key, hop_payloads || assoc_data)

### Filler Application

```haskell
-- | Apply filler to the final wrapped packet.
--
-- Overwrites the tail of hop_payloads with filler bytes.
-- This must be done after wrapping all hops but before
-- computing the final HMAC.
applyFiller
  :: BS.ByteString  -- ^ hop_payloads (1300 bytes)
  -> BS.ByteString  -- ^ filler
  -> BS.ByteString  -- ^ hop_payloads with filler applied
```

## Construction Algorithm

Full algorithm as pseudocode:

```
construct(session_key, hops, assoc_data):
  1. session = initSession(session_key)
  2. session = computeSessionData(session, map hopPubKey hops)

  3. Extract from session:
     - ephemeral_pub (for first hop)
     - shared_secrets[0..n-1]

  4. Compute payload sizes for each hop
  5. filler = generateFiller(shared_secrets[0..n-2], sizes[0..n-2])

  6. Initialize:
     - hop_payloads = random 1300 bytes (using pad key from last secret)
     - hmac = 32 zero bytes (final hop sees zeros)

  7. For i = n-1 down to 0:
     payload_bytes = encodeHopPayload(hops[i].payload)
     (hop_payloads, hmac) = wrapHop(
       shared_secrets[i], payload_bytes, hmac, hop_payloads, assoc_data
     )

     if i == n-1:
       hop_payloads = applyFiller(hop_payloads, filler)
       hmac = recompute HMAC after filler

  8. packet = OnionPacket {
       version = 0x00,
       ephemeral = ephemeral_pub,
       hop_payloads = hop_payloads,
       hmac = hmac
     }

  9. return (packet, shared_secrets)
```

## Implementation Notes

1. The session key should come from a CSPRNG. This module assumes it's
   provided externally (no IO).

2. Shared secrets are returned for error attribution - the sender needs
   them to unwrap error messages.

3. Filler generation is subtle. Test against spec vectors carefully.

4. The "random" initial hop_payloads should be deterministic from the
   pad key (derived from final hop's shared secret) for reproducibility.

5. Payload size validation: ensure total doesn't exceed 1300 bytes
   accounting for all length prefixes and HMACs.

## Test Vectors

From BOLT4 spec with session key 0x4141...41:

```
Hop 0: pubkey 02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
       payload (hex): ...

Final packet ephemeral key: 02...
Final packet hop_payloads (hex): ...
Final packet HMAC (hex): ...
```

Verify intermediate values (shared secrets, blinding factors) and
final packet bytes match spec exactly.

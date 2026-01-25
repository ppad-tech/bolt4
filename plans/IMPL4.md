# IMPL4: Packet Processing

**Module**: `Lightning.Protocol.BOLT4.Process`

**Dependencies**: IMPL1 (Prim), IMPL2 (Types, Codec)

**Can run in parallel with**: IMPL3, IMPL5 (after IMPL1 and IMPL2 complete)

## Overview

Implement onion packet processing from the receiver's perspective
(both intermediate nodes and final destination).

## Types

```haskell
-- | Result of processing an incoming onion packet.
data ProcessResult
  = Forward !ForwardData   -- ^ Intermediate node: forward to next hop
  | Receive !ReceiveData   -- ^ Final node: payment reached destination
  | Reject !RejectReason   -- ^ Invalid packet
  deriving (Eq, Show)

-- | Data for forwarding to next hop.
data ForwardData = ForwardData
  { fdNextPacket   :: !OnionPacket   -- ^ Packet for next node
  , fdPayload      :: !HopPayload    -- ^ Routing instructions
  , fdSharedSecret :: !SharedSecret  -- ^ For error wrapping
  } deriving (Eq, Show)

-- | Data when packet reaches final destination.
data ReceiveData = ReceiveData
  { rdPayload      :: !HopPayload    -- ^ Payment data
  , rdSharedSecret :: !SharedSecret  -- ^ For error wrapping
  } deriving (Eq, Show)

-- | Reasons for rejecting a packet.
data RejectReason
  = InvalidVersion !Word8          -- ^ Version != 0x00
  | InvalidEphemeralKey            -- ^ Malformed public key
  | HmacMismatch                   -- ^ HMAC verification failed
  | InvalidPayload !String         -- ^ Malformed payload
  deriving (Eq, Show)
```

## Main Function

```haskell
-- | Process an incoming onion packet.
--
-- Takes the node's private key, the incoming packet, and associated
-- data (typically payment_hash).
process
  :: Secp256k1.SecKey  -- ^ this node's private key
  -> OnionPacket       -- ^ incoming packet
  -> BS.ByteString     -- ^ associated data
  -> ProcessResult
```

## Internal Functions

### Validation

```haskell
-- | Validate packet version.
validateVersion :: OnionPacket -> Either RejectReason ()

-- | Parse and validate ephemeral public key.
parseEphemeralKey :: OnionPacket -> Either RejectReason Secp256k1.PubKey
```

### Decryption

```haskell
-- | Decrypt hop_payloads by XORing with rho stream.
--
-- Generates a stream of 2*1300 bytes (to handle the shift),
-- XORs with hop_payloads extended with 1300 zero bytes.
decryptPayloads
  :: DerivedKey      -- ^ rho key
  -> BS.ByteString   -- ^ hop_payloads (1300 bytes)
  -> BS.ByteString   -- ^ decrypted (2600 bytes, first 1300 useful)
```

### Payload Extraction

```haskell
-- | Extract payload from decrypted buffer.
--
-- Parses BigSize length, extracts payload bytes and next HMAC.
extractPayload
  :: BS.ByteString  -- ^ decrypted buffer
  -> Either RejectReason (HopPayload, BS.ByteString, BS.ByteString)
  -- ^ (payload, next_hmac, remaining_hop_payloads)
```

### HMAC Verification

```haskell
-- | Verify packet HMAC.
--
-- Computes HMAC over (hop_payloads || associated_data) using mu key.
-- Returns True if constant-time equal to packet's HMAC.
verifyPacketHmac
  :: DerivedKey      -- ^ mu key
  -> OnionPacket     -- ^ packet with HMAC to verify
  -> BS.ByteString   -- ^ associated data
  -> Bool
```

### Forwarding Preparation

```haskell
-- | Prepare packet for forwarding to next hop.
--
-- Computes blinded ephemeral key, constructs next OnionPacket.
prepareForward
  :: Secp256k1.PubKey  -- ^ current ephemeral key
  -> SharedSecret      -- ^ shared secret (for blinding)
  -> BS.ByteString     -- ^ remaining hop_payloads (after shift)
  -> BS.ByteString     -- ^ next HMAC
  -> Maybe OnionPacket
```

Algorithm:
1. Compute blinding factor = SHA256(ephemeral || shared_secret)
2. Blind ephemeral key: new_ephemeral = ephemeral * blinding_factor
3. Truncate remaining_payloads to 1300 bytes (they're already shifted)
4. Construct OnionPacket with new ephemeral and next HMAC

### Final Detection

```haskell
-- | Check if this is the final hop.
--
-- Final hop is indicated by next_hmac being all zeros.
isFinalHop :: BS.ByteString -> Bool
isFinalHop hmac = hmac == BS.replicate 32 0
```

## Processing Algorithm

Full algorithm as pseudocode:

```
process(node_seckey, packet, assoc_data):
  1. Validate version == 0x00
     If not: return Reject(InvalidVersion)

  2. Parse ephemeral_pubkey from packet
     If invalid: return Reject(InvalidEphemeralKey)

  3. Compute shared_secret = computeSharedSecret(node_seckey, ephemeral_pubkey)

  4. Derive keys:
     mu = deriveMu(shared_secret)
     rho = deriveRho(shared_secret)

  5. Verify HMAC:
     expected = computeHmac(mu, packet.hop_payloads, assoc_data)
     If not verifyHmac(packet.hmac, expected):
       return Reject(HmacMismatch)

  6. Decrypt:
     decrypted = decryptPayloads(rho, packet.hop_payloads)

  7. Extract payload:
     (payload, next_hmac, remaining) = extractPayload(decrypted)
     If error: return Reject(InvalidPayload)

  8. Parse payload TLV:
     hop_payload = decodeHopPayload(payload)
     If error: return Reject(InvalidPayload)

  9. Check if final:
     If isFinalHop(next_hmac):
       return Receive(ReceiveData {
         payload = hop_payload,
         shared_secret = shared_secret
       })

  10. Prepare forward packet:
      next_packet = prepareForward(ephemeral_pubkey, shared_secret,
                                   remaining, next_hmac)
      If error: return Reject(InvalidEphemeralKey)

  11. return Forward(ForwardData {
        next_packet = next_packet,
        payload = hop_payload,
        shared_secret = shared_secret
      })
```

## Implementation Notes

1. HMAC verification MUST be constant-time to prevent timing attacks.

2. The decryption extends hop_payloads with zeros because after XOR,
   the "shifted in" portion will contain the next layer's data.

3. After extracting the payload, the remaining buffer is already
   positioned for the next hop (left-shifted by payload size).

4. Shared secret is returned for error message construction - if the
   node needs to report a failure, it uses this to wrap the error.

5. The blinding operation on ephemeral key ensures each hop sees a
   different ephemeral key, unlinkable to previous hops.

## Test Vectors

Using the spec's test route, verify that processing at each hop:
- Produces correct shared secret
- Extracts correct payload
- Generates correct next ephemeral key
- Correctly identifies final hop

Process packet at node 0, verify forward packet matches node 1's view.
Process at node 4 (final), verify Receive result.

# IMPL5: Error Handling

**Module**: `Lightning.Protocol.BOLT4.Error`

**Dependencies**: IMPL1 (Prim), IMPL2 (Types, Codec)

**Can run in parallel with**: IMPL3, IMPL4 (after IMPL1 and IMPL2 complete)

## Overview

Implement failure message construction (by failing node) and
unwrapping/attribution (by origin node).

## Types

```haskell
-- | Wrapped error packet ready for return to origin.
newtype ErrorPacket = ErrorPacket BS.ByteString
  deriving (Eq, Show)

-- | Result of error attribution.
data AttributionResult
  = Attributed !Int !FailureMessage  -- ^ (hop index, failure)
  | UnknownOrigin !BS.ByteString     -- ^ Could not attribute
  deriving (Eq, Show)

-- | Minimum error packet size (256 bytes per spec).
minErrorPacketSize :: Int
minErrorPacketSize = 256
```

## Error Construction (Failing Node)

```haskell
-- | Construct an error packet at a failing node.
--
-- Takes the shared secret (from processing), failure message,
-- and wraps it for return to origin.
constructError
  :: SharedSecret      -- ^ from packet processing
  -> FailureMessage    -- ^ failure details
  -> ErrorPacket

-- | Wrap an existing error packet for forwarding back.
--
-- Each intermediate node wraps the error with its own layer.
wrapError
  :: SharedSecret      -- ^ this node's shared secret
  -> ErrorPacket       -- ^ error from downstream
  -> ErrorPacket
```

## Error Unwrapping (Origin Node)

```haskell
-- | Attempt to attribute an error to a specific hop.
--
-- Takes the shared secrets from original packet construction
-- (in order from first hop to final) and the error packet.
--
-- Tries each hop's keys until HMAC verifies, revealing origin.
unwrapError
  :: [SharedSecret]    -- ^ secrets from construction, in route order
  -> ErrorPacket       -- ^ received error
  -> AttributionResult
```

## Internal Functions

### Error Packet Construction

```haskell
-- | Build the inner error message structure.
--
-- Format: HMAC (32) || len (2) || message || pad_len (2) || padding
-- Total must be >= 256 bytes.
buildErrorMessage
  :: DerivedKey        -- ^ um key
  -> FailureMessage    -- ^ failure to encode
  -> BS.ByteString     -- ^ complete message with HMAC
```

Algorithm:
1. Encode failure message to bytes
2. Compute padding needed: max(0, 256 - 32 - 2 - msg_len - 2)
3. Build: len (u16 BE) || message || pad_len (u16 BE) || padding
4. Compute HMAC = HMAC-SHA256(um_key, len || message || pad_len || padding)
5. Return: HMAC || len || message || pad_len || padding

### Error Obfuscation

```haskell
-- | Obfuscate error packet with ammag stream.
--
-- XORs the entire packet (after HMAC) with pseudo-random stream.
obfuscateError
  :: DerivedKey        -- ^ ammag key
  -> BS.ByteString     -- ^ error packet
  -> BS.ByteString     -- ^ obfuscated packet
```

Note: The HMAC is computed over plaintext, then the entire packet
including HMAC is XORed with ammag stream.

### Error Deobfuscation

```haskell
-- | Remove one layer of obfuscation from error packet.
deobfuscateError
  :: DerivedKey        -- ^ ammag key
  -> BS.ByteString     -- ^ obfuscated packet
  -> BS.ByteString     -- ^ deobfuscated packet

-- | Verify error HMAC after deobfuscation.
verifyErrorHmac
  :: DerivedKey        -- ^ um key
  -> BS.ByteString     -- ^ deobfuscated packet (HMAC || rest)
  -> Bool
```

### Error Parsing

```haskell
-- | Parse error message from deobfuscated packet.
parseErrorMessage
  :: BS.ByteString     -- ^ packet after HMAC verification
  -> Maybe FailureMessage
```

## Construction Algorithm

At failing node:

```
constructError(shared_secret, failure):
  1. um = deriveUm(shared_secret)
  2. ammag = deriveAmmag(shared_secret)
  3. inner = buildErrorMessage(um, failure)
  4. obfuscated = obfuscateError(ammag, inner)
  5. return ErrorPacket(obfuscated)
```

At forwarding node (wrapping existing error):

```
wrapError(shared_secret, error_packet):
  1. ammag = deriveAmmag(shared_secret)
  2. wrapped = obfuscateError(ammag, error_packet)
  3. return ErrorPacket(wrapped)
```

## Unwrapping Algorithm

At origin node:

```
unwrapError(shared_secrets, error_packet):
  packet = error_packet.bytes

  for i = 0 to len(shared_secrets) - 1:
    ammag = deriveAmmag(shared_secrets[i])
    um = deriveUm(shared_secrets[i])

    packet = deobfuscateError(ammag, packet)

    if verifyErrorHmac(um, packet):
      failure = parseErrorMessage(packet[32:])
      return Attributed(i, failure)

  return UnknownOrigin(packet)
```

The first hop whose HMAC verifies is the origin of the error.

## Failure Codes

Common failure codes to handle (define in Types, use here):

```haskell
-- Flags
badonion, perm, node, update :: Word16

-- Codes (incomplete list)
invalid_realm                      = perm .|. 1
temporary_node_failure             = node .|. 2
permanent_node_failure             = perm .|. node .|. 2
required_node_feature_missing      = perm .|. node .|. 3
invalid_onion_version              = badonion .|. perm .|. 4
invalid_onion_hmac                 = badonion .|. perm .|. 5
invalid_onion_key                  = badonion .|. perm .|. 6
temporary_channel_failure          = update .|. 7
permanent_channel_failure          = perm .|. 8
amount_below_minimum               = update .|. 11
fee_insufficient                   = update .|. 12
incorrect_cltv_expiry              = update .|. 13
expiry_too_soon                    = update .|. 14
incorrect_or_unknown_payment_details = perm .|. 15
final_incorrect_cltv_expiry        = 18
final_incorrect_htlc_amount        = 19
channel_disabled                   = update .|. 20
expiry_too_far                     = 21
invalid_onion_payload              = perm .|. 22
mpp_timeout                        = 23
```

## Implementation Notes

1. Error packets are always at least 256 bytes to prevent length-based
   traffic analysis.

2. Each intermediate node adds a layer of encryption (XOR with ammag
   stream). Origin peels layers in route order.

3. HMAC verification at origin: only the actual failing node's HMAC
   will verify after exactly the right number of layers are removed.

4. The BADONION flag indicates the error relates to the onion itself
   (HMAC failure, bad key). These get special treatment.

5. UPDATE flag means the error includes a channel_update message that
   the origin should process.

## Test Vectors

From spec, with failure at node 4:

```
failure code: incorrect_or_unknown_payment_details (0x400f)
htlc_msat: 100
height: 800000
```

Verify:
- Error packet construction produces correct bytes
- Wrapping at each intermediate node matches spec
- Unwrapping at origin correctly attributes to node 4
- Parsed failure message matches original

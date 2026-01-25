# IMPL2: Types and Codec

**Module**: `Lightning.Protocol.BOLT4.Types`, `Lightning.Protocol.BOLT4.Codec`

**Dependencies**: base, bytestring

**Can run in parallel with**: IMPL1 (Primitives)

## Overview

Define core data types and serialization (BigSize, TLV, packets).

## Types Module

### Packet Types

```haskell
-- | Complete onion packet (1366 bytes).
data OnionPacket = OnionPacket
  { opVersion      :: {-# UNPACK #-} !Word8
  , opEphemeralKey :: !BS.ByteString  -- 33 bytes, compressed pubkey
  , opHopPayloads  :: !BS.ByteString  -- 1300 bytes
  , opHmac         :: !BS.ByteString  -- 32 bytes
  } deriving (Eq, Show)

-- | Parsed hop payload after decryption.
data HopPayload = HopPayload
  { hpAmtToForward   :: !(Maybe Word64)       -- TLV type 2
  , hpOutgoingCltv   :: !(Maybe Word32)       -- TLV type 4
  , hpShortChannelId :: !(Maybe ShortChannelId) -- TLV type 6
  , hpPaymentData    :: !(Maybe PaymentData)  -- TLV type 8
  , hpEncryptedData  :: !(Maybe BS.ByteString) -- TLV type 10
  , hpCurrentPathKey :: !(Maybe BS.ByteString) -- TLV type 12
  , hpUnknownTlvs    :: ![TlvRecord]          -- unknown types
  } deriving (Eq, Show)

-- | Short channel ID (8 bytes): block height, tx index, output index.
data ShortChannelId = ShortChannelId
  { sciBlockHeight :: {-# UNPACK #-} !Word32  -- 3 bytes in encoding
  , sciTxIndex     :: {-# UNPACK #-} !Word32  -- 3 bytes in encoding
  , sciOutputIndex :: {-# UNPACK #-} !Word16  -- 2 bytes in encoding
  } deriving (Eq, Show)

-- | Payment data for final hop (TLV type 8).
data PaymentData = PaymentData
  { pdPaymentSecret :: !BS.ByteString  -- 32 bytes
  , pdTotalMsat     :: {-# UNPACK #-} !Word64
  } deriving (Eq, Show)

-- | Generic TLV record for unknown/extension types.
data TlvRecord = TlvRecord
  { tlvType  :: {-# UNPACK #-} !Word64
  , tlvValue :: !BS.ByteString
  } deriving (Eq, Show)
```

### Error Types

```haskell
-- | Failure message from intermediate or final node.
data FailureMessage = FailureMessage
  { fmCode :: {-# UNPACK #-} !FailureCode
  , fmData :: !BS.ByteString
  , fmTlvs :: ![TlvRecord]
  } deriving (Eq, Show)

-- | 2-byte failure code with flag bits.
newtype FailureCode = FailureCode Word16
  deriving (Eq, Show)

-- Flag bits
pattern BADONION :: Word16
pattern BADONION = 0x8000

pattern PERM :: Word16
pattern PERM = 0x4000

pattern NODE :: Word16
pattern NODE = 0x2000

pattern UPDATE :: Word16
pattern UPDATE = 0x1000

-- Common failure codes (not exhaustive)
pattern InvalidRealm :: FailureCode
pattern InvalidRealm = FailureCode (PERM .|. 1)

pattern TemporaryNodeFailure :: FailureCode
pattern TemporaryNodeFailure = FailureCode (NODE .|. 2)

pattern PermanentNodeFailure :: FailureCode
pattern PermanentNodeFailure = FailureCode (PERM .|. NODE .|. 2)

pattern InvalidOnionHmac :: FailureCode
pattern InvalidOnionHmac = FailureCode (BADONION .|. PERM .|. 5)

pattern InvalidOnionKey :: FailureCode
pattern InvalidOnionKey = FailureCode (BADONION .|. PERM .|. 6)

pattern TemporaryChannelFailure :: FailureCode
pattern TemporaryChannelFailure = FailureCode (UPDATE .|. 7)

pattern IncorrectOrUnknownPaymentDetails :: FailureCode
pattern IncorrectOrUnknownPaymentDetails = FailureCode (PERM .|. 15)
```

### Processing Results

```haskell
-- | Result of processing an onion packet.
data ProcessResult
  = Forward !ForwardInfo   -- ^ Forward to next hop
  | Receive !ReceiveInfo   -- ^ Final destination reached
  deriving (Eq, Show)

data ForwardInfo = ForwardInfo
  { fiNextPacket    :: !OnionPacket
  , fiPayload       :: !HopPayload
  , fiSharedSecret  :: !BS.ByteString  -- for error attribution
  } deriving (Eq, Show)

data ReceiveInfo = ReceiveInfo
  { riPayload      :: !HopPayload
  , riSharedSecret :: !BS.ByteString
  } deriving (Eq, Show)
```

### Constants

```haskell
onionPacketSize :: Int
onionPacketSize = 1366

hopPayloadsSize :: Int
hopPayloadsSize = 1300

hmacSize :: Int
hmacSize = 32

pubkeySize :: Int
pubkeySize = 33

versionByte :: Word8
versionByte = 0x00

maxPayloadSize :: Int
maxPayloadSize = 1300 - 32 - 1  -- minus HMAC and min length byte
```

## Codec Module

### BigSize Encoding

Variable-length integer encoding per BOLT1:

```haskell
-- | Encode integer as BigSize.
-- 0-0xFC: 1 byte
-- 0xFD-0xFFFF: 0xFD ++ 2 bytes BE
-- 0x10000-0xFFFFFFFF: 0xFE ++ 4 bytes BE
-- larger: 0xFF ++ 8 bytes BE
encodeBigSize :: Word64 -> BS.ByteString

-- | Decode BigSize, returning (value, remaining bytes).
decodeBigSize :: BS.ByteString -> Maybe (Word64, BS.ByteString)

-- | Get encoded size of a BigSize value without encoding.
bigSizeLen :: Word64 -> Int
```

### TLV Encoding

```haskell
-- | Encode a TLV record.
encodeTlv :: TlvRecord -> BS.ByteString

-- | Decode a single TLV record.
decodeTlv :: BS.ByteString -> Maybe (TlvRecord, BS.ByteString)

-- | Decode a TLV stream (sequence of records).
decodeTlvStream :: BS.ByteString -> Maybe [TlvRecord]

-- | Encode a TLV stream from records.
-- Records must be sorted by type, no duplicates.
encodeTlvStream :: [TlvRecord] -> BS.ByteString
```

### Packet Serialization

```haskell
-- | Serialize OnionPacket to 1366 bytes.
encodeOnionPacket :: OnionPacket -> BS.ByteString

-- | Parse OnionPacket from 1366 bytes.
decodeOnionPacket :: BS.ByteString -> Maybe OnionPacket

-- | Encode HopPayload to bytes (without length prefix).
encodeHopPayload :: HopPayload -> BS.ByteString

-- | Decode HopPayload from bytes.
decodeHopPayload :: BS.ByteString -> Maybe HopPayload
```

### ShortChannelId

```haskell
-- | Encode ShortChannelId to 8 bytes.
-- Format: 3 bytes block || 3 bytes tx || 2 bytes output (all BE)
encodeShortChannelId :: ShortChannelId -> BS.ByteString

-- | Decode ShortChannelId from 8 bytes.
decodeShortChannelId :: BS.ByteString -> Maybe ShortChannelId
```

### Failure Message

```haskell
-- | Encode failure message.
encodeFailureMessage :: FailureMessage -> BS.ByteString

-- | Decode failure message.
decodeFailureMessage :: BS.ByteString -> Maybe FailureMessage
```

## Implementation Notes

1. BigSize is the same as BOLT1's variable-length integer encoding.
   Consider importing from ppad-bolt1 if compatible.

2. TLV types must be encoded in strictly increasing order. The decoder
   should reject streams with out-of-order or duplicate types.

3. ShortChannelId packs 3+3+2 bytes into 8 bytes total. Use bit shifting.

4. HopPayload decoding: parse TLV stream, then extract known types
   into structured fields. Unknown types go into `hpUnknownTlvs`.

5. All decoders return Maybe to handle malformed input gracefully.

6. Use Builder for efficient encoding, strict ByteString for results.

## Test Cases

1. BigSize round-trip for boundary values: 0, 0xFC, 0xFD, 0xFFFF,
   0x10000, 0xFFFFFFFF, 0x100000000.

2. TLV stream with multiple records, verify ordering enforcement.

3. ShortChannelId encode/decode with known values.

4. OnionPacket round-trip (construct, serialize, deserialize, compare).

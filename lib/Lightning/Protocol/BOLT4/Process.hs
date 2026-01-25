{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module: Lightning.Protocol.BOLT4.Process
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Onion packet processing for BOLT4.

module Lightning.Protocol.BOLT4.Process (
    -- * Processing
    process

    -- * Rejection reasons
  , RejectReason(..)
  ) where

import Data.Bits (xor)
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import qualified Data.ByteString as BS
import Data.Word (Word8)
import GHC.Generics (Generic)
import Lightning.Protocol.BOLT4.Codec
import Lightning.Protocol.BOLT4.Prim
import Lightning.Protocol.BOLT4.Types

-- | Reasons for rejecting a packet.
data RejectReason
  = InvalidVersion !Word8       -- ^ Version byte is not 0x00
  | InvalidEphemeralKey         -- ^ Malformed public key
  | HmacMismatch                -- ^ HMAC verification failed
  | InvalidPayload !String      -- ^ Malformed hop payload
  deriving (Eq, Show, Generic)

-- | Process an incoming onion packet.
--
-- Takes the receiving node's private key, the incoming packet, and
-- associated data (typically the payment hash).
--
-- Returns either a rejection reason or the processing result
-- (forward to next hop or receive at final destination).
process
  :: BS.ByteString    -- ^ 32-byte secret key of this node
  -> OnionPacket      -- ^ incoming onion packet
  -> BS.ByteString    -- ^ associated data (payment hash)
  -> Either RejectReason ProcessResult
process !secKey !packet !assocData = do
  -- Step 1: Validate version
  validateVersion packet

  -- Step 2: Parse ephemeral public key
  ephemeral <- parseEphemeralKey packet

  -- Step 3: Compute shared secret
  ss <- case computeSharedSecret secKey ephemeral of
    Nothing -> Left InvalidEphemeralKey
    Just s  -> Right s

  -- Step 4: Derive keys
  let !muKey = deriveMu ss
      !rhoKey = deriveRho ss

  -- Step 5: Verify HMAC
  if not (verifyPacketHmac muKey packet assocData)
    then Left HmacMismatch
    else pure ()

  -- Step 6: Decrypt hop payloads
  let !decrypted = decryptPayloads rhoKey (opHopPayloads packet)

  -- Step 7: Extract payload
  (payloadBytes, nextHmac, remaining) <- extractPayload decrypted

  -- Step 8: Parse payload TLV
  hopPayload <- case decodeHopPayload payloadBytes of
    Nothing -> Left (InvalidPayload "failed to decode TLV")
    Just hp -> Right hp

  -- Step 9: Check if final hop
  let SharedSecret ssBytes = ss
  if isFinalHop nextHmac
    then Right $! Receive $! ReceiveInfo
      { riPayload = hopPayload
      , riSharedSecret = ssBytes
      }
    else do
      -- Step 10: Prepare forward packet
      nextPacket <- case prepareForward ephemeral ss remaining nextHmac of
        Nothing -> Left InvalidEphemeralKey
        Just np -> Right np

      Right $! Forward $! ForwardInfo
        { fiNextPacket = nextPacket
        , fiPayload = hopPayload
        , fiSharedSecret = ssBytes
        }

-- | Validate packet version is 0x00.
validateVersion :: OnionPacket -> Either RejectReason ()
validateVersion !packet
  | opVersion packet == versionByte = Right ()
  | otherwise = Left (InvalidVersion (opVersion packet))
{-# INLINE validateVersion #-}

-- | Parse and validate ephemeral public key from packet.
parseEphemeralKey :: OnionPacket -> Either RejectReason Secp256k1.Projective
parseEphemeralKey !packet =
  case Secp256k1.parse_point (opEphemeralKey packet) of
    Nothing  -> Left InvalidEphemeralKey
    Just pub -> Right pub
{-# INLINE parseEphemeralKey #-}

-- | Decrypt hop payloads by XORing with rho stream.
--
-- Generates a stream of 2*1300 bytes and XORs with hop_payloads
-- extended with 1300 zero bytes.
decryptPayloads
  :: DerivedKey      -- ^ rho key
  -> BS.ByteString   -- ^ hop_payloads (1300 bytes)
  -> BS.ByteString   -- ^ decrypted (2600 bytes, first 1300 useful)
decryptPayloads !rhoKey !payloads =
  let !streamLen = 2 * hopPayloadsSize  -- 2600 bytes
      !stream = generateStream rhoKey streamLen
      -- Extend payloads with zeros for the shift operation
      !extended = payloads <> BS.replicate hopPayloadsSize 0
  in  xorBytes stream extended
{-# INLINE decryptPayloads #-}

-- | XOR two bytestrings of equal length.
xorBytes :: BS.ByteString -> BS.ByteString -> BS.ByteString
xorBytes !a !b = BS.pack (BS.zipWith xor a b)
{-# INLINE xorBytes #-}

-- | Extract payload from decrypted buffer.
--
-- Parses BigSize length prefix, extracts payload bytes and next HMAC.
extractPayload
  :: BS.ByteString
  -> Either RejectReason (BS.ByteString, BS.ByteString, BS.ByteString)
     -- ^ (payload_bytes, next_hmac, remaining_hop_payloads)
extractPayload !decrypted = do
  -- Parse length prefix
  (len, afterLen) <- case decodeBigSize decrypted of
    Nothing -> Left (InvalidPayload "invalid length prefix")
    Just (l, r) -> Right (fromIntegral l :: Int, r)

  -- Validate length
  if len > BS.length afterLen
    then Left (InvalidPayload "payload length exceeds buffer")
    else if len == 0
      then Left (InvalidPayload "zero-length payload")
      else pure ()

  -- Extract payload bytes
  let !payloadBytes = BS.take len afterLen
      !afterPayload = BS.drop len afterLen

  -- Extract next HMAC (32 bytes)
  if BS.length afterPayload < hmacSize
    then Left (InvalidPayload "insufficient bytes for HMAC")
    else do
      let !nextHmac = BS.take hmacSize afterPayload
          -- Remaining payloads: skip the HMAC, take first 1300 bytes
          -- This is already "shifted" by the payload extraction
          !remaining = BS.drop hmacSize afterPayload

      Right (payloadBytes, nextHmac, remaining)

-- | Verify packet HMAC.
--
-- Computes HMAC over (hop_payloads || associated_data) using mu key
-- and compares with packet's HMAC using constant-time comparison.
verifyPacketHmac
  :: DerivedKey      -- ^ mu key
  -> OnionPacket     -- ^ packet with HMAC to verify
  -> BS.ByteString   -- ^ associated data
  -> Bool
verifyPacketHmac !muKey !packet !assocData =
  let !computed = computeHmac muKey (opHopPayloads packet) assocData
  in  verifyHmac (opHmac packet) computed
{-# INLINE verifyPacketHmac #-}

-- | Prepare packet for forwarding to next hop.
--
-- Computes blinded ephemeral key and constructs next OnionPacket.
prepareForward
  :: Secp256k1.Projective  -- ^ current ephemeral key
  -> SharedSecret          -- ^ shared secret (for blinding)
  -> BS.ByteString         -- ^ remaining hop_payloads (after shift)
  -> BS.ByteString         -- ^ next HMAC
  -> Maybe OnionPacket
prepareForward !ephemeral !ss !remaining !nextHmac = do
  -- Compute blinding factor and blind ephemeral key
  let !bf = computeBlindingFactor ephemeral ss
  newEphemeral <- blindPubKey ephemeral bf

  -- Serialize new ephemeral key
  let !newEphBytes = Secp256k1.serialize_point newEphemeral

  -- Truncate remaining to exactly 1300 bytes
  let !newPayloads = BS.take hopPayloadsSize remaining

  -- Construct next packet
  pure $! OnionPacket
    { opVersion = versionByte
    , opEphemeralKey = newEphBytes
    , opHopPayloads = newPayloads
    , opHmac = nextHmac
    }

-- | Check if this is the final hop.
--
-- Final hop is indicated by next_hmac being all zeros.
isFinalHop :: BS.ByteString -> Bool
isFinalHop !hmac = hmac == BS.replicate hmacSize 0
{-# INLINE isFinalHop #-}

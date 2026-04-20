{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module: Lightning.Protocol.BOLT4.Construct
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Onion packet construction for BOLT4.

module Lightning.Protocol.BOLT4.Construct (
    -- * Types
    Hop(..)
  , Error(..)

    -- * Packet construction
  , construct
  ) where

import Data.Bits (xor)
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import qualified Data.ByteString as BS
import Lightning.Protocol.BOLT4.Codec
import Lightning.Protocol.BOLT4.Internal
import Lightning.Protocol.BOLT4.Prim
import Lightning.Protocol.BOLT4.Types

-- | Route information for a single hop.
data Hop = Hop
  { hopPubKey  :: !Secp256k1.Projective  -- ^ node's public key
  , hopPayload :: !HopPayload            -- ^ routing data for this hop
  } deriving (Eq, Show)

-- | Errors during packet construction.
data Error
  = InvalidSessionKey
  | EmptyRoute
  | TooManyHops
  | PayloadTooLarge !Int
  | InvalidHopPubKey !Int
  deriving (Eq, Show)

-- | Maximum number of hops in a route.
maxHops :: Int
maxHops = 20
{-# INLINE maxHops #-}

-- | Construct an onion packet for a payment route.
--
-- Takes a session key (32 bytes random), list of hops, and associated
-- data (typically payment_hash).
--
-- Returns the onion packet and list of shared secrets (for error
-- attribution).
construct
  :: BS.ByteString       -- ^ 32-byte session key (random)
  -> [Hop]               -- ^ route (first hop to final destination)
  -> BS.ByteString       -- ^ associated data
  -> Either Error (OnionPacket, [SharedSecret])
construct !sessionKey !hops !assocData
  | BS.length sessionKey /= 32 = Left InvalidSessionKey
  | null hops = Left EmptyRoute
  | length hops > maxHops = Left TooManyHops
  | otherwise = do
      -- Initialize ephemeral keypair from session key
      ephSec <- maybe (Left InvalidSessionKey) Right
                  (Secp256k1.roll32 sessionKey)
      ephPub <- maybe (Left InvalidSessionKey) Right
                  (Secp256k1.derive_pub ephSec)

      -- Compute shared secrets and blinding factors for all hops
      let hopPubKeys = map hopPubKey hops
      (secrets, _) <- computeAllSecrets sessionKey ephPub hopPubKeys

      -- Validate payload sizes
      let payloadBytes = map (encodeHopPayload . hopPayload) hops
          payloadSizes = map payloadShiftSize payloadBytes
          totalSize = sum payloadSizes
      if totalSize > hopPayloadsSize
        then Left (PayloadTooLarge totalSize)
        else do
          -- Generate filler using secrets for all but final hop
          let numHops = length hops
              secretsExceptFinal = take (numHops - 1) secrets
              sizesExceptFinal = take (numHops - 1) payloadSizes
              filler = generateFiller secretsExceptFinal sizesExceptFinal

          -- Initialize hop_payloads with deterministic padding
          let DerivedKey padKey = derivePad (SharedSecret sessionKey)
              initialPayloads = generateStream (DerivedKey padKey)
                                  hopPayloadsSize

          -- Wrap payloads in reverse order (final hop first)
          let (finalPayloads, finalHmac) = wrapAllHops
                secrets payloadBytes filler assocData initialPayloads

          -- Build the final packet
          let ephPubBytes = Secp256k1.serialize_point ephPub
              packet = OnionPacket
                { opVersion = versionByte
                , opEphemeralKey = ephPubBytes
                , opHopPayloads = unsafeHopPayloads finalPayloads
                , opHmac = unsafeHmac32 finalHmac
                }

          Right (packet, secrets)

-- | Compute the total shift size for a payload.
payloadShiftSize :: BS.ByteString -> Int
payloadShiftSize !payload =
  let !len = BS.length payload
      !bsLen = bigSizeLen (fromIntegral len)
  in  bsLen + len + hmacSize
{-# INLINE payloadShiftSize #-}

-- | Compute shared secrets for all hops.
computeAllSecrets
  :: BS.ByteString
  -> Secp256k1.Projective
  -> [Secp256k1.Projective]
  -> Either Error ([SharedSecret], Secp256k1.Projective)
computeAllSecrets !initSec !initPub = go initSec initPub 0 []
  where
    go !_ephSec !ephPub !_ !acc [] = Right (reverse acc, ephPub)
    go !ephSec !ephPub !idx !acc (hopPub:rest) = do
      ss <- maybe (Left (InvalidHopPubKey idx)) Right
              (computeSharedSecret ephSec hopPub)
      let !bf = computeBlindingFactor ephPub ss
      newEphSec <- maybe (Left (InvalidHopPubKey idx)) Right
                     (blindSecKey ephSec bf)
      newEphPub <- maybe (Left (InvalidHopPubKey idx)) Right
                     (blindPubKey ephPub bf)
      go newEphSec newEphPub (idx + 1) (ss : acc) rest

-- | Generate filler bytes.
generateFiller :: [SharedSecret] -> [Int] -> BS.ByteString
generateFiller !secrets !sizes = go BS.empty secrets sizes
  where
    go !filler [] [] = filler
    go !filler (ss:sss) (sz:szs) =
      let !extended = filler <> BS.replicate sz 0
          !rhoKey = deriveRho ss
          !stream = generateStream rhoKey (2 * hopPayloadsSize)
          !streamOffset = hopPayloadsSize
          !streamPart = BS.take (BS.length extended)
                          (BS.drop streamOffset stream)
          !newFiller = xorBytes extended streamPart
      in  go newFiller sss szs
    go !filler _ _ = filler
{-# INLINE generateFiller #-}

-- | Wrap all hops in reverse order.
wrapAllHops
  :: [SharedSecret]
  -> [BS.ByteString]
  -> BS.ByteString
  -> BS.ByteString
  -> BS.ByteString
  -> (BS.ByteString, BS.ByteString)
wrapAllHops !secrets !payloads !filler !assocData !initPayloads =
  let !paired = reverse (zip secrets payloads)
      !numHops = length paired
      !initHmac = BS.replicate hmacSize 0
  in  go numHops initPayloads initHmac paired
  where
    go !_ !hpBuf !hmac [] = (hpBuf, hmac)
    go !remaining !hpBuf !hmac ((ss, payload):rest) =
      let !isLastHop = remaining ==
            length (reverse (zip secrets payloads))
          (!newPayloads, !newHmac) =
            wrapHop ss payload hmac hpBuf
              assocData filler isLastHop
      in  go (remaining - 1) newPayloads newHmac rest

-- | Wrap a single hop's payload.
wrapHop
  :: SharedSecret
  -> BS.ByteString
  -> BS.ByteString
  -> BS.ByteString
  -> BS.ByteString
  -> BS.ByteString
  -> Bool
  -> (BS.ByteString, BS.ByteString)
wrapHop !ss !payload !hmac !hpBuf !assocData !filler !isFinalHop =
  let !payloadLen = BS.length payload
      !lenBytes = encodeBigSize (fromIntegral payloadLen)
      !shiftSize = BS.length lenBytes + payloadLen + hmacSize
      !shifted = BS.take (hopPayloadsSize - shiftSize) hpBuf
      !prepended = lenBytes <> payload <> hmac <> shifted
      !rhoKey = deriveRho ss
      !stream = generateStream rhoKey hopPayloadsSize
      !obfuscated = xorBytes prepended stream
      !withFiller = if isFinalHop && not (BS.null filler)
                      then applyFiller obfuscated filler
                      else obfuscated
      !muKey = deriveMu ss
      !newHmac = computeHmac muKey withFiller assocData
  in  (withFiller, newHmac)
{-# INLINE wrapHop #-}

-- | Apply filler to the tail of hop_payloads.
applyFiller :: BS.ByteString -> BS.ByteString -> BS.ByteString
applyFiller !hpBuf !filler =
  let !fillerLen = BS.length filler
      !prefix = BS.take (hopPayloadsSize - fillerLen) hpBuf
  in  prefix <> filler
{-# INLINE applyFiller #-}

-- | XOR two ByteStrings.
xorBytes :: BS.ByteString -> BS.ByteString -> BS.ByteString
xorBytes !a !b = BS.pack $ BS.zipWith xor a b
{-# INLINE xorBytes #-}

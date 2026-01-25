{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module: Lightning.Protocol.BOLT4.Error
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Error packet construction and unwrapping for BOLT4 onion routing.
--
-- Failing nodes construct error packets that are wrapped at each
-- intermediate hop on the return path. The origin node unwraps
-- layers to attribute the error to a specific hop.

module Lightning.Protocol.BOLT4.Error (
    -- * Types
    ErrorPacket(..)
  , AttributionResult(..)
  , minErrorPacketSize

    -- * Error construction (failing node)
  , constructError

    -- * Error forwarding (intermediate node)
  , wrapError

    -- * Error unwrapping (origin node)
  , unwrapError
  ) where

import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Lazy as BL
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Word (Word8, Word16)
import Lightning.Protocol.BOLT4.Codec (encodeFailureMessage, decodeFailureMessage)
import Lightning.Protocol.BOLT4.Prim
import Lightning.Protocol.BOLT4.Types (FailureMessage)

-- | Wrapped error packet ready for return to origin.
newtype ErrorPacket = ErrorPacket BS.ByteString
  deriving (Eq, Show)

-- | Result of error attribution.
data AttributionResult
  = Attributed {-# UNPACK #-} !Int !FailureMessage
    -- ^ (hop index, failure)
  | UnknownOrigin !BS.ByteString
    -- ^ Could not attribute to any hop
  deriving (Eq, Show)

-- | Minimum error packet size (256 bytes per spec).
minErrorPacketSize :: Int
minErrorPacketSize = 256
{-# INLINE minErrorPacketSize #-}

-- Error construction ---------------------------------------------------------

-- | Construct an error packet at a failing node.
--
-- Takes the shared secret (from processing) and failure message,
-- and wraps it for return to origin.
constructError
  :: SharedSecret      -- ^ from packet processing
  -> FailureMessage    -- ^ failure details
  -> ErrorPacket
constructError !ss !failure =
  let !um = deriveUm ss
      !ammag = deriveAmmag ss
      !inner = buildErrorMessage um failure
      !obfuscated = obfuscateError ammag inner
  in  ErrorPacket obfuscated
{-# INLINE constructError #-}

-- | Wrap an existing error packet for forwarding back.
--
-- Each intermediate node wraps the error with its own layer.
wrapError
  :: SharedSecret      -- ^ this node's shared secret
  -> ErrorPacket       -- ^ error from downstream
  -> ErrorPacket
wrapError !ss (ErrorPacket !packet) =
  let !ammag = deriveAmmag ss
      !wrapped = obfuscateError ammag packet
  in  ErrorPacket wrapped
{-# INLINE wrapError #-}

-- Error unwrapping -----------------------------------------------------------

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
unwrapError secrets (ErrorPacket !initialPacket) = go 0 initialPacket secrets
  where
    go :: Int -> BS.ByteString -> [SharedSecret] -> AttributionResult
    go !_ !packet [] = UnknownOrigin packet
    go !idx !packet (ss:rest) =
      let !ammag = deriveAmmag ss
          !um = deriveUm ss
          !deobfuscated = deobfuscateError ammag packet
      in  if verifyErrorHmac um deobfuscated
            then case parseErrorMessage (BS.drop 32 deobfuscated) of
                   Just msg -> Attributed idx msg
                   Nothing  -> UnknownOrigin deobfuscated
            else go (idx + 1) deobfuscated rest

-- Internal functions ---------------------------------------------------------

-- | Build the inner error message structure.
--
-- Format: HMAC (32) || len (2) || message || pad_len (2) || padding
-- Total must be >= 256 bytes.
buildErrorMessage
  :: DerivedKey        -- ^ um key
  -> FailureMessage    -- ^ failure to encode
  -> BS.ByteString     -- ^ complete message with HMAC
buildErrorMessage (DerivedKey !umKey) !failure =
  let !encoded = encodeFailureMessage failure
      !msgLen = BS.length encoded
      -- Total payload: len(2) + msg + pad_len(2) + padding = 256 - 32 = 224
      -- padding = 224 - 2 - msgLen - 2 = 220 - msgLen
      !padLen = max 0 (minErrorPacketSize - 32 - 2 - msgLen - 2)
      !padding = BS.replicate padLen 0
      -- Build: len || message || pad_len || padding
      !payload = toStrict $
        B.word16BE (fromIntegral msgLen) <>
        B.byteString encoded <>
        B.word16BE (fromIntegral padLen) <>
        B.byteString padding
      -- HMAC over the payload
      SHA256.MAC !hmac = SHA256.hmac umKey payload
  in  hmac <> payload
{-# INLINE buildErrorMessage #-}

-- | Obfuscate error packet with ammag stream.
--
-- XORs the entire packet with pseudo-random stream.
obfuscateError
  :: DerivedKey        -- ^ ammag key
  -> BS.ByteString     -- ^ error packet
  -> BS.ByteString     -- ^ obfuscated packet
obfuscateError !ammag !packet =
  let !stream = generateStream ammag (BS.length packet)
  in  xorBytes packet stream
{-# INLINE obfuscateError #-}

-- | Remove one layer of obfuscation from error packet.
--
-- XOR is its own inverse, so same as obfuscation.
deobfuscateError
  :: DerivedKey        -- ^ ammag key
  -> BS.ByteString     -- ^ obfuscated packet
  -> BS.ByteString     -- ^ deobfuscated packet
deobfuscateError = obfuscateError
{-# INLINE deobfuscateError #-}

-- | Verify error HMAC after deobfuscation.
verifyErrorHmac
  :: DerivedKey        -- ^ um key
  -> BS.ByteString     -- ^ deobfuscated packet (HMAC || rest)
  -> Bool
verifyErrorHmac (DerivedKey !umKey) !packet
  | BS.length packet < 32 = False
  | otherwise =
      let !receivedHmac = BS.take 32 packet
          !payload = BS.drop 32 packet
          SHA256.MAC !computedHmac = SHA256.hmac umKey payload
      in  constantTimeEq receivedHmac computedHmac
{-# INLINE verifyErrorHmac #-}

-- | Parse error message from deobfuscated packet (after HMAC).
parseErrorMessage
  :: BS.ByteString     -- ^ packet after HMAC (len || msg || pad_len || pad)
  -> Maybe FailureMessage
parseErrorMessage !bs
  | BS.length bs < 4 = Nothing
  | otherwise =
      let !msgLen = fromIntegral (word16BE (BS.take 2 bs))
      in  if BS.length bs < 2 + msgLen
            then Nothing
            else decodeFailureMessage (BS.take msgLen (BS.drop 2 bs))
{-# INLINE parseErrorMessage #-}

-- Helper functions -----------------------------------------------------------

-- | XOR two ByteStrings of equal length.
xorBytes :: BS.ByteString -> BS.ByteString -> BS.ByteString
xorBytes !a !b = BS.pack $ BS.zipWith xor a b
{-# INLINE xorBytes #-}

-- | Constant-time equality comparison.
constantTimeEq :: BS.ByteString -> BS.ByteString -> Bool
constantTimeEq !a !b
  | BS.length a /= BS.length b = False
  | otherwise = go 0 (BS.zip a b)
  where
    go :: Word8 -> [(Word8, Word8)] -> Bool
    go !acc [] = acc == 0
    go !acc ((x, y):rest) = go (acc `xor` (x `xor` y)) rest
{-# INLINE constantTimeEq #-}

-- | Decode big-endian Word16.
word16BE :: BS.ByteString -> Word16
word16BE !bs =
  let !b0 = fromIntegral (BS.index bs 0) :: Word16
      !b1 = fromIntegral (BS.index bs 1) :: Word16
  in  (b0 * 256) + b1
{-# INLINE word16BE #-}

-- | Convert Builder to strict ByteString.
toStrict :: B.Builder -> BS.ByteString
toStrict = BL.toStrict . B.toLazyByteString
{-# INLINE toStrict #-}

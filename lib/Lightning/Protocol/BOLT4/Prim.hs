{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module: Lightning.Protocol.BOLT4.Prim
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Low-level cryptographic primitives for BOLT4 onion routing.

module Lightning.Protocol.BOLT4.Prim (
    -- * Types
    SharedSecret(..)
  , DerivedKey(..)
  , BlindingFactor(..)

    -- * Key derivation
  , deriveRho
  , deriveMu
  , deriveUm
  , derivePad
  , deriveAmmag

    -- * Shared secret computation
  , computeSharedSecret

    -- * Blinding factor computation
  , computeBlindingFactor

    -- * Key blinding
  , blindPubKey
  , blindSecKey

    -- * Stream generation
  , generateStream

    -- * HMAC operations
  , computeHmac
  , verifyHmac
  ) where

import qualified Crypto.Cipher.ChaCha20 as ChaCha
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.List as L
import Data.Word (Word8, Word32)

-- | 32-byte shared secret derived from ECDH.
newtype SharedSecret = SharedSecret BS.ByteString
  deriving (Eq, Show)

-- | 32-byte derived key (rho, mu, um, pad, ammag).
newtype DerivedKey = DerivedKey BS.ByteString
  deriving (Eq, Show)

-- | 32-byte blinding factor for ephemeral key updates.
newtype BlindingFactor = BlindingFactor BS.ByteString
  deriving (Eq, Show)

-- Key derivation ------------------------------------------------------------

-- | Derive rho key for obfuscation stream generation.
--
-- @rho = HMAC-SHA256(key="rho", data=shared_secret)@
deriveRho :: SharedSecret -> DerivedKey
deriveRho = deriveKey "rho"
{-# INLINE deriveRho #-}

-- | Derive mu key for HMAC computation.
--
-- @mu = HMAC-SHA256(key="mu", data=shared_secret)@
deriveMu :: SharedSecret -> DerivedKey
deriveMu = deriveKey "mu"
{-# INLINE deriveMu #-}

-- | Derive um key for return error HMAC.
--
-- @um = HMAC-SHA256(key="um", data=shared_secret)@
deriveUm :: SharedSecret -> DerivedKey
deriveUm = deriveKey "um"
{-# INLINE deriveUm #-}

-- | Derive pad key for filler generation.
--
-- @pad = HMAC-SHA256(key="pad", data=shared_secret)@
derivePad :: SharedSecret -> DerivedKey
derivePad = deriveKey "pad"
{-# INLINE derivePad #-}

-- | Derive ammag key for error obfuscation.
--
-- @ammag = HMAC-SHA256(key="ammag", data=shared_secret)@
deriveAmmag :: SharedSecret -> DerivedKey
deriveAmmag = deriveKey "ammag"
{-# INLINE deriveAmmag #-}

-- Internal helper for key derivation.
deriveKey :: BS.ByteString -> SharedSecret -> DerivedKey
deriveKey !keyType (SharedSecret !ss) =
  let SHA256.MAC !result = SHA256.hmac keyType ss
  in  DerivedKey result
{-# INLINE deriveKey #-}

-- Shared secret computation -------------------------------------------------

-- | Compute shared secret from ECDH.
--
-- Takes a 32-byte secret key and a public key.
-- Returns SHA256 of the compressed ECDH point (33 bytes).
computeSharedSecret
  :: BS.ByteString         -- ^ 32-byte secret key
  -> Secp256k1.Projective  -- ^ public key
  -> Maybe SharedSecret
computeSharedSecret !secBs !pub = do
  sec <- Secp256k1.roll32 secBs
  ecdhPoint <- Secp256k1.mul pub sec
  let !compressed = Secp256k1.serialize_point ecdhPoint
      !ss = SHA256.hash compressed
  pure $! SharedSecret ss
{-# INLINE computeSharedSecret #-}

-- Blinding factor -----------------------------------------------------------

-- | Compute blinding factor for ephemeral key updates.
--
-- @blinding_factor = SHA256(ephemeral_pubkey || shared_secret)@
computeBlindingFactor
  :: Secp256k1.Projective  -- ^ ephemeral public key
  -> SharedSecret          -- ^ shared secret
  -> BlindingFactor
computeBlindingFactor !pub (SharedSecret !ss) =
  let !pubBytes = Secp256k1.serialize_point pub
      !combined = pubBytes <> ss
      !hashed = SHA256.hash combined
  in  BlindingFactor hashed
{-# INLINE computeBlindingFactor #-}

-- Key blinding --------------------------------------------------------------

-- | Blind a public key by multiplying with blinding factor.
--
-- @new_pubkey = pubkey * blinding_factor@
blindPubKey
  :: Secp256k1.Projective
  -> BlindingFactor
  -> Maybe Secp256k1.Projective
blindPubKey !pub (BlindingFactor !bf) = do
  sk <- Secp256k1.roll32 bf
  Secp256k1.mul pub sk
{-# INLINE blindPubKey #-}

-- | Blind a secret key by multiplying with blinding factor (mod curve order).
--
-- @new_seckey = seckey * blinding_factor (mod q)@
--
-- Takes a 32-byte secret key and returns a 32-byte blinded secret key.
blindSecKey
  :: BS.ByteString     -- ^ 32-byte secret key
  -> BlindingFactor    -- ^ blinding factor
  -> Maybe BS.ByteString  -- ^ 32-byte blinded secret key
blindSecKey !secBs (BlindingFactor !bf)
  | BS.length secBs /= 32 = Nothing
  | BS.length bf /= 32 = Nothing
  | otherwise =
      -- Convert to Integer, multiply, reduce mod q, convert back
      let !secInt = bsToInteger secBs
          !bfInt = bsToInteger bf
          -- secp256k1 curve order
          !qInt = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
          !resultInt = (secInt * bfInt) `mod` qInt
          !resultBs = integerToBS32 resultInt
      in  Just resultBs
{-# INLINE blindSecKey #-}

-- Convert big-endian ByteString to Integer.
bsToInteger :: BS.ByteString -> Integer
bsToInteger = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0
{-# INLINE bsToInteger #-}

-- Convert Integer to 32-byte big-endian ByteString.
integerToBS32 :: Integer -> BS.ByteString
integerToBS32 n = BS.pack (go 32 n [])
  where
    go :: Int -> Integer -> [Word8] -> [Word8]
    go 0 _ acc = acc
    go i x acc = go (i - 1) (x `div` 256) (fromIntegral (x `mod` 256) : acc)
{-# INLINE integerToBS32 #-}

-- Stream generation ---------------------------------------------------------

-- | Generate pseudo-random byte stream using ChaCha20.
--
-- Uses derived key as ChaCha20 key, 96-bit zero nonce, counter=0.
-- Encrypts zeros to produce keystream.
generateStream
  :: DerivedKey     -- ^ rho or ammag key
  -> Int            -- ^ desired length
  -> BS.ByteString
generateStream (DerivedKey !key) !len =
  let !nonce = BS.replicate 12 0
      !zeros = BS.replicate len 0
  in  either (const (BS.replicate len 0)) id
        (ChaCha.cipher key (0 :: Word32) nonce zeros)
{-# INLINE generateStream #-}

-- HMAC operations -----------------------------------------------------------

-- | Compute HMAC-SHA256 for packet integrity.
computeHmac
  :: DerivedKey      -- ^ mu key
  -> BS.ByteString   -- ^ hop_payloads
  -> BS.ByteString   -- ^ associated_data
  -> BS.ByteString   -- ^ 32-byte HMAC
computeHmac (DerivedKey !key) !payloads !assocData =
  let SHA256.MAC !result = SHA256.hmac key (payloads <> assocData)
  in  result
{-# INLINE computeHmac #-}

-- | Constant-time HMAC comparison.
verifyHmac
  :: BS.ByteString  -- ^ expected
  -> BS.ByteString  -- ^ computed
  -> Bool
verifyHmac !expected !computed
  | BS.length expected /= BS.length computed = False
  | otherwise = constantTimeEq expected computed
{-# INLINE verifyHmac #-}

-- Constant-time equality comparison.
constantTimeEq :: BS.ByteString -> BS.ByteString -> Bool
constantTimeEq !a !b =
  let !diff = L.foldl' (\acc (x, y) -> acc `xor` (x `xor` y)) (0 :: Word8)
                       (BS.zip a b)
  in  diff == 0
{-# INLINE constantTimeEq #-}

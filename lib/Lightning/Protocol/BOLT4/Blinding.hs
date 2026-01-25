{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module: Lightning.Protocol.BOLT4.Blinding
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Route blinding for BOLT4 onion routing.

module Lightning.Protocol.BOLT4.Blinding (
    -- * Types
    BlindedPath(..)
  , BlindedHop(..)
  , BlindedHopData(..)
  , PaymentRelay(..)
  , PaymentConstraints(..)
  , BlindingError(..)

    -- * Path creation
  , createBlindedPath

    -- * Hop processing
  , processBlindedHop

    -- * Key derivation (exported for testing)
  , deriveBlindingRho
  , deriveBlindedNodeId
  , nextEphemeral

    -- * TLV encoding (exported for testing)
  , encodeBlindedHopData
  , decodeBlindedHopData

    -- * Encryption (exported for testing)
  , encryptHopData
  , decryptHopData
  ) where

import qualified Crypto.AEAD.ChaCha20Poly1305 as AEAD
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import Data.Word (Word16, Word32, Word64)
import qualified Numeric.Montgomery.Secp256k1.Scalar as S
import Lightning.Protocol.BOLT4.Codec
  ( encodeShortChannelId, decodeShortChannelId
  , encodeTlvStream, decodeTlvStream
  , toStrict, word16BE, word32BE
  , encodeWord64TU, decodeWord64TU
  , encodeWord32TU, decodeWord32TU
  )
import Lightning.Protocol.BOLT4.Prim (SharedSecret(..), DerivedKey(..))
import Lightning.Protocol.BOLT4.Types (ShortChannelId(..), TlvRecord(..))

-- Types ---------------------------------------------------------------------

-- | A blinded route provided by recipient.
data BlindedPath = BlindedPath
  { bpIntroductionNode :: !Secp256k1.Projective  -- ^ First node (unblinded)
  , bpBlindingKey      :: !Secp256k1.Projective  -- ^ E_0, initial ephemeral
  , bpBlindedHops      :: ![BlindedHop]
  } deriving (Eq, Show)

-- | A single hop in a blinded path.
data BlindedHop = BlindedHop
  { bhBlindedNodeId :: !BS.ByteString  -- ^ 33 bytes, blinded pubkey
  , bhEncryptedData :: !BS.ByteString  -- ^ Encrypted routing data
  } deriving (Eq, Show)

-- | Data encrypted for each blinded hop (before encryption).
data BlindedHopData = BlindedHopData
  { bhdPadding             :: !(Maybe BS.ByteString)  -- ^ TLV 1
  , bhdShortChannelId      :: !(Maybe ShortChannelId) -- ^ TLV 2
  , bhdNextNodeId          :: !(Maybe BS.ByteString)  -- ^ TLV 4, 33-byte pubkey
  , bhdPathId              :: !(Maybe BS.ByteString)  -- ^ TLV 6
  , bhdNextPathKeyOverride :: !(Maybe BS.ByteString)  -- ^ TLV 8
  , bhdPaymentRelay        :: !(Maybe PaymentRelay)   -- ^ TLV 10
  , bhdPaymentConstraints  :: !(Maybe PaymentConstraints) -- ^ TLV 12
  , bhdAllowedFeatures     :: !(Maybe BS.ByteString)  -- ^ TLV 14
  } deriving (Eq, Show)

-- | Payment relay parameters (TLV 10).
data PaymentRelay = PaymentRelay
  { prCltvExpiryDelta  :: {-# UNPACK #-} !Word16
  , prFeeProportional  :: {-# UNPACK #-} !Word32  -- ^ Fee in millionths
  , prFeeBaseMsat      :: {-# UNPACK #-} !Word32
  } deriving (Eq, Show)

-- | Payment constraints (TLV 12).
data PaymentConstraints = PaymentConstraints
  { pcMaxCltvExpiry   :: {-# UNPACK #-} !Word32
  , pcHtlcMinimumMsat :: {-# UNPACK #-} !Word64
  } deriving (Eq, Show)

-- | Errors during blinding operations.
data BlindingError
  = InvalidSeed
  | EmptyPath
  | InvalidNodeKey Int
  | DecryptionFailed
  | InvalidPathKey
  deriving (Eq, Show)

-- Key derivation ------------------------------------------------------------

-- | Derive rho key for encrypting hop data.
--
-- @rho = HMAC-SHA256(key="rho", data=shared_secret)@
deriveBlindingRho :: SharedSecret -> DerivedKey
deriveBlindingRho (SharedSecret !ss) =
  let SHA256.MAC !result = SHA256.hmac "rho" ss
  in  DerivedKey result
{-# INLINE deriveBlindingRho #-}

-- | Derive blinded node ID from shared secret and node pubkey.
--
-- @B_i = HMAC256("blinded_node_id", ss_i) * N_i@
deriveBlindedNodeId
  :: SharedSecret
  -> Secp256k1.Projective
  -> Maybe BS.ByteString
deriveBlindedNodeId (SharedSecret !ss) !nodePub = do
  let SHA256.MAC !hmacResult = SHA256.hmac "blinded_node_id" ss
  sk <- Secp256k1.roll32 hmacResult
  blindedPub <- Secp256k1.mul nodePub sk
  pure $! Secp256k1.serialize_point blindedPub
{-# INLINE deriveBlindedNodeId #-}

-- | Compute next ephemeral key pair.
--
-- @e_{i+1} = SHA256(E_i || ss_i) * e_i@
-- @E_{i+1} = SHA256(E_i || ss_i) * E_i@
nextEphemeral
  :: BS.ByteString        -- ^ e_i (32-byte secret key)
  -> Secp256k1.Projective -- ^ E_i
  -> SharedSecret         -- ^ ss_i
  -> Maybe (BS.ByteString, Secp256k1.Projective)  -- ^ (e_{i+1}, E_{i+1})
nextEphemeral !secKey !pubKey (SharedSecret !ss) = do
  let !pubBytes = Secp256k1.serialize_point pubKey
      !blindingFactor = SHA256.hash (pubBytes <> ss)
  bfInt <- Secp256k1.roll32 blindingFactor
  -- Compute e_{i+1} = e_i * blindingFactor (mod q)
  let !newSecKey = mulSecKey secKey blindingFactor
  -- Compute E_{i+1} = E_i * blindingFactor
  newPubKey <- Secp256k1.mul pubKey bfInt
  pure (newSecKey, newPubKey)
{-# INLINE nextEphemeral #-}

-- | Compute blinding factor for next path key (public key only).
nextPathKey
  :: Secp256k1.Projective -- ^ E_i
  -> SharedSecret         -- ^ ss_i
  -> Maybe Secp256k1.Projective  -- ^ E_{i+1}
nextPathKey !pubKey (SharedSecret !ss) = do
  let !pubBytes = Secp256k1.serialize_point pubKey
      !blindingFactor = SHA256.hash (pubBytes <> ss)
  bfInt <- Secp256k1.roll32 blindingFactor
  Secp256k1.mul pubKey bfInt
{-# INLINE nextPathKey #-}

-- Encryption/Decryption -----------------------------------------------------

-- | Encrypt hop data with ChaCha20-Poly1305.
--
-- Uses rho key and 12-byte zero nonce, empty AAD.
encryptHopData :: DerivedKey -> BlindedHopData -> BS.ByteString
encryptHopData (DerivedKey !rho) !hopData =
  let !plaintext = encodeBlindedHopData hopData
      !nonce = BS.replicate 12 0
  in  case AEAD.encrypt BS.empty rho nonce plaintext of
        Left e -> error $ "encryptHopData: unexpected AEAD error: " ++ show e
        Right (!ciphertext, !mac) -> ciphertext <> mac
{-# INLINE encryptHopData #-}

-- | Decrypt hop data with ChaCha20-Poly1305.
decryptHopData :: DerivedKey -> BS.ByteString -> Maybe BlindedHopData
decryptHopData (DerivedKey !rho) !encData
  | BS.length encData < 16 = Nothing
  | otherwise = do
      let !ciphertext = BS.take (BS.length encData - 16) encData
          !mac = BS.drop (BS.length encData - 16) encData
          !nonce = BS.replicate 12 0
      case AEAD.decrypt BS.empty rho nonce (ciphertext, mac) of
        Left _ -> Nothing
        Right !plaintext -> decodeBlindedHopData plaintext
{-# INLINE decryptHopData #-}

-- TLV Encoding/Decoding -----------------------------------------------------

-- | Encode BlindedHopData to TLV stream.
encodeBlindedHopData :: BlindedHopData -> BS.ByteString
encodeBlindedHopData !bhd = encodeTlvStream (buildTlvs bhd)
  where
    buildTlvs :: BlindedHopData -> [TlvRecord]
    buildTlvs (BlindedHopData pad sci nid pid pko pr pc af) =
      let pad'  = maybe [] (\p -> [TlvRecord 1 p]) pad
          sci'  = maybe [] (\s -> [TlvRecord 2 (encodeShortChannelId s)]) sci
          nid'  = maybe [] (\n -> [TlvRecord 4 n]) nid
          pid'  = maybe [] (\p -> [TlvRecord 6 p]) pid
          pko'  = maybe [] (\k -> [TlvRecord 8 k]) pko
          pr'   = maybe [] (\r -> [TlvRecord 10 (encodePaymentRelay r)]) pr
          pc'   = maybe [] (\c -> [TlvRecord 12 (encodePaymentConstraints c)]) pc
          af'   = maybe [] (\f -> [TlvRecord 14 f]) af
      in  pad' ++ sci' ++ nid' ++ pid' ++ pko' ++ pr' ++ pc' ++ af'
{-# INLINE encodeBlindedHopData #-}

-- | Decode TLV stream to BlindedHopData.
decodeBlindedHopData :: BS.ByteString -> Maybe BlindedHopData
decodeBlindedHopData !bs = do
  tlvs <- decodeTlvStream bs
  parseBlindedHopData tlvs

parseBlindedHopData :: [TlvRecord] -> Maybe BlindedHopData
parseBlindedHopData = go emptyHopData
  where
    emptyHopData :: BlindedHopData
    emptyHopData = BlindedHopData
      Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing

    go :: BlindedHopData -> [TlvRecord] -> Maybe BlindedHopData
    go !bhd [] = Just bhd
    go !bhd (TlvRecord typ val : rest) = case typ of
      1  -> go bhd { bhdPadding = Just val } rest
      2  -> do
        sci <- decodeShortChannelId val
        go bhd { bhdShortChannelId = Just sci } rest
      4  -> go bhd { bhdNextNodeId = Just val } rest
      6  -> go bhd { bhdPathId = Just val } rest
      8  -> go bhd { bhdNextPathKeyOverride = Just val } rest
      10 -> do
        pr <- decodePaymentRelay val
        go bhd { bhdPaymentRelay = Just pr } rest
      12 -> do
        pc <- decodePaymentConstraints val
        go bhd { bhdPaymentConstraints = Just pc } rest
      14 -> go bhd { bhdAllowedFeatures = Just val } rest
      _  -> go bhd rest  -- Skip unknown TLVs

-- PaymentRelay encoding/decoding --------------------------------------------

-- | Encode PaymentRelay.
--
-- Format: 2-byte cltv_delta BE, 4-byte fee_prop BE, tu32 fee_base
encodePaymentRelay :: PaymentRelay -> BS.ByteString
encodePaymentRelay (PaymentRelay !cltv !feeProp !feeBase) = toStrict $
  B.word16BE cltv <>
  B.word32BE feeProp <>
  B.byteString (encodeWord32TU feeBase)
{-# INLINE encodePaymentRelay #-}

-- | Decode PaymentRelay.
decodePaymentRelay :: BS.ByteString -> Maybe PaymentRelay
decodePaymentRelay !bs
  | BS.length bs < 6 = Nothing
  | otherwise = do
      let !cltv = word16BE (BS.take 2 bs)
          !feeProp = word32BE (BS.take 4 (BS.drop 2 bs))
          !feeBaseBytes = BS.drop 6 bs
      feeBase <- decodeWord32TU feeBaseBytes
      Just (PaymentRelay cltv feeProp feeBase)
{-# INLINE decodePaymentRelay #-}

-- PaymentConstraints encoding/decoding --------------------------------------

-- | Encode PaymentConstraints.
--
-- Format: 4-byte max_cltv BE, tu64 htlc_min
encodePaymentConstraints :: PaymentConstraints -> BS.ByteString
encodePaymentConstraints (PaymentConstraints !maxCltv !htlcMin) = toStrict $
  B.word32BE maxCltv <>
  B.byteString (encodeWord64TU htlcMin)
{-# INLINE encodePaymentConstraints #-}

-- | Decode PaymentConstraints.
decodePaymentConstraints :: BS.ByteString -> Maybe PaymentConstraints
decodePaymentConstraints !bs
  | BS.length bs < 4 = Nothing
  | otherwise = do
      let !maxCltv = word32BE (BS.take 4 bs)
          !htlcMinBytes = BS.drop 4 bs
      htlcMin <- decodeWord64TU htlcMinBytes
      Just (PaymentConstraints maxCltv htlcMin)
{-# INLINE decodePaymentConstraints #-}

-- Shared secret computation -------------------------------------------------

-- | Compute shared secret from ECDH.
computeSharedSecret
  :: BS.ByteString         -- ^ 32-byte secret key
  -> Secp256k1.Projective  -- ^ Public key
  -> Maybe SharedSecret
computeSharedSecret !secBs !pub = do
  sec <- Secp256k1.roll32 secBs
  ecdhPoint <- Secp256k1.mul pub sec
  let !compressed = Secp256k1.serialize_point ecdhPoint
      !ss = SHA256.hash compressed
  pure $! SharedSecret ss
{-# INLINE computeSharedSecret #-}

-- Path creation -------------------------------------------------------------

-- | Create a blinded path from a seed and list of nodes with their data.
createBlindedPath
  :: BS.ByteString  -- ^ 32-byte random seed for ephemeral key
  -> [(Secp256k1.Projective, BlindedHopData)]  -- ^ Nodes with their data
  -> Either BlindingError BlindedPath
createBlindedPath !seed !nodes
  | BS.length seed /= 32 = Left InvalidSeed
  | otherwise = case nodes of
      [] -> Left EmptyPath
      ((introNode, _) : _) -> do
        -- (e_0, E_0) = keypair from seed
        e0 <- maybe (Left InvalidSeed) Right (Secp256k1.roll32 seed)
        e0Pub <- maybe (Left InvalidSeed) Right
                   (Secp256k1.mul Secp256k1._CURVE_G e0)
        -- Process all hops
        hops <- processHops seed e0Pub nodes 0
        Right (BlindedPath introNode e0Pub hops)

processHops
  :: BS.ByteString  -- ^ Current e_i
  -> Secp256k1.Projective  -- ^ Current E_i
  -> [(Secp256k1.Projective, BlindedHopData)]
  -> Int  -- ^ Index for error reporting
  -> Either BlindingError [BlindedHop]
processHops _ _ [] _ = Right []
processHops !eKey !ePub ((nodePub, hopData) : rest) !idx = do
  -- ss_i = SHA256(ECDH(e_i, N_i))
  ss <- maybe (Left (InvalidNodeKey idx)) Right
          (computeSharedSecret eKey nodePub)
  -- rho_i = deriveBlindingRho(ss_i)
  let !rho = deriveBlindingRho ss
  -- B_i = deriveBlindedNodeId(ss_i, N_i)
  blindedId <- maybe (Left (InvalidNodeKey idx)) Right
                 (deriveBlindedNodeId ss nodePub)
  -- encrypted_i = encryptHopData(rho_i, data_i)
  let !encData = encryptHopData rho hopData
      !hop = BlindedHop blindedId encData
  -- (e_{i+1}, E_{i+1}) = nextEphemeral(e_i, E_i, ss_i)
  (nextE, nextEPub) <- maybe (Left (InvalidNodeKey idx)) Right
                         (nextEphemeral eKey ePub ss)
  -- Process remaining hops
  restHops <- processHops nextE nextEPub rest (idx + 1)
  Right (hop : restHops)

-- Hop processing ------------------------------------------------------------

-- | Process a blinded hop, returning decrypted data and next path key.
processBlindedHop
  :: BS.ByteString        -- ^ Node's 32-byte private key
  -> Secp256k1.Projective -- ^ E_i, current path key (blinding point)
  -> BS.ByteString        -- ^ encrypted_data from onion payload
  -> Either BlindingError (BlindedHopData, Secp256k1.Projective)
processBlindedHop !nodeSecKey !pathKey !encData = do
  -- ss = SHA256(ECDH(node_seckey, path_key))
  ss <- maybe (Left InvalidPathKey) Right
          (computeSharedSecret nodeSecKey pathKey)
  -- rho = deriveBlindingRho(ss)
  let !rho = deriveBlindingRho ss
  -- hop_data = decryptHopData(rho, encrypted_data)
  hopData <- maybe (Left DecryptionFailed) Right
               (decryptHopData rho encData)
  -- Compute next path key
  nextKey <- case bhdNextPathKeyOverride hopData of
    Just override -> do
      -- Parse override as compressed point
      maybe (Left InvalidPathKey) Right (Secp256k1.parse_point override)
    Nothing -> do
      -- E_next = SHA256(path_key || ss) * path_key
      maybe (Left InvalidPathKey) Right (nextPathKey pathKey ss)
  Right (hopData, nextKey)

-- Scalar multiplication -----------------------------------------------------

-- | Multiply two 32-byte scalars mod curve order q.
--
-- Uses Montgomery multiplication from ppad-fixed for efficiency.
mulSecKey :: BS.ByteString -> BS.ByteString -> BS.ByteString
mulSecKey !a !b =
  let !aW = Secp256k1.unsafe_roll32 a
      !bW = Secp256k1.unsafe_roll32 b
      !aM = S.to aW
      !bM = S.to bW
      !resultM = S.mul aM bM
      !resultW = S.retr resultM
  in  Secp256k1.unroll32 resultW
{-# INLINE mulSecKey #-}

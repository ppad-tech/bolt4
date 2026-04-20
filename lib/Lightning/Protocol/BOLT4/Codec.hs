{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module: Lightning.Protocol.BOLT4.Codec
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Serialization and deserialization for BOLT4 types.

module Lightning.Protocol.BOLT4.Codec (
    -- * BigSize encoding
    encodeBigSize
  , decodeBigSize
  , bigSizeLen

    -- * TLV encoding
  , encodeTlv
  , decodeTlv
  , decodeTlvStream
  , encodeTlvStream

    -- * Packet serialization
  , encodeOnionPacket
  , decodeOnionPacket
  , encodeHopPayload
  , decodeHopPayload

    -- * ShortChannelId
  , encodeShortChannelId
  , decodeShortChannelId

    -- * Failure messages
  , encodeFailureMessage
  , decodeFailureMessage

    -- * Internal helpers (for Blinding)
  , toStrict
  , word16BE
  , word32BE
  , encodeWord64TU
  , decodeWord64TU
  , encodeWord32TU
  , decodeWord32TU
  ) where

import Data.Bits (shiftL)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Lazy as BL
import Data.Word (Word16, Word32, Word64)
import Lightning.Protocol.BOLT4.Types

-- BigSize encoding ---------------------------------------------------------

-- | Encode integer as BigSize.
--
-- * 0-0xFC: 1 byte
-- * 0xFD-0xFFFF: 0xFD ++ 2 bytes BE
-- * 0x10000-0xFFFFFFFF: 0xFE ++ 4 bytes BE
-- * larger: 0xFF ++ 8 bytes BE
encodeBigSize :: Word64 -> BS.ByteString
encodeBigSize !n
  | n < 0xFD = BS.singleton (fromIntegral n)
  | n <= 0xFFFF = toStrict $
      B.word8 0xFD <> B.word16BE (fromIntegral n)
  | n <= 0xFFFFFFFF = toStrict $
      B.word8 0xFE <> B.word32BE (fromIntegral n)
  | otherwise = toStrict $
      B.word8 0xFF <> B.word64BE n
{-# INLINE encodeBigSize #-}

-- | Decode BigSize, returning (value, remaining bytes).
decodeBigSize :: BS.ByteString -> Maybe (Word64, BS.ByteString)
decodeBigSize !bs = case BS.uncons bs of
  Nothing -> Nothing
  Just (b, rest)
    | b < 0xFD -> Just (fromIntegral b, rest)
    | b == 0xFD -> do
        (hi, r1) <- BS.uncons rest
        (lo, r2) <- BS.uncons r1
        let !val = fromIntegral hi `shiftL` 8 + fromIntegral lo
        -- Canonical: must be >= 0xFD
        if val < 0xFD then Nothing else Just (val, r2)
    | b == 0xFE -> do
        if BS.length rest < 4 then Nothing else do
          let !bytes = BS.take 4 rest
              !r = BS.drop 4 rest
              !val = word32BE bytes
          -- Canonical: must be > 0xFFFF
          if val <= 0xFFFF then Nothing else Just (fromIntegral val, r)
    | otherwise -> do  -- b == 0xFF
        if BS.length rest < 8 then Nothing else do
          let !bytes = BS.take 8 rest
              !r = BS.drop 8 rest
              !val = word64BE bytes
          -- Canonical: must be > 0xFFFFFFFF
          if val <= 0xFFFFFFFF then Nothing else Just (val, r)
{-# INLINE decodeBigSize #-}

-- | Get encoded size of a BigSize value without encoding.
bigSizeLen :: Word64 -> Int
bigSizeLen !n
  | n < 0xFD       = 1
  | n <= 0xFFFF    = 3
  | n <= 0xFFFFFFFF = 5
  | otherwise      = 9
{-# INLINE bigSizeLen #-}

-- TLV encoding -------------------------------------------------------------

-- | Encode a TLV record.
encodeTlv :: TlvRecord -> BS.ByteString
encodeTlv (TlvRecord !typ !val) = toStrict $
  B.byteString (encodeBigSize typ) <>
  B.byteString (encodeBigSize (fromIntegral (BS.length val))) <>
  B.byteString val
{-# INLINE encodeTlv #-}

-- | Decode a single TLV record.
decodeTlv :: BS.ByteString -> Maybe (TlvRecord, BS.ByteString)
decodeTlv !bs = do
  (typ, r1) <- decodeBigSize bs
  (len, r2) <- decodeBigSize r1
  let !len' = fromIntegral len
  if BS.length r2 < len'
    then Nothing
    else do
      let !val = BS.take len' r2
          !rest = BS.drop len' r2
      Just (TlvRecord typ val, rest)
{-# INLINE decodeTlv #-}

-- | Decode a TLV stream (sequence of records).
-- Validates strictly increasing type order.
decodeTlvStream :: BS.ByteString -> Maybe [TlvRecord]
decodeTlvStream = go Nothing
  where
    go :: Maybe Word64 -> BS.ByteString -> Maybe [TlvRecord]
    go _ !bs | BS.null bs = Just []
    go !mPrev !bs = do
      (rec@(TlvRecord typ _), rest) <- decodeTlv bs
      -- Check strictly increasing order
      case mPrev of
        Just prev | typ <= prev -> Nothing
        _ -> do
          recs <- go (Just typ) rest
          Just (rec : recs)

-- | Encode a TLV stream from records.
-- Records must be sorted by type, no duplicates.
encodeTlvStream :: [TlvRecord] -> BS.ByteString
encodeTlvStream !recs = toStrict $ foldMap (B.byteString . encodeTlv) recs
{-# INLINE encodeTlvStream #-}

-- Packet serialization -----------------------------------------------------

-- | Serialize OnionPacket to 1366 bytes.
encodeOnionPacket :: OnionPacket -> BS.ByteString
encodeOnionPacket (OnionPacket !ver !eph !payloads !mac) =
  toStrict $
    B.word8 ver <>
    B.byteString eph <>
    B.byteString (unHopPayloads payloads) <>
    B.byteString (unHmac32 mac)
{-# INLINE encodeOnionPacket #-}

-- | Parse OnionPacket from 1366 bytes.
decodeOnionPacket :: BS.ByteString -> Maybe OnionPacket
decodeOnionPacket !bs
  | BS.length bs /= onionPacketSize = Nothing
  | otherwise = do
      let !ver = BS.index bs 0
          !eph = BS.take pubkeySize (BS.drop 1 bs)
          !payloadsRaw = BS.take hopPayloadsSize
                           (BS.drop (1 + pubkeySize) bs)
          !macRaw = BS.drop
                      (1 + pubkeySize + hopPayloadsSize) bs
      hp <- hopPayloads payloadsRaw
      hm <- hmac32 macRaw
      Just (OnionPacket ver eph hp hm)
{-# INLINE decodeOnionPacket #-}

-- | Encode HopPayload to bytes (without length prefix).
encodeHopPayload :: HopPayload -> BS.ByteString
encodeHopPayload !hp = encodeTlvStream (buildTlvs hp)
  where
    buildTlvs :: HopPayload -> [TlvRecord]
    buildTlvs (HopPayload amt cltv sci pd ed cpk unk) =
      let amt' = maybe [] (\a -> [TlvRecord 2 (encodeWord64TU a)]) amt
          cltv' = maybe [] (\c -> [TlvRecord 4 (encodeWord32TU c)]) cltv
          sci' = maybe [] (\s -> [TlvRecord 6 (encodeShortChannelId s)]) sci
          pd' = maybe [] (\p -> [TlvRecord 8 (encodePaymentData p)]) pd
          ed' = maybe [] (\e -> [TlvRecord 10 e]) ed
          cpk' = maybe [] (\k -> [TlvRecord 12 k]) cpk
      in  amt' ++ cltv' ++ sci' ++ pd' ++ ed' ++ cpk' ++ unk

-- | Decode HopPayload from bytes.
decodeHopPayload :: BS.ByteString -> Maybe HopPayload
decodeHopPayload !bs = do
  tlvs <- decodeTlvStream bs
  parseHopPayload tlvs

parseHopPayload :: [TlvRecord] -> Maybe HopPayload
parseHopPayload = go emptyHop
  where
    emptyHop :: HopPayload
    emptyHop = HopPayload Nothing Nothing Nothing Nothing Nothing Nothing []

    go :: HopPayload -> [TlvRecord] -> Maybe HopPayload
    go !hp [] = Just hp { hpUnknownTlvs = reverse (hpUnknownTlvs hp) }
    go !hp (TlvRecord typ val : rest) = case typ of
      2  -> do
        amt <- decodeWord64TU val
        go hp { hpAmtToForward = Just amt } rest
      4  -> do
        cltv <- decodeWord32TU val
        go hp { hpOutgoingCltv = Just cltv } rest
      6  -> do
        sci <- decodeShortChannelId val
        go hp { hpShortChannelId = Just sci } rest
      8  -> do
        pd <- decodePaymentData val
        go hp { hpPaymentData = Just pd } rest
      10 -> go hp { hpEncryptedData = Just val } rest
      12 -> go hp { hpCurrentPathKey = Just val } rest
      _  -> go hp { hpUnknownTlvs = TlvRecord typ val : hpUnknownTlvs hp } rest

-- ShortChannelId -----------------------------------------------------------

-- | Encode ShortChannelId to 8 bytes big-endian.
encodeShortChannelId :: ShortChannelId -> BS.ByteString
encodeShortChannelId !sci = toStrict (B.word64BE (scidWord64 sci))
{-# INLINE encodeShortChannelId #-}

-- | Decode ShortChannelId from 8 bytes big-endian.
decodeShortChannelId :: BS.ByteString -> Maybe ShortChannelId
decodeShortChannelId !bs
  | BS.length bs /= 8 = Nothing
  | otherwise =
      let !w = (fromIntegral (BS.index bs 0) `shiftL` 56)
            + (fromIntegral (BS.index bs 1) `shiftL` 48)
            + (fromIntegral (BS.index bs 2) `shiftL` 40)
            + (fromIntegral (BS.index bs 3) `shiftL` 32)
            + (fromIntegral (BS.index bs 4) `shiftL` 24)
            + (fromIntegral (BS.index bs 5) `shiftL` 16)
            + (fromIntegral (BS.index bs 6) `shiftL` 8)
            +  fromIntegral (BS.index bs 7) :: Word64
      in  Just (ShortChannelId w)
{-# INLINE decodeShortChannelId #-}

-- Failure messages ---------------------------------------------------------

-- | Encode failure message.
encodeFailureMessage :: FailureMessage -> BS.ByteString
encodeFailureMessage (FailureMessage (FailureCode !code) !dat !tlvs) =
  toStrict $
    B.word16BE code <>
    B.word16BE (fromIntegral (BS.length dat)) <>
    B.byteString dat <>
    B.byteString (encodeTlvStream tlvs)
{-# INLINE encodeFailureMessage #-}

-- | Decode failure message.
decodeFailureMessage :: BS.ByteString -> Maybe FailureMessage
decodeFailureMessage !bs = do
  if BS.length bs < 4 then Nothing else do
    let !code = word16BE (BS.take 2 bs)
        !dlen = fromIntegral (word16BE (BS.take 2 (BS.drop 2 bs)))
    if BS.length bs < 4 + dlen then Nothing else do
      let !dat = BS.take dlen (BS.drop 4 bs)
          !tlvBytes = BS.drop (4 + dlen) bs
      tlvs <- if BS.null tlvBytes
                then Just []
                else decodeTlvStream tlvBytes
      Just (FailureMessage (FailureCode code) dat tlvs)

-- Helper functions ---------------------------------------------------------

-- | Convert Builder to strict ByteString.
toStrict :: B.Builder -> BS.ByteString
toStrict = BL.toStrict . B.toLazyByteString
{-# INLINE toStrict #-}

-- | Decode big-endian Word16.
word16BE :: BS.ByteString -> Word16
word16BE !bs =
  let !b0 = fromIntegral (BS.index bs 0) :: Word16
      !b1 = fromIntegral (BS.index bs 1) :: Word16
  in  (b0 `shiftL` 8) + b1
{-# INLINE word16BE #-}

-- | Decode big-endian Word32.
word32BE :: BS.ByteString -> Word32
word32BE !bs =
  let !b0 = fromIntegral (BS.index bs 0) :: Word32
      !b1 = fromIntegral (BS.index bs 1) :: Word32
      !b2 = fromIntegral (BS.index bs 2) :: Word32
      !b3 = fromIntegral (BS.index bs 3) :: Word32
  in  (b0 `shiftL` 24) + (b1 `shiftL` 16) + (b2 `shiftL` 8) + b3
{-# INLINE word32BE #-}

-- | Decode big-endian Word64.
word64BE :: BS.ByteString -> Word64
word64BE !bs =
  let !b0 = fromIntegral (BS.index bs 0) :: Word64
      !b1 = fromIntegral (BS.index bs 1) :: Word64
      !b2 = fromIntegral (BS.index bs 2) :: Word64
      !b3 = fromIntegral (BS.index bs 3) :: Word64
      !b4 = fromIntegral (BS.index bs 4) :: Word64
      !b5 = fromIntegral (BS.index bs 5) :: Word64
      !b6 = fromIntegral (BS.index bs 6) :: Word64
      !b7 = fromIntegral (BS.index bs 7) :: Word64
  in  (b0 `shiftL` 56) + (b1 `shiftL` 48) + (b2 `shiftL` 40) +
      (b3 `shiftL` 32) + (b4 `shiftL` 24) + (b5 `shiftL` 16) +
      (b6 `shiftL` 8) + b7
{-# INLINE word64BE #-}

-- | Encode Word64 as truncated unsigned (minimal bytes).
encodeWord64TU :: Word64 -> BS.ByteString
encodeWord64TU !n
  | n == 0 = BS.empty
  | otherwise = BS.dropWhile (== 0) (toStrict (B.word64BE n))
{-# INLINE encodeWord64TU #-}

-- | Decode truncated unsigned to Word64.
decodeWord64TU :: BS.ByteString -> Maybe Word64
decodeWord64TU !bs
  | BS.null bs = Just 0
  | BS.length bs > 8 = Nothing
  | not (BS.null bs) && BS.index bs 0 == 0 = Nothing  -- Non-canonical
  | otherwise = Just (go 0 bs)
  where
    go :: Word64 -> BS.ByteString -> Word64
    go !acc !b = case BS.uncons b of
      Nothing -> acc
      Just (x, rest) -> go ((acc `shiftL` 8) + fromIntegral x) rest
{-# INLINE decodeWord64TU #-}

-- | Encode Word32 as truncated unsigned.
encodeWord32TU :: Word32 -> BS.ByteString
encodeWord32TU !n
  | n == 0 = BS.empty
  | otherwise = BS.dropWhile (== 0) (toStrict (B.word32BE n))
{-# INLINE encodeWord32TU #-}

-- | Decode truncated unsigned to Word32.
decodeWord32TU :: BS.ByteString -> Maybe Word32
decodeWord32TU !bs
  | BS.null bs = Just 0
  | BS.length bs > 4 = Nothing
  | not (BS.null bs) && BS.index bs 0 == 0 = Nothing  -- Non-canonical
  | otherwise = Just (go 0 bs)
  where
    go :: Word32 -> BS.ByteString -> Word32
    go !acc !b = case BS.uncons b of
      Nothing -> acc
      Just (x, rest) -> go ((acc `shiftL` 8) + fromIntegral x) rest
{-# INLINE decodeWord32TU #-}

-- | Encode PaymentData.
encodePaymentData :: PaymentData -> BS.ByteString
encodePaymentData (PaymentData !secret !total) =
  unPaymentSecret secret <> encodeWord64TU total
{-# INLINE encodePaymentData #-}

-- | Decode PaymentData.
decodePaymentData :: BS.ByteString -> Maybe PaymentData
decodePaymentData !bs
  | BS.length bs < 32 = Nothing
  | otherwise = do
      ps <- paymentSecret (BS.take 32 bs)
      let !rest = BS.drop 32 bs
      total <- decodeWord64TU rest
      Just (PaymentData ps total)
{-# INLINE decodePaymentData #-}

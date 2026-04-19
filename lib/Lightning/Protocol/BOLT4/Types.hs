{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module: Lightning.Protocol.BOLT4.Types
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Core data types for BOLT4 onion routing.

module Lightning.Protocol.BOLT4.Types (
    -- * Packet types
    OnionPacket(..)
  , HopPayload(..)
  , ShortChannelId(..)
  , shortChannelId
  , scidBlockHeight
  , scidTxIndex
  , scidOutputIndex
  , scidWord64
  , PaymentData(..)
  , TlvRecord(..)

    -- * Error types
  , FailureMessage(..)
  , FailureCode(..)
    -- ** Flag bits
  , pattern BADONION
  , pattern PERM
  , pattern NODE
  , pattern UPDATE
    -- ** Common failure codes
  , pattern InvalidRealm
  , pattern TemporaryNodeFailure
  , pattern PermanentNodeFailure
  , pattern RequiredNodeFeatureMissing
  , pattern InvalidOnionVersion
  , pattern InvalidOnionHmac
  , pattern InvalidOnionKey
  , pattern TemporaryChannelFailure
  , pattern PermanentChannelFailure
  , pattern AmountBelowMinimum
  , pattern FeeInsufficient
  , pattern IncorrectCltvExpiry
  , pattern ExpiryTooSoon
  , pattern IncorrectOrUnknownPaymentDetails
  , pattern FinalIncorrectCltvExpiry
  , pattern FinalIncorrectHtlcAmount
  , pattern ChannelDisabled
  , pattern ExpiryTooFar
  , pattern InvalidOnionPayload
  , pattern MppTimeout

    -- * Processing results
  , ProcessResult(..)
  , ForwardInfo(..)
  , ReceiveInfo(..)

    -- * Constants
  , onionPacketSize
  , hopPayloadsSize
  , hmacSize
  , pubkeySize
  , versionByte
  , maxPayloadSize
  ) where

import Data.Bits ((.&.), (.|.))
import qualified Data.ByteString as BS
import Data.Word (Word8, Word16, Word32, Word64)
import GHC.Generics (Generic)
import Lightning.Protocol.BOLT1.Prim
  ( ShortChannelId(..), shortChannelId
  , scidBlockHeight, scidTxIndex, scidOutputIndex, scidWord64
  )

-- Packet types -------------------------------------------------------------

-- | Complete onion packet (1366 bytes).
data OnionPacket = OnionPacket
  { opVersion      :: {-# UNPACK #-} !Word8
  , opEphemeralKey :: !BS.ByteString  -- ^ 33 bytes, compressed pubkey
  , opHopPayloads  :: !BS.ByteString  -- ^ 1300 bytes
  , opHmac         :: !BS.ByteString  -- ^ 32 bytes
  } deriving (Eq, Show, Generic)

-- | Parsed hop payload after decryption.
data HopPayload = HopPayload
  { hpAmtToForward   :: !(Maybe Word64)         -- ^ TLV type 2
  , hpOutgoingCltv   :: !(Maybe Word32)         -- ^ TLV type 4
  , hpShortChannelId :: !(Maybe ShortChannelId) -- ^ TLV type 6
  , hpPaymentData    :: !(Maybe PaymentData)    -- ^ TLV type 8
  , hpEncryptedData  :: !(Maybe BS.ByteString)  -- ^ TLV type 10
  , hpCurrentPathKey :: !(Maybe BS.ByteString)  -- ^ TLV type 12
  , hpUnknownTlvs    :: ![TlvRecord]            -- ^ Unknown types
  } deriving (Eq, Show, Generic)

-- | Payment data for final hop (TLV type 8).
data PaymentData = PaymentData
  { pdPaymentSecret :: !BS.ByteString         -- ^ 32 bytes
  , pdTotalMsat     :: {-# UNPACK #-} !Word64
  } deriving (Eq, Show, Generic)

-- | Generic TLV record for unknown/extension types.
data TlvRecord = TlvRecord
  { tlvType  :: {-# UNPACK #-} !Word64
  , tlvValue :: !BS.ByteString
  } deriving (Eq, Show, Generic)

-- Error types --------------------------------------------------------------

-- | Failure message from intermediate or final node.
data FailureMessage = FailureMessage
  { fmCode :: {-# UNPACK #-} !FailureCode
  , fmData :: !BS.ByteString
  , fmTlvs :: ![TlvRecord]
  } deriving (Eq, Show, Generic)

-- | 2-byte failure code with flag bits.
newtype FailureCode = FailureCode Word16
  deriving (Eq, Show)

-- Flag bits

-- | BADONION flag (0x8000): error was in parsing the onion.
pattern BADONION :: Word16
pattern BADONION = 0x8000

-- | PERM flag (0x4000): permanent failure, do not retry.
pattern PERM :: Word16
pattern PERM = 0x4000

-- | NODE flag (0x2000): node failure rather than channel.
pattern NODE :: Word16
pattern NODE = 0x2000

-- | UPDATE flag (0x1000): channel update is attached.
pattern UPDATE :: Word16
pattern UPDATE = 0x1000

-- Common failure codes

-- | Invalid realm byte in onion.
pattern InvalidRealm :: FailureCode
pattern InvalidRealm = FailureCode 0x4001  -- PERM .|. 1

-- | Temporary node failure.
pattern TemporaryNodeFailure :: FailureCode
pattern TemporaryNodeFailure = FailureCode 0x2002  -- NODE .|. 2

-- | Permanent node failure.
pattern PermanentNodeFailure :: FailureCode
pattern PermanentNodeFailure = FailureCode 0x6002  -- PERM .|. NODE .|. 2

-- | Required node feature missing.
pattern RequiredNodeFeatureMissing :: FailureCode
pattern RequiredNodeFeatureMissing = FailureCode 0x6003  -- PERM .|. NODE .|. 3

-- | Invalid onion version.
pattern InvalidOnionVersion :: FailureCode
pattern InvalidOnionVersion = FailureCode 0xC004  -- BADONION .|. PERM .|. 4

-- | Invalid HMAC in onion.
pattern InvalidOnionHmac :: FailureCode
pattern InvalidOnionHmac = FailureCode 0xC005  -- BADONION .|. PERM .|. 5

-- | Invalid ephemeral key in onion.
pattern InvalidOnionKey :: FailureCode
pattern InvalidOnionKey = FailureCode 0xC006  -- BADONION .|. PERM .|. 6

-- | Temporary channel failure.
pattern TemporaryChannelFailure :: FailureCode
pattern TemporaryChannelFailure = FailureCode 0x1007  -- UPDATE .|. 7

-- | Permanent channel failure.
pattern PermanentChannelFailure :: FailureCode
pattern PermanentChannelFailure = FailureCode 0x4008  -- PERM .|. 8

-- | Amount below minimum for channel.
pattern AmountBelowMinimum :: FailureCode
pattern AmountBelowMinimum = FailureCode 0x100B  -- UPDATE .|. 11

-- | Fee insufficient.
pattern FeeInsufficient :: FailureCode
pattern FeeInsufficient = FailureCode 0x100C  -- UPDATE .|. 12

-- | Incorrect CLTV expiry.
pattern IncorrectCltvExpiry :: FailureCode
pattern IncorrectCltvExpiry = FailureCode 0x100D  -- UPDATE .|. 13

-- | Expiry too soon.
pattern ExpiryTooSoon :: FailureCode
pattern ExpiryTooSoon = FailureCode 0x100E  -- UPDATE .|. 14

-- | Payment details incorrect or unknown.
pattern IncorrectOrUnknownPaymentDetails :: FailureCode
pattern IncorrectOrUnknownPaymentDetails = FailureCode 0x400F  -- PERM .|. 15

-- | Final incorrect CLTV expiry.
pattern FinalIncorrectCltvExpiry :: FailureCode
pattern FinalIncorrectCltvExpiry = FailureCode 18  -- 0x12

-- | Final incorrect HTLC amount.
pattern FinalIncorrectHtlcAmount :: FailureCode
pattern FinalIncorrectHtlcAmount = FailureCode 19  -- 0x13

-- | Channel disabled.
pattern ChannelDisabled :: FailureCode
pattern ChannelDisabled = FailureCode 0x1014  -- UPDATE .|. 20

-- | Expiry too far.
pattern ExpiryTooFar :: FailureCode
pattern ExpiryTooFar = FailureCode 21  -- 0x15

-- | Invalid onion payload.
pattern InvalidOnionPayload :: FailureCode
pattern InvalidOnionPayload = FailureCode 0x4016  -- PERM .|. 22

-- | MPP timeout.
pattern MppTimeout :: FailureCode
pattern MppTimeout = FailureCode 23  -- 0x17

-- Processing results -------------------------------------------------------

-- | Result of processing an onion packet.
data ProcessResult
  = Forward !ForwardInfo  -- ^ Forward to next hop
  | Receive !ReceiveInfo  -- ^ Final destination reached
  deriving (Eq, Show, Generic)

-- | Information for forwarding to next hop.
data ForwardInfo = ForwardInfo
  { fiNextPacket   :: !OnionPacket
  , fiPayload      :: !HopPayload
  , fiSharedSecret :: !BS.ByteString  -- ^ For error attribution
  } deriving (Eq, Show, Generic)

-- | Information for receiving at final destination.
data ReceiveInfo = ReceiveInfo
  { riPayload      :: !HopPayload
  , riSharedSecret :: !BS.ByteString
  } deriving (Eq, Show, Generic)

-- Constants ----------------------------------------------------------------

-- | Total onion packet size (1366 bytes).
onionPacketSize :: Int
onionPacketSize = 1366
{-# INLINE onionPacketSize #-}

-- | Hop payloads section size (1300 bytes).
hopPayloadsSize :: Int
hopPayloadsSize = 1300
{-# INLINE hopPayloadsSize #-}

-- | HMAC size (32 bytes).
hmacSize :: Int
hmacSize = 32
{-# INLINE hmacSize #-}

-- | Compressed public key size (33 bytes).
pubkeySize :: Int
pubkeySize = 33
{-# INLINE pubkeySize #-}

-- | Version byte for onion packets.
versionByte :: Word8
versionByte = 0x00
{-# INLINE versionByte #-}

-- | Maximum payload size (1300 - 32 - 1 = 1267 bytes).
maxPayloadSize :: Int
maxPayloadSize = hopPayloadsSize - hmacSize - 1
{-# INLINE maxPayloadSize #-}

-- Silence unused import warning
_useBits :: Word16
_useBits = BADONION .&. PERM .|. NODE .|. UPDATE

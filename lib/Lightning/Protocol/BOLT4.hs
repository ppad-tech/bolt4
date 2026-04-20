{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module: Lightning.Protocol.BOLT4
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- BOLT4 onion routing for the Lightning Network.
--
-- This module re-exports the public interface from submodules.

module Lightning.Protocol.BOLT4 (
    -- * Re-exports
    module Lightning.Protocol.BOLT4.Blinding
  , module Lightning.Protocol.BOLT4.Codec
  , module Lightning.Protocol.BOLT4.Prim

    -- * Fixed-size newtypes
  , Hmac32
  , hmac32
  , unHmac32
  , HopPayloads
  , hopPayloads
  , unHopPayloads
  , PaymentSecret
  , paymentSecret
  , unPaymentSecret

    -- * Packet types
  , OnionPacket(..)
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

import Lightning.Protocol.BOLT4.Blinding
import Lightning.Protocol.BOLT4.Codec
import Lightning.Protocol.BOLT4.Prim
import Lightning.Protocol.BOLT4.Types

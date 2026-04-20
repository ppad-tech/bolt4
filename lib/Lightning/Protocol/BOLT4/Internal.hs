{-# OPTIONS_HADDOCK hide #-}

-- |
-- Module: Lightning.Protocol.BOLT4.Internal
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Internal definitions for BOLT4.
--
-- This module exports unsafe constructors that bypass
-- validation. Use only in tests or trusted internal code.

module Lightning.Protocol.BOLT4.Internal (
  -- * Unsafe constructors
    unsafeHmac32
  , unsafeHopPayloads
  , unsafePaymentSecret
  ) where

import qualified Data.ByteString as BS
import Lightning.Protocol.BOLT4.Types

-- | Construct an 'Hmac32' without length validation.
--
-- For test use only.
unsafeHmac32 :: BS.ByteString -> Hmac32
unsafeHmac32 = Hmac32

-- | Construct a 'HopPayloads' without length validation.
--
-- For test use only.
unsafeHopPayloads :: BS.ByteString -> HopPayloads
unsafeHopPayloads = HopPayloads

-- | Construct a 'PaymentSecret' without length validation.
--
-- For test use only.
unsafePaymentSecret :: BS.ByteString -> PaymentSecret
unsafePaymentSecret = PaymentSecret

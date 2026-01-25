{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import Lightning.Protocol.BOLT4.Codec
import Lightning.Protocol.BOLT4.Prim
import Lightning.Protocol.BOLT4.Process
import Lightning.Protocol.BOLT4.Types
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

main :: IO ()
main = defaultMain $ testGroup "ppad-bolt4" [
    testGroup "Prim" [
        primTests
      ]
  , testGroup "BigSize" [
        bigsizeTests
      , bigsizeRoundtripProp
      ]
  , testGroup "TLV" [
        tlvTests
      ]
  , testGroup "ShortChannelId" [
        sciTests
      ]
  , testGroup "OnionPacket" [
        onionPacketTests
      ]
  , testGroup "Process" [
        processTests
      ]
  ]

-- BigSize tests ------------------------------------------------------------

bigsizeTests :: TestTree
bigsizeTests = testGroup "boundary values" [
    testCase "0" $
      encodeBigSize 0 @?= BS.pack [0x00]
  , testCase "0xFC" $
      encodeBigSize 0xFC @?= BS.pack [0xFC]
  , testCase "0xFD" $
      encodeBigSize 0xFD @?= BS.pack [0xFD, 0x00, 0xFD]
  , testCase "0xFFFF" $
      encodeBigSize 0xFFFF @?= BS.pack [0xFD, 0xFF, 0xFF]
  , testCase "0x10000" $
      encodeBigSize 0x10000 @?= BS.pack [0xFE, 0x00, 0x01, 0x00, 0x00]
  , testCase "0xFFFFFFFF" $
      encodeBigSize 0xFFFFFFFF @?= BS.pack [0xFE, 0xFF, 0xFF, 0xFF, 0xFF]
  , testCase "0x100000000" $
      encodeBigSize 0x100000000 @?=
        BS.pack [0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
  , testCase "decode 0" $ do
      let result = decodeBigSize (BS.pack [0x00])
      result @?= Just (0, BS.empty)
  , testCase "decode 0xFC" $ do
      let result = decodeBigSize (BS.pack [0xFC])
      result @?= Just (0xFC, BS.empty)
  , testCase "decode 0xFD" $ do
      let result = decodeBigSize (BS.pack [0xFD, 0x00, 0xFD])
      result @?= Just (0xFD, BS.empty)
  , testCase "decode 0xFFFF" $ do
      let result = decodeBigSize (BS.pack [0xFD, 0xFF, 0xFF])
      result @?= Just (0xFFFF, BS.empty)
  , testCase "decode 0x10000" $ do
      let result = decodeBigSize (BS.pack [0xFE, 0x00, 0x01, 0x00, 0x00])
      result @?= Just (0x10000, BS.empty)
  , testCase "decode 0xFFFFFFFF" $ do
      let result = decodeBigSize (BS.pack [0xFE, 0xFF, 0xFF, 0xFF, 0xFF])
      result @?= Just (0xFFFFFFFF, BS.empty)
  , testCase "decode 0x100000000" $ do
      let result = decodeBigSize $
            BS.pack [0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
      result @?= Just (0x100000000, BS.empty)
  , testCase "reject non-canonical 0xFD encoding of small value" $ do
      -- 0x00FC encoded as 0xFD 0x00 0xFC should be rejected
      let result = decodeBigSize (BS.pack [0xFD, 0x00, 0xFC])
      result @?= Nothing
  , testCase "reject non-canonical 0xFE encoding of small value" $ do
      -- 0x0000FFFF encoded with 0xFE should be rejected
      let result = decodeBigSize (BS.pack [0xFE, 0x00, 0x00, 0xFF, 0xFF])
      result @?= Nothing
  , testCase "bigSizeLen" $ do
      bigSizeLen 0 @?= 1
      bigSizeLen 0xFC @?= 1
      bigSizeLen 0xFD @?= 3
      bigSizeLen 0xFFFF @?= 3
      bigSizeLen 0x10000 @?= 5
      bigSizeLen 0xFFFFFFFF @?= 5
      bigSizeLen 0x100000000 @?= 9
  ]

bigsizeRoundtripProp :: TestTree
bigsizeRoundtripProp = testProperty "roundtrip" $ \n ->
  let encoded = encodeBigSize n
      decoded = decodeBigSize encoded
  in  decoded == Just (n, BS.empty)

-- TLV tests ----------------------------------------------------------------

tlvTests :: TestTree
tlvTests = testGroup "encoding/decoding" [
    testCase "single record" $ do
      let rec = TlvRecord 2 (BS.pack [0x01, 0x02, 0x03])
          encoded = encodeTlv rec
          decoded = decodeTlv encoded
      decoded @?= Just (rec, BS.empty)
  , testCase "stream roundtrip" $ do
      let recs = [ TlvRecord 2 (BS.pack [0x01])
                 , TlvRecord 4 (BS.pack [0x02, 0x03])
                 , TlvRecord 100 (BS.pack [0x04, 0x05, 0x06])
                 ]
          encoded = encodeTlvStream recs
          decoded = decodeTlvStream encoded
      decoded @?= Just recs
  , testCase "reject out-of-order types" $ do
      -- Manually construct out-of-order stream
      let rec1 = encodeTlv (TlvRecord 4 (BS.pack [0x01]))
          rec2 = encodeTlv (TlvRecord 2 (BS.pack [0x02]))
          badStream = rec1 <> rec2
          decoded = decodeTlvStream badStream
      decoded @?= Nothing
  , testCase "reject duplicate types" $ do
      let rec1 = encodeTlv (TlvRecord 2 (BS.pack [0x01]))
          rec2 = encodeTlv (TlvRecord 2 (BS.pack [0x02]))
          badStream = rec1 <> rec2
          decoded = decodeTlvStream badStream
      decoded @?= Nothing
  , testCase "empty stream" $ do
      let decoded = decodeTlvStream BS.empty
      decoded @?= Just []
  ]

-- ShortChannelId tests -----------------------------------------------------

sciTests :: TestTree
sciTests = testGroup "encoding/decoding" [
    testCase "known value" $ do
      let sci = ShortChannelId 700000 1234 5
          encoded = encodeShortChannelId sci
      BS.length encoded @?= 8
      let decoded = decodeShortChannelId encoded
      decoded @?= Just sci
  , testCase "maximum values" $ do
      -- Max 3-byte block (0xFFFFFF), max 3-byte tx (0xFFFFFF), max output
      let sci = ShortChannelId 0xFFFFFF 0xFFFFFF 0xFFFF
          encoded = encodeShortChannelId sci
      BS.length encoded @?= 8
      let decoded = decodeShortChannelId encoded
      decoded @?= Just sci
  , testCase "zero values" $ do
      let sci = ShortChannelId 0 0 0
          encoded = encodeShortChannelId sci
          expected = BS.pack [0, 0, 0, 0, 0, 0, 0, 0]
      encoded @?= expected
      let decoded = decodeShortChannelId encoded
      decoded @?= Just sci
  , testCase "reject wrong length" $ do
      let decoded = decodeShortChannelId (BS.pack [0, 1, 2, 3, 4, 5, 6])
      decoded @?= Nothing
  ]

-- OnionPacket tests --------------------------------------------------------

onionPacketTests :: TestTree
onionPacketTests = testGroup "encoding/decoding" [
    testCase "roundtrip" $ do
      let packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey = BS.replicate 33 0xAB
            , opHopPayloads = BS.replicate 1300 0xCD
            , opHmac = BS.replicate 32 0xEF
            }
          encoded = encodeOnionPacket packet
      BS.length encoded @?= onionPacketSize
      let decoded = decodeOnionPacket encoded
      decoded @?= Just packet
  , testCase "reject wrong size" $ do
      let decoded = decodeOnionPacket (BS.replicate 1000 0x00)
      decoded @?= Nothing
  ]

-- Prim tests -----------------------------------------------------------------

-- BOLT4 spec test vectors using session key 0x4141...41 (32 bytes of 0x41).
sessionKey :: BS.ByteString
sessionKey = BS.replicate 32 0x41

hop0PubKeyHex :: BS.ByteString
hop0PubKeyHex =
  "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"

hop0SharedSecretHex :: BS.ByteString
hop0SharedSecretHex =
  "53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66"

hop0BlindingFactorHex :: BS.ByteString
hop0BlindingFactorHex =
  "2ec2e5da605776054187180343287683aa6a51b4b1c04d6dd49c45d8cffb3c36"

-- Parse hex helper
fromHex :: BS.ByteString -> BS.ByteString
fromHex h = case B16.decode h of
  Just bs -> bs
  Nothing -> error "fromHex: invalid hex"

primTests :: TestTree
primTests = testGroup "cryptographic primitives" [
    testSharedSecret
  , testBlindingFactor
  , testKeyDerivation
  , testBlindPubKey
  , testGenerateStream
  , testHmacOperations
  ]

testSharedSecret :: TestTree
testSharedSecret = testCase "computeSharedSecret (BOLT4 spec hop 0)" $ do
  let Just pubKey = Secp256k1.parse_point (fromHex hop0PubKeyHex)
  case computeSharedSecret sessionKey pubKey of
    Nothing -> assertFailure "computeSharedSecret returned Nothing"
    Just (SharedSecret computed) -> do
      let expected = fromHex hop0SharedSecretHex
      computed @?= expected

testBlindingFactor :: TestTree
testBlindingFactor = testCase "computeBlindingFactor (BOLT4 spec hop 0)" $ do
  let Just sk = Secp256k1.roll32 sessionKey
      Just ephemPubKey = Secp256k1.derive_pub sk
      Just nodePubKey = Secp256k1.parse_point (fromHex hop0PubKeyHex)
  case computeSharedSecret sessionKey nodePubKey of
    Nothing -> assertFailure "computeSharedSecret returned Nothing"
    Just sharedSecret -> do
      let BlindingFactor computed =
            computeBlindingFactor ephemPubKey sharedSecret
          expected = fromHex hop0BlindingFactorHex
      computed @?= expected

testKeyDerivation :: TestTree
testKeyDerivation = testGroup "key derivation" [
    testCase "deriveRho produces 32 bytes" $ do
      let ss = SharedSecret (BS.replicate 32 0)
          DerivedKey rho = deriveRho ss
      BS.length rho @?= 32
  , testCase "deriveMu produces 32 bytes" $ do
      let ss = SharedSecret (BS.replicate 32 0)
          DerivedKey mu = deriveMu ss
      BS.length mu @?= 32
  , testCase "deriveUm produces 32 bytes" $ do
      let ss = SharedSecret (BS.replicate 32 0)
          DerivedKey um = deriveUm ss
      BS.length um @?= 32
  , testCase "derivePad produces 32 bytes" $ do
      let ss = SharedSecret (BS.replicate 32 0)
          DerivedKey pad = derivePad ss
      BS.length pad @?= 32
  , testCase "deriveAmmag produces 32 bytes" $ do
      let ss = SharedSecret (BS.replicate 32 0)
          DerivedKey ammag = deriveAmmag ss
      BS.length ammag @?= 32
  , testCase "different key types produce different results" $ do
      let ss = SharedSecret (BS.replicate 32 0x42)
          DerivedKey rho = deriveRho ss
          DerivedKey mu = deriveMu ss
          DerivedKey um = deriveUm ss
      assertBool "rho /= mu" (rho /= mu)
      assertBool "mu /= um" (mu /= um)
      assertBool "rho /= um" (rho /= um)
  ]

testBlindPubKey :: TestTree
testBlindPubKey = testGroup "key blinding" [
    testCase "blindPubKey produces valid key" $ do
      let Just sk = Secp256k1.roll32 sessionKey
          Just pubKey = Secp256k1.derive_pub sk
          bf = BlindingFactor (fromHex hop0BlindingFactorHex)
      case blindPubKey pubKey bf of
        Nothing -> assertFailure "blindPubKey returned Nothing"
        Just _blinded -> return ()
  , testCase "blindSecKey produces valid key" $ do
      let bf = BlindingFactor (fromHex hop0BlindingFactorHex)
      case blindSecKey sessionKey bf of
        Nothing -> assertFailure "blindSecKey returned Nothing"
        Just _blinded -> return ()
  ]

testGenerateStream :: TestTree
testGenerateStream = testGroup "generateStream" [
    testCase "produces correct length" $ do
      let dk = DerivedKey (BS.replicate 32 0)
          stream = generateStream dk 100
      BS.length stream @?= 100
  , testCase "1300-byte stream for hop_payloads" $ do
      let dk = DerivedKey (BS.replicate 32 0x42)
          stream = generateStream dk 1300
      BS.length stream @?= 1300
  , testCase "deterministic output" $ do
      let dk = DerivedKey (BS.replicate 32 0x55)
          stream1 = generateStream dk 64
          stream2 = generateStream dk 64
      stream1 @?= stream2
  ]

testHmacOperations :: TestTree
testHmacOperations = testGroup "HMAC operations" [
    testCase "computeHmac produces 32 bytes" $ do
      let dk = DerivedKey (BS.replicate 32 0)
          hmac = computeHmac dk "payloads" "assocdata"
      BS.length hmac @?= 32
  , testCase "verifyHmac succeeds for matching" $ do
      let dk = DerivedKey (BS.replicate 32 0)
          hmac = computeHmac dk "payloads" "assocdata"
      assertBool "verifyHmac should succeed" (verifyHmac hmac hmac)
  , testCase "verifyHmac fails for different" $ do
      let dk = DerivedKey (BS.replicate 32 0)
          hmac1 = computeHmac dk "payloads1" "assocdata"
          hmac2 = computeHmac dk "payloads2" "assocdata"
      assertBool "verifyHmac should fail" (not $ verifyHmac hmac1 hmac2)
  , testCase "verifyHmac fails for different lengths" $ do
      assertBool "verifyHmac should fail"
        (not $ verifyHmac "short" "different length")
  ]

-- Process tests -------------------------------------------------------------

processTests :: TestTree
processTests = testGroup "packet processing" [
    testVersionValidation
  , testEphemeralKeyValidation
  , testHmacValidation
  , testProcessBasic
  ]

testVersionValidation :: TestTree
testVersionValidation = testGroup "version validation" [
    testCase "reject invalid version 0x01" $ do
      let packet = OnionPacket
            { opVersion = 0x01  -- Invalid, should be 0x00
            , opEphemeralKey = BS.replicate 33 0x02
            , opHopPayloads = BS.replicate 1300 0x00
            , opHmac = BS.replicate 32 0x00
            }
      case process sessionKey packet BS.empty of
        Left (InvalidVersion v) -> v @?= 0x01
        Left other -> assertFailure $ "expected InvalidVersion, got: " ++ show other
        Right _ -> assertFailure "expected rejection, got success"
  , testCase "reject invalid version 0xFF" $ do
      let packet = OnionPacket
            { opVersion = 0xFF
            , opEphemeralKey = BS.replicate 33 0x02
            , opHopPayloads = BS.replicate 1300 0x00
            , opHmac = BS.replicate 32 0x00
            }
      case process sessionKey packet BS.empty of
        Left (InvalidVersion v) -> v @?= 0xFF
        Left other -> assertFailure $ "expected InvalidVersion, got: " ++ show other
        Right _ -> assertFailure "expected rejection, got success"
  ]

testEphemeralKeyValidation :: TestTree
testEphemeralKeyValidation = testGroup "ephemeral key validation" [
    testCase "reject invalid ephemeral key (all zeros)" $ do
      let packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey = BS.replicate 33 0x00  -- Invalid pubkey
            , opHopPayloads = BS.replicate 1300 0x00
            , opHmac = BS.replicate 32 0x00
            }
      case process sessionKey packet BS.empty of
        Left InvalidEphemeralKey -> return ()
        Left other -> assertFailure $ "expected InvalidEphemeralKey, got: "
          ++ show other
        Right _ -> assertFailure "expected rejection, got success"
  , testCase "reject malformed ephemeral key" $ do
      -- 0x04 prefix is for uncompressed keys, but we only have 33 bytes
      let packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey = BS.pack (0x04 : replicate 32 0xAB)
            , opHopPayloads = BS.replicate 1300 0x00
            , opHmac = BS.replicate 32 0x00
            }
      case process sessionKey packet BS.empty of
        Left InvalidEphemeralKey -> return ()
        Left other -> assertFailure $ "expected InvalidEphemeralKey, got: "
          ++ show other
        Right _ -> assertFailure "expected rejection, got success"
  ]

testHmacValidation :: TestTree
testHmacValidation = testGroup "HMAC validation" [
    testCase "reject invalid HMAC" $ do
      -- Use a valid ephemeral key but wrong HMAC
      let Just hop0PubKey = Secp256k1.parse_point (fromHex hop0PubKeyHex)
          ephKeyBytes = Secp256k1.serialize_point hop0PubKey
          packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey = ephKeyBytes
            , opHopPayloads = BS.replicate 1300 0x00
            , opHmac = BS.replicate 32 0xFF  -- Wrong HMAC
            }
      case process sessionKey packet BS.empty of
        Left HmacMismatch -> return ()
        Left other -> assertFailure $ "expected HmacMismatch, got: "
          ++ show other
        Right _ -> assertFailure "expected rejection, got success"
  ]

-- | Test basic packet processing with a properly constructed packet.
testProcessBasic :: TestTree
testProcessBasic = testGroup "basic processing" [
    testCase "process valid packet (final hop, all-zero next HMAC)" $ do
      -- Construct a valid packet for a final hop
      -- The hop payload needs to be properly formatted TLV
      let Just hop0PubKey = Secp256k1.parse_point (fromHex hop0PubKeyHex)
          ephKeyBytes = Secp256k1.serialize_point hop0PubKey

          -- Create a minimal hop payload TLV
          -- amt_to_forward (type 2) = 1000 msat
          -- outgoing_cltv (type 4) = 500000
          hopPayloadTlv = encodeHopPayload HopPayload
            { hpAmtToForward = Just 1000
            , hpOutgoingCltv = Just 500000
            , hpShortChannelId = Nothing
            , hpPaymentData = Nothing
            , hpEncryptedData = Nothing
            , hpCurrentPathKey = Nothing
            , hpUnknownTlvs = []
            }

          -- Length-prefixed payload followed by all-zero HMAC (final hop)
          payloadLen = BS.length hopPayloadTlv
          lenPrefix = encodeBigSize (fromIntegral payloadLen)
          payloadWithHmac = lenPrefix <> hopPayloadTlv
            <> BS.replicate 32 0x00  -- Zero HMAC = final hop

          -- Pad to 1300 bytes
          padding = BS.replicate (1300 - BS.length payloadWithHmac) 0x00
          rawPayloads = payloadWithHmac <> padding

          -- Compute shared secret and encrypt payloads
          Just ss = computeSharedSecret sessionKey hop0PubKey
          rhoKey = deriveRho ss
          muKey = deriveMu ss

          -- Encrypt: XOR with keystream
          stream = generateStream rhoKey 1300
          encryptedPayloads = BS.pack (BS.zipWith xor rawPayloads stream)

          -- Compute correct HMAC
          correctHmac = computeHmac muKey encryptedPayloads BS.empty

          packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey = ephKeyBytes
            , opHopPayloads = encryptedPayloads
            , opHmac = correctHmac
            }

      case process sessionKey packet BS.empty of
        Left err -> assertFailure $ "expected success, got: " ++ show err
        Right (Receive ri) -> do
          -- Verify we got the payload back
          hpAmtToForward (riPayload ri) @?= Just 1000
          hpOutgoingCltv (riPayload ri) @?= Just 500000
        Right (Forward _) -> assertFailure "expected Receive, got Forward"
  ]

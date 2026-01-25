{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import Lightning.Protocol.BOLT4.Codec
import Lightning.Protocol.BOLT4.Error
import Lightning.Protocol.BOLT4.Prim
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
  , testGroup "Error" [
        errorTests
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

-- Error tests -----------------------------------------------------------------

errorTests :: TestTree
errorTests = testGroup "error handling" [
    testErrorConstruction
  , testErrorRoundtrip
  , testMultiHopWrapping
  , testErrorAttribution
  , testFailureMessageParsing
  ]

-- Shared secrets for testing (deterministic)
testSecret1 :: SharedSecret
testSecret1 = SharedSecret (BS.replicate 32 0x11)

testSecret2 :: SharedSecret
testSecret2 = SharedSecret (BS.replicate 32 0x22)

testSecret3 :: SharedSecret
testSecret3 = SharedSecret (BS.replicate 32 0x33)

testSecret4 :: SharedSecret
testSecret4 = SharedSecret (BS.replicate 32 0x44)

-- Simple failure message for testing
testFailure :: FailureMessage
testFailure = FailureMessage IncorrectOrUnknownPaymentDetails BS.empty []

testErrorConstruction :: TestTree
testErrorConstruction = testCase "error packet construction" $ do
  let errPacket = constructError testSecret1 testFailure
      ErrorPacket bs = errPacket
  -- Error packet should be at least minErrorPacketSize
  assertBool "error packet >= 256 bytes" (BS.length bs >= minErrorPacketSize)

testErrorRoundtrip :: TestTree
testErrorRoundtrip = testCase "construct and unwrap roundtrip" $ do
  let errPacket = constructError testSecret1 testFailure
      result = unwrapError [testSecret1] errPacket
  case result of
    Attributed idx msg -> do
      idx @?= 0
      fmCode msg @?= IncorrectOrUnknownPaymentDetails
    UnknownOrigin _ ->
      assertFailure "Expected Attributed, got UnknownOrigin"

testMultiHopWrapping :: TestTree
testMultiHopWrapping = testGroup "multi-hop wrapping" [
    testCase "3-hop route, error from hop 2 (final)" $ do
      -- Route: origin -> hop0 -> hop1 -> hop2 (final, fails)
      -- Error constructed at hop2, wrapped at hop1, wrapped at hop0
      let secrets = [testSecret1, testSecret2, testSecret3]
          -- Hop 2 constructs error
          err0 = constructError testSecret3 testFailure
          -- Hop 1 wraps
          err1 = wrapError testSecret2 err0
          -- Hop 0 wraps
          err2 = wrapError testSecret1 err1
          -- Origin unwraps
          result = unwrapError secrets err2
      case result of
        Attributed idx msg -> do
          idx @?= 2
          fmCode msg @?= IncorrectOrUnknownPaymentDetails
        UnknownOrigin _ ->
          assertFailure "Expected Attributed, got UnknownOrigin"

  , testCase "4-hop route, error from hop 1 (intermediate)" $ do
      -- Route: origin -> hop0 -> hop1 (fails) -> hop2 -> hop3
      let secrets = [testSecret1, testSecret2, testSecret3, testSecret4]
          -- Hop 1 constructs error
          err0 = constructError testSecret2 testFailure
          -- Hop 0 wraps
          err1 = wrapError testSecret1 err0
          -- Origin unwraps
          result = unwrapError secrets err1
      case result of
        Attributed idx msg -> do
          idx @?= 1
          fmCode msg @?= IncorrectOrUnknownPaymentDetails
        UnknownOrigin _ ->
          assertFailure "Expected Attributed, got UnknownOrigin"

  , testCase "4-hop route, error from hop 0 (first)" $ do
      let secrets = [testSecret1, testSecret2, testSecret3, testSecret4]
          -- Hop 0 constructs error (no wrapping needed)
          err0 = constructError testSecret1 testFailure
          -- Origin unwraps
          result = unwrapError secrets err0
      case result of
        Attributed idx msg -> do
          idx @?= 0
          fmCode msg @?= IncorrectOrUnknownPaymentDetails
        UnknownOrigin _ ->
          assertFailure "Expected Attributed, got UnknownOrigin"
  ]

testErrorAttribution :: TestTree
testErrorAttribution = testGroup "error attribution" [
    testCase "wrong secrets gives UnknownOrigin" $ do
      let err = constructError testSecret1 testFailure
          wrongSecrets = [testSecret2, testSecret3]
          result = unwrapError wrongSecrets err
      case result of
        UnknownOrigin _ -> return ()
        Attributed _ _ ->
          assertFailure "Expected UnknownOrigin with wrong secrets"

  , testCase "empty secrets gives UnknownOrigin" $ do
      let err = constructError testSecret1 testFailure
          result = unwrapError [] err
      case result of
        UnknownOrigin _ -> return ()
        Attributed _ _ ->
          assertFailure "Expected UnknownOrigin with empty secrets"

  , testCase "correct attribution with multiple failures" $ do
      -- Test different failure codes
      let failures =
            [ (TemporaryNodeFailure, testSecret1)
            , (PermanentNodeFailure, testSecret2)
            , (InvalidOnionHmac, testSecret3)
            ]
      mapM_ (\(code, secret) -> do
        let failure = FailureMessage code BS.empty []
            err = constructError secret failure
            result = unwrapError [secret] err
        case result of
          Attributed 0 msg -> fmCode msg @?= code
          _ -> assertFailure $ "Failed for code: " ++ show code
        ) failures
  ]

testFailureMessageParsing :: TestTree
testFailureMessageParsing = testGroup "failure message parsing" [
    testCase "code with data" $ do
      -- AmountBelowMinimum typically includes channel update data
      let failData = BS.replicate 10 0xAB
          failure = FailureMessage AmountBelowMinimum failData []
          err = constructError testSecret1 failure
          result = unwrapError [testSecret1] err
      case result of
        Attributed 0 msg -> do
          fmCode msg @?= AmountBelowMinimum
          fmData msg @?= failData
        _ -> assertFailure "Expected Attributed"

  , testCase "various failure codes roundtrip" $ do
      let codes =
            [ InvalidRealm
            , TemporaryNodeFailure
            , PermanentNodeFailure
            , InvalidOnionHmac
            , TemporaryChannelFailure
            , IncorrectOrUnknownPaymentDetails
            ]
      mapM_ (\code -> do
        let failure = FailureMessage code BS.empty []
            err = constructError testSecret1 failure
            result = unwrapError [testSecret1] err
        case result of
          Attributed 0 msg -> fmCode msg @?= code
          _ -> assertFailure $ "Failed for code: " ++ show code
        ) codes
  ]

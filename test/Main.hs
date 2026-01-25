{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import Lightning.Protocol.BOLT4.Codec
import Lightning.Protocol.BOLT4.Construct
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
  , testGroup "Construct" [
        constructTests
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

-- Construct tests ------------------------------------------------------------

-- Test vectors from BOLT4 spec
hop1PubKeyHex :: BS.ByteString
hop1PubKeyHex =
  "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"

hop2PubKeyHex :: BS.ByteString
hop2PubKeyHex =
  "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007"

hop3PubKeyHex :: BS.ByteString
hop3PubKeyHex =
  "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"

hop4PubKeyHex :: BS.ByteString
hop4PubKeyHex =
  "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145"

-- Expected shared secrets from BOLT4 error test vectors (in route order)
hop1SharedSecretHex :: BS.ByteString
hop1SharedSecretHex =
  "a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae"

hop2SharedSecretHex :: BS.ByteString
hop2SharedSecretHex =
  "3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc"

hop3SharedSecretHex :: BS.ByteString
hop3SharedSecretHex =
  "21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d"

hop4SharedSecretHex :: BS.ByteString
hop4SharedSecretHex =
  "b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328"

constructTests :: TestTree
constructTests = testGroup "packet construction" [
    testConstructErrorCases
  , testSharedSecretComputation
  , testPacketStructure
  , testSingleHop
  ]

testConstructErrorCases :: TestTree
testConstructErrorCases = testGroup "error cases" [
    testCase "rejects invalid session key (too short)" $ do
      let result = construct (BS.replicate 31 0x41) [] ""
      case result of
        Left InvalidSessionKey -> return ()
        _ -> assertFailure "Expected InvalidSessionKey"
  , testCase "rejects invalid session key (too long)" $ do
      let result = construct (BS.replicate 33 0x41) [] ""
      case result of
        Left InvalidSessionKey -> return ()
        _ -> assertFailure "Expected InvalidSessionKey"
  , testCase "rejects empty route" $ do
      let result = construct sessionKey [] ""
      case result of
        Left EmptyRoute -> return ()
        _ -> assertFailure "Expected EmptyRoute"
  , testCase "rejects too many hops" $ do
      let Just pub = Secp256k1.parse_point (fromHex hop0PubKeyHex)
          emptyPayload = HopPayload Nothing Nothing Nothing Nothing
                           Nothing Nothing []
          hop = Hop pub emptyPayload
          hops = replicate 21 hop
          result = construct sessionKey hops ""
      case result of
        Left TooManyHops -> return ()
        _ -> assertFailure "Expected TooManyHops"
  ]

testSharedSecretComputation :: TestTree
testSharedSecretComputation =
  testCase "computes correct shared secrets (BOLT4 spec)" $ do
    let Just pub0 = Secp256k1.parse_point (fromHex hop0PubKeyHex)
        Just pub1 = Secp256k1.parse_point (fromHex hop1PubKeyHex)
        Just pub2 = Secp256k1.parse_point (fromHex hop2PubKeyHex)
        Just pub3 = Secp256k1.parse_point (fromHex hop3PubKeyHex)
        Just pub4 = Secp256k1.parse_point (fromHex hop4PubKeyHex)
        emptyPayload = HopPayload Nothing Nothing Nothing Nothing
                         Nothing Nothing []
        hops = [ Hop pub0 emptyPayload
               , Hop pub1 emptyPayload
               , Hop pub2 emptyPayload
               , Hop pub3 emptyPayload
               , Hop pub4 emptyPayload
               ]
        result = construct sessionKey hops ""
    case result of
      Left err -> assertFailure $ "construct failed: " ++ show err
      Right (_, secrets) -> do
        length secrets @?= 5
        let [SharedSecret ss0, SharedSecret ss1, SharedSecret ss2,
             SharedSecret ss3, SharedSecret ss4] = secrets
        ss0 @?= fromHex hop0SharedSecretHex
        ss1 @?= fromHex hop1SharedSecretHex
        ss2 @?= fromHex hop2SharedSecretHex
        ss3 @?= fromHex hop3SharedSecretHex
        ss4 @?= fromHex hop4SharedSecretHex

testPacketStructure :: TestTree
testPacketStructure = testCase "produces valid packet structure" $ do
  let Just pub0 = Secp256k1.parse_point (fromHex hop0PubKeyHex)
      Just pub1 = Secp256k1.parse_point (fromHex hop1PubKeyHex)
      emptyPayload = HopPayload Nothing Nothing Nothing Nothing
                       Nothing Nothing []
      hops = [Hop pub0 emptyPayload, Hop pub1 emptyPayload]
      result = construct sessionKey hops ""
  case result of
    Left err -> assertFailure $ "construct failed: " ++ show err
    Right (packet, _) -> do
      opVersion packet @?= versionByte
      BS.length (opEphemeralKey packet) @?= pubkeySize
      BS.length (opHopPayloads packet) @?= hopPayloadsSize
      BS.length (opHmac packet) @?= hmacSize
      -- The ephemeral key should be the public key derived from session key
      let Just sk = Secp256k1.roll32 sessionKey
          Just expectedPub = Secp256k1.derive_pub sk
          expectedPubBytes = Secp256k1.serialize_point expectedPub
      opEphemeralKey packet @?= expectedPubBytes

testSingleHop :: TestTree
testSingleHop = testCase "constructs single-hop packet" $ do
  let Just pub0 = Secp256k1.parse_point (fromHex hop0PubKeyHex)
      payload = HopPayload
        { hpAmtToForward = Just 1000
        , hpOutgoingCltv = Just 500000
        , hpShortChannelId = Nothing
        , hpPaymentData = Nothing
        , hpEncryptedData = Nothing
        , hpCurrentPathKey = Nothing
        , hpUnknownTlvs = []
        }
      hops = [Hop pub0 payload]
      result = construct sessionKey hops ""
  case result of
    Left err -> assertFailure $ "construct failed: " ++ show err
    Right (packet, secrets) -> do
      length secrets @?= 1
      -- Packet should be valid structure
      let encoded = encodeOnionPacket packet
      BS.length encoded @?= onionPacketSize
      -- Should decode back
      let Just decoded = decodeOnionPacket encoded
      decoded @?= packet

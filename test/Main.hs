{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import Data.Word (Word8, Word16, Word32)
import Lightning.Protocol.BOLT4.Blinding
import Lightning.Protocol.BOLT4.Codec
import Lightning.Protocol.BOLT4.Construct
import Lightning.Protocol.BOLT4.Error
import Lightning.Protocol.BOLT4.Internal
import Lightning.Protocol.BOLT4.Prim
import Lightning.Protocol.BOLT4.Process
import Lightning.Protocol.BOLT4.Types
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

-- | Demand a Just value in IO, failing the test on Nothing.
demand :: String -> Maybe a -> IO a
demand _ (Just a) = pure a
demand msg Nothing = assertFailure msg

-- | Construct a ShortChannelId, failing if invalid.
assertScid :: Word32 -> Word32 -> Word16
           -> IO ShortChannelId
assertScid b t o = demand "shortChannelId" (shortChannelId b t o)

-- | Construct a ShortChannelId for test fixtures.
mkScid :: Word32 -> Word32 -> Word16 -> ShortChannelId
mkScid b t o = case shortChannelId b t o of
  Just s  -> s
  Nothing -> error "mkScid: invalid test fixture"

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
  , testGroup "Process" [
        processTests
      ]
  , testGroup "Error" [
        errorTests
      ]
  , testGroup "properties" [
        propertyTests
      ]
  , testGroup "Blinding" [
        blindingKeyDerivationTests
      , blindingEphemeralKeyTests
      , blindingTlvTests
      , blindingEncryptionTests
      , blindingCreatePathTests
      , blindingProcessHopTests
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
      encodeBigSize 0x10000 @?=
        BS.pack [0xFE, 0x00, 0x01, 0x00, 0x00]
  , testCase "0xFFFFFFFF" $
      encodeBigSize 0xFFFFFFFF @?=
        BS.pack [0xFE, 0xFF, 0xFF, 0xFF, 0xFF]
  , testCase "0x100000000" $
      encodeBigSize 0x100000000 @?=
        BS.pack [0xFF, 0x00, 0x00, 0x00, 0x01,
                 0x00, 0x00, 0x00, 0x00]
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
      let result = decodeBigSize $
            BS.pack [0xFE, 0x00, 0x01, 0x00, 0x00]
      result @?= Just (0x10000, BS.empty)
  , testCase "decode 0xFFFFFFFF" $ do
      let result = decodeBigSize $
            BS.pack [0xFE, 0xFF, 0xFF, 0xFF, 0xFF]
      result @?= Just (0xFFFFFFFF, BS.empty)
  , testCase "decode 0x100000000" $ do
      let result = decodeBigSize $
            BS.pack [0xFF, 0x00, 0x00, 0x00, 0x01,
                     0x00, 0x00, 0x00, 0x00]
      result @?= Just (0x100000000, BS.empty)
  , testCase "reject non-canonical 0xFD encoding" $ do
      let result = decodeBigSize (BS.pack [0xFD, 0x00, 0xFC])
      result @?= Nothing
  , testCase "reject non-canonical 0xFE encoding" $ do
      let result = decodeBigSize $
            BS.pack [0xFE, 0x00, 0x00, 0xFF, 0xFF]
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
      sci <- assertScid 700000 1234 5
      let encoded = encodeShortChannelId sci
      BS.length encoded @?= 8
      let decoded = decodeShortChannelId encoded
      decoded @?= Just sci
  , testCase "maximum values" $ do
      sci <- assertScid 0xFFFFFF 0xFFFFFF 0xFFFF
      let encoded = encodeShortChannelId sci
      BS.length encoded @?= 8
      let decoded = decodeShortChannelId encoded
      decoded @?= Just sci
  , testCase "zero values" $ do
      sci <- assertScid 0 0 0
      let encoded = encodeShortChannelId sci
          expected = BS.pack [0, 0, 0, 0, 0, 0, 0, 0]
      encoded @?= expected
      let decoded = decodeShortChannelId encoded
      decoded @?= Just sci
  , testCase "reject wrong length" $ do
      let decoded =
            decodeShortChannelId (BS.pack [0, 1, 2, 3, 4, 5, 6])
      decoded @?= Nothing
  ]

-- OnionPacket tests --------------------------------------------------------

onionPacketTests :: TestTree
onionPacketTests = testGroup "encoding/decoding" [
    testCase "roundtrip" $ do
      let packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey = BS.replicate 33 0xAB
            , opHopPayloads =
                unsafeHopPayloads (BS.replicate 1300 0xCD)
            , opHmac = unsafeHmac32 (BS.replicate 32 0xEF)
            }
          encoded = encodeOnionPacket packet
      BS.length encoded @?= onionPacketSize
      let decoded = decodeOnionPacket encoded
      decoded @?= Just packet
  , testCase "reject wrong size" $ do
      let decoded =
            decodeOnionPacket (BS.replicate 1000 0x00)
      decoded @?= Nothing
  ]

-- Prim tests ---------------------------------------------------------------

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
testSharedSecret =
  testCase "computeSharedSecret (BOLT4 spec hop 0)" $ do
    pubKey <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop0PubKeyHex)
    case computeSharedSecret sessionKey pubKey of
      Nothing ->
        assertFailure "computeSharedSecret returned Nothing"
      Just (SharedSecret computed) -> do
        let expected = fromHex hop0SharedSecretHex
        computed @?= expected

testBlindingFactor :: TestTree
testBlindingFactor =
  testCase "computeBlindingFactor (BOLT4 spec hop 0)" $ do
    sk <- demand "roll32" $ Secp256k1.roll32 sessionKey
    ephemPubKey <- demand "derive_pub" $
      Secp256k1.derive_pub sk
    nodePubKey <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop0PubKeyHex)
    case computeSharedSecret sessionKey nodePubKey of
      Nothing ->
        assertFailure "computeSharedSecret returned Nothing"
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
      sk <- demand "roll32" $ Secp256k1.roll32 sessionKey
      pubKey <- demand "derive_pub" $ Secp256k1.derive_pub sk
      let bf = BlindingFactor (fromHex hop0BlindingFactorHex)
      case blindPubKey pubKey bf of
        Nothing ->
          assertFailure "blindPubKey returned Nothing"
        Just _blinded -> return ()
  , testCase "blindSecKey produces valid key" $ do
      let bf = BlindingFactor (fromHex hop0BlindingFactorHex)
      case blindSecKey sessionKey bf of
        Nothing ->
          assertFailure "blindSecKey returned Nothing"
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
          hm = computeHmac dk "payloads" "assocdata"
      BS.length hm @?= 32
  , testCase "verifyHmac succeeds for matching" $ do
      let dk = DerivedKey (BS.replicate 32 0)
          hm = computeHmac dk "payloads" "assocdata"
      assertBool "verifyHmac should succeed"
        (verifyHmac hm hm)
  , testCase "verifyHmac fails for different" $ do
      let dk = DerivedKey (BS.replicate 32 0)
          hm1 = computeHmac dk "payloads1" "assocdata"
          hm2 = computeHmac dk "payloads2" "assocdata"
      assertBool "verifyHmac should fail"
        (not $ verifyHmac hm1 hm2)
  , testCase "verifyHmac fails for different lengths" $ do
      assertBool "verifyHmac should fail"
        (not $ verifyHmac "short" "different length")
  ]

-- Construct tests ----------------------------------------------------------

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

-- Expected shared secrets from BOLT4 error test vectors
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
      pub <- demand "parse_point" $
        Secp256k1.parse_point (fromHex hop0PubKeyHex)
      let emptyPayload = HopPayload Nothing Nothing Nothing
                           Nothing Nothing Nothing []
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
    pub0 <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop0PubKeyHex)
    pub1 <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop1PubKeyHex)
    pub2 <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop2PubKeyHex)
    pub3 <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop3PubKeyHex)
    pub4 <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop4PubKeyHex)
    let emptyPayload = HopPayload Nothing Nothing Nothing
                         Nothing Nothing Nothing []
        hops = [ Hop pub0 emptyPayload
               , Hop pub1 emptyPayload
               , Hop pub2 emptyPayload
               , Hop pub3 emptyPayload
               , Hop pub4 emptyPayload
               ]
        result = construct sessionKey hops ""
    case result of
      Left err ->
        assertFailure $ "construct failed: " ++ show err
      Right (_, secrets) -> case secrets of
        [SharedSecret ss0, SharedSecret ss1,
         SharedSecret ss2, SharedSecret ss3,
         SharedSecret ss4] -> do
          ss0 @?= fromHex hop0SharedSecretHex
          ss1 @?= fromHex hop1SharedSecretHex
          ss2 @?= fromHex hop2SharedSecretHex
          ss3 @?= fromHex hop3SharedSecretHex
          ss4 @?= fromHex hop4SharedSecretHex
        _ -> assertFailure "expected 5 shared secrets"

testPacketStructure :: TestTree
testPacketStructure =
  testCase "produces valid packet structure" $ do
    pub0 <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop0PubKeyHex)
    pub1 <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop1PubKeyHex)
    let emptyPayload = HopPayload Nothing Nothing Nothing
                         Nothing Nothing Nothing []
        hops = [Hop pub0 emptyPayload,
                Hop pub1 emptyPayload]
        result = construct sessionKey hops ""
    case result of
      Left err ->
        assertFailure $ "construct failed: " ++ show err
      Right (packet, _) -> do
        opVersion packet @?= versionByte
        BS.length (opEphemeralKey packet) @?= pubkeySize
        BS.length (unHopPayloads (opHopPayloads packet))
          @?= hopPayloadsSize
        BS.length (unHmac32 (opHmac packet)) @?= hmacSize
        sk <- demand "roll32" $ Secp256k1.roll32 sessionKey
        expectedPub <- demand "derive_pub" $
          Secp256k1.derive_pub sk
        let expectedPubBytes =
              Secp256k1.serialize_point expectedPub
        opEphemeralKey packet @?= expectedPubBytes

testSingleHop :: TestTree
testSingleHop =
  testCase "constructs single-hop packet" $ do
    pub0 <- demand "parse_point" $
      Secp256k1.parse_point (fromHex hop0PubKeyHex)
    let payload = HopPayload
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
      Left err ->
        assertFailure $ "construct failed: " ++ show err
      Right (packet, secrets) -> do
        length secrets @?= 1
        -- Packet should be valid structure
        let encoded = encodeOnionPacket packet
        BS.length encoded @?= onionPacketSize
        -- Should decode back
        decoded <- demand "decodeOnionPacket" $
          decodeOnionPacket encoded
        decoded @?= packet

-- Process tests -----------------------------------------------------------

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
            { opVersion = 0x01
            , opEphemeralKey = BS.replicate 33 0x02
            , opHopPayloads =
                unsafeHopPayloads (BS.replicate 1300 0x00)
            , opHmac =
                unsafeHmac32 (BS.replicate 32 0x00)
            }
      case process sessionKey packet BS.empty of
        Left (InvalidVersion v) -> v @?= 0x01
        Left other ->
          assertFailure $ "expected InvalidVersion, got: "
            ++ show other
        Right _ ->
          assertFailure "expected rejection, got success"
  , testCase "reject invalid version 0xFF" $ do
      let packet = OnionPacket
            { opVersion = 0xFF
            , opEphemeralKey = BS.replicate 33 0x02
            , opHopPayloads =
                unsafeHopPayloads (BS.replicate 1300 0x00)
            , opHmac =
                unsafeHmac32 (BS.replicate 32 0x00)
            }
      case process sessionKey packet BS.empty of
        Left (InvalidVersion v) -> v @?= 0xFF
        Left other ->
          assertFailure $ "expected InvalidVersion, got: "
            ++ show other
        Right _ ->
          assertFailure "expected rejection, got success"
  ]

testEphemeralKeyValidation :: TestTree
testEphemeralKeyValidation =
  testGroup "ephemeral key validation" [
    testCase "reject invalid ephemeral key (all zeros)" $ do
      let packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey = BS.replicate 33 0x00
            , opHopPayloads =
                unsafeHopPayloads (BS.replicate 1300 0x00)
            , opHmac =
                unsafeHmac32 (BS.replicate 32 0x00)
            }
      case process sessionKey packet BS.empty of
        Left InvalidEphemeralKey -> return ()
        Left other ->
          assertFailure $
            "expected InvalidEphemeralKey, got: "
              ++ show other
        Right _ ->
          assertFailure "expected rejection, got success"
  , testCase "reject malformed ephemeral key" $ do
      let packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey =
                BS.pack (0x04 : replicate 32 0xAB)
            , opHopPayloads =
                unsafeHopPayloads (BS.replicate 1300 0x00)
            , opHmac =
                unsafeHmac32 (BS.replicate 32 0x00)
            }
      case process sessionKey packet BS.empty of
        Left InvalidEphemeralKey -> return ()
        Left other ->
          assertFailure $
            "expected InvalidEphemeralKey, got: "
              ++ show other
        Right _ ->
          assertFailure "expected rejection, got success"
  ]

testHmacValidation :: TestTree
testHmacValidation = testGroup "HMAC validation" [
    testCase "reject invalid HMAC" $ do
      hop0PubKey <- demand "parse_point" $
        Secp256k1.parse_point (fromHex hop0PubKeyHex)
      let ephKeyBytes =
            Secp256k1.serialize_point hop0PubKey
          packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey = ephKeyBytes
            , opHopPayloads =
                unsafeHopPayloads (BS.replicate 1300 0x00)
            , opHmac =
                unsafeHmac32 (BS.replicate 32 0xFF)
            }
      case process sessionKey packet BS.empty of
        Left HmacMismatch -> return ()
        Left other ->
          assertFailure $ "expected HmacMismatch, got: "
            ++ show other
        Right _ ->
          assertFailure "expected rejection, got success"
  ]

-- | Test basic packet processing with a properly constructed
--   packet.
testProcessBasic :: TestTree
testProcessBasic = testGroup "basic processing" [
    testCase "process valid packet (final hop)" $ do
      hop0PubKey <- demand "parse_point" $
        Secp256k1.parse_point (fromHex hop0PubKeyHex)
      let ephKeyBytes =
            Secp256k1.serialize_point hop0PubKey
          hopPayloadTlv = encodeHopPayload HopPayload
            { hpAmtToForward = Just 1000
            , hpOutgoingCltv = Just 500000
            , hpShortChannelId = Nothing
            , hpPaymentData = Nothing
            , hpEncryptedData = Nothing
            , hpCurrentPathKey = Nothing
            , hpUnknownTlvs = []
            }
          payloadLen = BS.length hopPayloadTlv
          lenPrefix =
            encodeBigSize (fromIntegral payloadLen)
          payloadWithHmac = lenPrefix <> hopPayloadTlv
            <> BS.replicate 32 0x00
          padding = BS.replicate
            (1300 - BS.length payloadWithHmac) 0x00
          rawPayloads = payloadWithHmac <> padding
      ss <- demand "computeSharedSecret" $
        computeSharedSecret sessionKey hop0PubKey
      let rhoKey = deriveRho ss
          muKey = deriveMu ss
          stream = generateStream rhoKey 1300
          encryptedPayloads =
            BS.pack (BS.zipWith xor rawPayloads stream)
          correctHmac =
            computeHmac muKey encryptedPayloads BS.empty
          packet = OnionPacket
            { opVersion = 0x00
            , opEphemeralKey = ephKeyBytes
            , opHopPayloads =
                unsafeHopPayloads encryptedPayloads
            , opHmac = unsafeHmac32 correctHmac
            }

      case process sessionKey packet BS.empty of
        Left err ->
          assertFailure $
            "expected success, got: " ++ show err
        Right (Receive ri) -> do
          hpAmtToForward (riPayload ri) @?= Just 1000
          hpOutgoingCltv (riPayload ri) @?= Just 500000
        Right (Forward _) ->
          assertFailure "expected Receive, got Forward"
  ]

-- Error tests -------------------------------------------------------------

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
testFailure =
  FailureMessage IncorrectOrUnknownPaymentDetails BS.empty []

testErrorConstruction :: TestTree
testErrorConstruction =
  testCase "error packet construction" $ do
    let errPacket = constructError testSecret1 testFailure
        ErrorPacket bs = errPacket
    assertBool "error packet >= 256 bytes"
      (BS.length bs >= minErrorPacketSize)

testErrorRoundtrip :: TestTree
testErrorRoundtrip =
  testCase "construct and unwrap roundtrip" $ do
    let errPacket = constructError testSecret1 testFailure
        result = unwrapError [testSecret1] errPacket
    case result of
      Attributed idx msg -> do
        idx @?= 0
        fmCode msg @?= IncorrectOrUnknownPaymentDetails
      UnknownOrigin _ ->
        assertFailure
          "Expected Attributed, got UnknownOrigin"

testMultiHopWrapping :: TestTree
testMultiHopWrapping = testGroup "multi-hop wrapping" [
    testCase "3-hop route, error from hop 2 (final)" $ do
      let secrets =
            [testSecret1, testSecret2, testSecret3]
          err0 = constructError testSecret3 testFailure
          err1 = wrapError testSecret2 err0
          err2 = wrapError testSecret1 err1
          result = unwrapError secrets err2
      case result of
        Attributed idx msg -> do
          idx @?= 2
          fmCode msg @?= IncorrectOrUnknownPaymentDetails
        UnknownOrigin _ ->
          assertFailure
            "Expected Attributed, got UnknownOrigin"

  , testCase "4-hop route, error from hop 1" $ do
      let secrets = [testSecret1, testSecret2,
                     testSecret3, testSecret4]
          err0 = constructError testSecret2 testFailure
          err1 = wrapError testSecret1 err0
          result = unwrapError secrets err1
      case result of
        Attributed idx msg -> do
          idx @?= 1
          fmCode msg @?= IncorrectOrUnknownPaymentDetails
        UnknownOrigin _ ->
          assertFailure
            "Expected Attributed, got UnknownOrigin"

  , testCase "4-hop route, error from hop 0 (first)" $ do
      let secrets = [testSecret1, testSecret2,
                     testSecret3, testSecret4]
          err0 = constructError testSecret1 testFailure
          result = unwrapError secrets err0
      case result of
        Attributed idx msg -> do
          idx @?= 0
          fmCode msg @?= IncorrectOrUnknownPaymentDetails
        UnknownOrigin _ ->
          assertFailure
            "Expected Attributed, got UnknownOrigin"
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
          assertFailure
            "Expected UnknownOrigin with wrong secrets"

  , testCase "empty secrets gives UnknownOrigin" $ do
      let err = constructError testSecret1 testFailure
          result = unwrapError [] err
      case result of
        UnknownOrigin _ -> return ()
        Attributed _ _ ->
          assertFailure
            "Expected UnknownOrigin with empty secrets"

  , testCase "correct attribution with multiple failures" $ do
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
          _ -> assertFailure $
            "Failed for code: " ++ show code
        ) failures
  ]

testFailureMessageParsing :: TestTree
testFailureMessageParsing =
  testGroup "failure message parsing" [
    testCase "code with data" $ do
      let failData = BS.replicate 10 0xAB
          failure =
            FailureMessage AmountBelowMinimum failData []
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
          _ -> assertFailure $
            "Failed for code: " ++ show code
        ) codes
  ]

-- Blinding tests -----------------------------------------------------------

-- Test data setup

testSeed :: BS.ByteString
testSeed = BS.pack [1..32]

makeSecKey :: Word8 -> BS.ByteString
makeSecKey seed = BS.pack $ replicate 31 0x00 ++ [seed]

makePubKey :: Word8 -> Maybe Secp256k1.Projective
makePubKey seed = do
  sk <- Secp256k1.roll32 (makeSecKey seed)
  Secp256k1.derive_pub sk

testNodeSecKey1, testNodeSecKey2,
  testNodeSecKey3 :: BS.ByteString
testNodeSecKey1 = makeSecKey 0x11
testNodeSecKey2 = makeSecKey 0x22
testNodeSecKey3 = makeSecKey 0x33

testNodePubKey1, testNodePubKey2,
  testNodePubKey3 :: Secp256k1.Projective
testNodePubKey1 = case makePubKey 0x11 of
  Just pk -> pk
  Nothing -> error "testNodePubKey1: invalid key"
testNodePubKey2 = case makePubKey 0x22 of
  Just pk -> pk
  Nothing -> error "testNodePubKey2: invalid key"
testNodePubKey3 = case makePubKey 0x33 of
  Just pk -> pk
  Nothing -> error "testNodePubKey3: invalid key"

testSharedSecretBS :: SharedSecret
testSharedSecretBS = SharedSecret (BS.pack [0x42..0x61])

emptyHopData :: BlindedHopData
emptyHopData = BlindedHopData
  Nothing Nothing Nothing Nothing
  Nothing Nothing Nothing Nothing

sampleHopData :: BlindedHopData
sampleHopData = BlindedHopData
  { bhdPadding = Nothing
  , bhdShortChannelId = Just (mkScid 700000 1234 0)
  , bhdNextNodeId = Nothing
  , bhdPathId = Just (BS.pack [0x42, 0x42])
  , bhdNextPathKeyOverride = Nothing
  , bhdPaymentRelay = Just (PaymentRelay 40 1000 500)
  , bhdPaymentConstraints =
      Just (PaymentConstraints 144 1000000)
  , bhdAllowedFeatures = Nothing
  }

hopDataWithNextNode :: BlindedHopData
hopDataWithNextNode = emptyHopData
  { bhdNextNodeId =
      Just (Secp256k1.serialize_point testNodePubKey2)
  }

-- 1. Key Derivation Tests -------------------------------------------------

blindingKeyDerivationTests :: TestTree
blindingKeyDerivationTests = testGroup "key derivation" [
    testCase "deriveBlindingRho produces 32 bytes" $ do
      let DerivedKey rho =
            deriveBlindingRho testSharedSecretBS
      BS.length rho @?= 32

  , testCase "deriveBlindingRho is deterministic" $ do
      let rho1 = deriveBlindingRho testSharedSecretBS
          rho2 = deriveBlindingRho testSharedSecretBS
      rho1 @?= rho2

  , testCase "deriveBlindingRho differs for diff secrets" $ do
      let ss1 = SharedSecret (BS.replicate 32 0x00)
          ss2 = SharedSecret (BS.replicate 32 0x01)
          rho1 = deriveBlindingRho ss1
          rho2 = deriveBlindingRho ss2
      assertBool "rho values should differ" (rho1 /= rho2)

  , testCase "deriveBlindedNodeId produces 33 bytes" $ do
      case deriveBlindedNodeId
             testSharedSecretBS testNodePubKey1 of
        Nothing ->
          assertFailure
            "deriveBlindedNodeId returned Nothing"
        Just blindedId -> BS.length blindedId @?= 33

  , testCase "deriveBlindedNodeId is deterministic" $ do
      let result1 = deriveBlindedNodeId
                       testSharedSecretBS testNodePubKey1
          result2 = deriveBlindedNodeId
                       testSharedSecretBS testNodePubKey1
      result1 @?= result2

  , testCase "deriveBlindedNodeId differs for diff nodes" $ do
      let result1 = deriveBlindedNodeId
                       testSharedSecretBS testNodePubKey1
          result2 = deriveBlindedNodeId
                       testSharedSecretBS testNodePubKey2
      assertBool "blinded node IDs should differ"
        (result1 /= result2)
  ]

-- 2. Ephemeral Key Iteration Tests ----------------------------------------

-- | Derive the public key for testSeed
testSeedPubKey :: Secp256k1.Projective
testSeedPubKey = case Secp256k1.roll32 testSeed of
  Nothing -> error "testSeedPubKey: invalid seed"
  Just sk -> case Secp256k1.derive_pub sk of
    Nothing -> error "testSeedPubKey: invalid key"
    Just pk -> pk

blindingEphemeralKeyTests :: TestTree
blindingEphemeralKeyTests =
  testGroup "ephemeral key iteration" [
    testCase "nextEphemeral produces valid keys" $ do
      case nextEphemeral
             testSeed testSeedPubKey testSharedSecretBS of
        Nothing ->
          assertFailure "nextEphemeral returned Nothing"
        Just (newSecKey, newPubKey) -> do
          BS.length newSecKey @?= 32
          let serialized =
                Secp256k1.serialize_point newPubKey
          BS.length serialized @?= 33

  , testCase "nextEphemeral: sec key derives pub key" $ do
      case nextEphemeral
             testSeed testSeedPubKey testSharedSecretBS of
        Nothing ->
          assertFailure "nextEphemeral returned Nothing"
        Just (newSecKey, newPubKey) -> do
          sk <- demand "roll32" $
            Secp256k1.roll32 newSecKey
          derivedPub <- demand "derive_pub" $
            Secp256k1.derive_pub sk
          derivedPub @?= newPubKey

  , testCase "nextEphemeral is deterministic" $ do
      let result1 = nextEphemeral
                       testSeed testSeedPubKey
                       testSharedSecretBS
          result2 = nextEphemeral
                       testSeed testSeedPubKey
                       testSharedSecretBS
      result1 @?= result2

  , testCase "nextEphemeral differs for diff secrets" $ do
      let ss1 = SharedSecret (BS.replicate 32 0xAA)
          ss2 = SharedSecret (BS.replicate 32 0xBB)
          result1 = nextEphemeral
                       testSeed testSeedPubKey ss1
          result2 = nextEphemeral
                       testSeed testSeedPubKey ss2
      assertBool "results should differ"
        (result1 /= result2)
  ]

-- 3. TLV Encoding/Decoding Tests -----------------------------------------

blindingTlvTests :: TestTree
blindingTlvTests = testGroup "TLV encoding/decoding" [
    testCase "roundtrip: empty hop data" $ do
      let encoded = encodeBlindedHopData emptyHopData
          decoded = decodeBlindedHopData encoded
      decoded @?= Just emptyHopData

  , testCase "roundtrip: sample hop data" $ do
      let encoded = encodeBlindedHopData sampleHopData
          decoded = decodeBlindedHopData encoded
      decoded @?= Just sampleHopData

  , testCase "roundtrip: hop data with next node ID" $ do
      let encoded = encodeBlindedHopData hopDataWithNextNode
          decoded = decodeBlindedHopData encoded
      decoded @?= Just hopDataWithNextNode

  , testCase "roundtrip: hop data with padding" $ do
      let hd = emptyHopData
            { bhdPadding = Just (BS.replicate 16 0x00) }
          encoded = encodeBlindedHopData hd
          decoded = decodeBlindedHopData encoded
      decoded @?= Just hd

  , testCase "PaymentRelay encoding/decoding" $ do
      let relay = PaymentRelay 40 1000 500
          hd = emptyHopData
            { bhdPaymentRelay = Just relay }
          encoded = encodeBlindedHopData hd
          decoded = decodeBlindedHopData encoded
      case decoded of
        Nothing ->
          assertFailure
            "decodeBlindedHopData returned Nothing"
        Just d -> bhdPaymentRelay d @?= Just relay

  , testCase "PaymentConstraints encoding/decoding" $ do
      let constraints = PaymentConstraints 144 1000000
          hd = emptyHopData
            { bhdPaymentConstraints = Just constraints }
          encoded = encodeBlindedHopData hd
          decoded = decodeBlindedHopData encoded
      case decoded of
        Nothing ->
          assertFailure
            "decodeBlindedHopData returned Nothing"
        Just d ->
          bhdPaymentConstraints d @?= Just constraints

  , testCase "decode empty bytestring" $ do
      let decoded = decodeBlindedHopData BS.empty
      decoded @?= Just emptyHopData
  ]

-- 4. Encryption/Decryption Tests ------------------------------------------

blindingEncryptionTests :: TestTree
blindingEncryptionTests =
  testGroup "encryption/decryption" [
    testCase "roundtrip: encrypt then decrypt" $ do
      let rho = deriveBlindingRho testSharedSecretBS
          encrypted = encryptHopData rho sampleHopData
          decrypted = decryptHopData rho encrypted
      decrypted @?= Just sampleHopData

  , testCase "roundtrip: empty hop data" $ do
      let rho = deriveBlindingRho testSharedSecretBS
          encrypted = encryptHopData rho emptyHopData
          decrypted = decryptHopData rho encrypted
      decrypted @?= Just emptyHopData

  , testCase "decryption with wrong key fails" $ do
      let rho1 = deriveBlindingRho testSharedSecretBS
          rho2 = deriveBlindingRho
            (SharedSecret (BS.replicate 32 0xFF))
          encrypted = encryptHopData rho1 sampleHopData
          decrypted = decryptHopData rho2 encrypted
      assertBool "decryption should fail or produce garbage"
        (decrypted /= Just sampleHopData)

  , testCase "encrypt is deterministic" $ do
      let rho = deriveBlindingRho testSharedSecretBS
          encrypted1 = encryptHopData rho sampleHopData
          encrypted2 = encryptHopData rho sampleHopData
      encrypted1 @?= encrypted2
  ]

-- 5. createBlindedPath Tests ----------------------------------------------

blindingCreatePathTests :: TestTree
blindingCreatePathTests = testGroup "createBlindedPath" [
    testCase "create path with 2 hops" $ do
      let nodes = [(testNodePubKey1, emptyHopData),
                   (testNodePubKey2, sampleHopData)]
      case createBlindedPath testSeed nodes of
        Left err ->
          assertFailure $
            "createBlindedPath failed: " ++ show err
        Right path -> do
          length (bpBlindedHops path) @?= 2
          let serialized =
                Secp256k1.serialize_point
                  (bpBlindingKey path)
          BS.length serialized @?= 33

  , testCase "create path with 3 hops" $ do
      let nodes = [ (testNodePubKey1, emptyHopData)
                  , (testNodePubKey2, hopDataWithNextNode)
                  , (testNodePubKey3, sampleHopData)
                  ]
      case createBlindedPath testSeed nodes of
        Left err ->
          assertFailure $
            "createBlindedPath failed: " ++ show err
        Right path ->
          length (bpBlindedHops path) @?= 3

  , testCase "all blinded node IDs are 33 bytes" $ do
      let nodes = [ (testNodePubKey1, emptyHopData)
                  , (testNodePubKey2, emptyHopData)
                  , (testNodePubKey3, emptyHopData)
                  ]
      case createBlindedPath testSeed nodes of
        Left err ->
          assertFailure $
            "createBlindedPath failed: " ++ show err
        Right path -> do
          let blindedIds =
                map bhBlindedNodeId (bpBlindedHops path)
          mapM_ (\bid -> BS.length bid @?= 33) blindedIds

  , testCase "empty path returns EmptyPath error" $ do
      case createBlindedPath testSeed [] of
        Left EmptyPath -> return ()
        Left err ->
          assertFailure $
            "Expected EmptyPath, got: " ++ show err
        Right _ ->
          assertFailure "Expected error, got success"

  , testCase "invalid seed returns InvalidSeed error" $ do
      let invalidSeed = BS.pack [1..16]
          nodes = [(testNodePubKey1, emptyHopData)]
      case createBlindedPath invalidSeed nodes of
        Left InvalidSeed -> return ()
        Left err ->
          assertFailure $
            "Expected InvalidSeed, got: " ++ show err
        Right _ ->
          assertFailure "Expected error, got success"

  , testCase "createBlindedPath is deterministic" $ do
      let nodes = [(testNodePubKey1, emptyHopData),
                   (testNodePubKey2, sampleHopData)]
          result1 = createBlindedPath testSeed nodes
          result2 = createBlindedPath testSeed nodes
      result1 @?= result2
  ]

-- 6. processBlindedHop Tests ----------------------------------------------

blindingProcessHopTests :: TestTree
blindingProcessHopTests =
  testGroup "processBlindedHop" [
    testCase "process first hop decrypts correctly" $ do
      let nodes = [(testNodePubKey1, sampleHopData),
                   (testNodePubKey2, emptyHopData)]
      case createBlindedPath testSeed nodes of
        Left err ->
          assertFailure $
            "createBlindedPath failed: " ++ show err
        Right path -> case bpBlindedHops path of
          firstHop : _ -> do
            let pathKey = bpBlindingKey path
            case processBlindedHop testNodeSecKey1
                   pathKey (bhEncryptedData firstHop) of
              Left err -> assertFailure $
                "processBlindedHop failed: " ++ show err
              Right (decryptedData, _) ->
                decryptedData @?= sampleHopData
          [] -> assertFailure "expected non-empty hops"

  , testCase "process hop chain correctly" $ do
      let nodes =
            [ (testNodePubKey1, emptyHopData)
            , (testNodePubKey2, sampleHopData)
            , (testNodePubKey3, hopDataWithNextNode)
            ]
      case createBlindedPath testSeed nodes of
        Left err ->
          assertFailure $
            "createBlindedPath failed: " ++ show err
        Right path -> case bpBlindedHops path of
          [hop1, hop2, hop3] -> do
            let pathKey1 = bpBlindingKey path
            case processBlindedHop testNodeSecKey1
                   pathKey1 (bhEncryptedData hop1) of
              Left err -> assertFailure $
                "processBlindedHop hop1 failed: "
                  ++ show err
              Right (data1, pathKey2) -> do
                data1 @?= emptyHopData
                case processBlindedHop testNodeSecKey2
                       pathKey2
                       (bhEncryptedData hop2) of
                  Left err -> assertFailure $
                    "processBlindedHop hop2 failed: "
                      ++ show err
                  Right (data2, pathKey3) -> do
                    data2 @?= sampleHopData
                    case processBlindedHop
                           testNodeSecKey3 pathKey3
                           (bhEncryptedData hop3) of
                      Left err -> assertFailure $
                        "processBlindedHop hop3: "
                          ++ show err
                      Right (data3, _) ->
                        data3 @?= hopDataWithNextNode
          _ -> assertFailure "expected 3 blinded hops"

  , testCase "process hop with wrong node key fails" $ do
      let nodes = [(testNodePubKey1, sampleHopData)]
      case createBlindedPath testSeed nodes of
        Left err ->
          assertFailure $
            "createBlindedPath failed: " ++ show err
        Right path -> case bpBlindedHops path of
          firstHop : _ -> do
            let pathKey = bpBlindingKey path
            case processBlindedHop testNodeSecKey2
                   pathKey (bhEncryptedData firstHop) of
              Left _ -> return ()
              Right (decryptedData, _) ->
                assertBool "should not decrypt correctly"
                  (decryptedData /= sampleHopData)
          [] -> assertFailure "expected non-empty hops"

  , testCase "next path key is valid point" $ do
      let nodes = [(testNodePubKey1, emptyHopData),
                   (testNodePubKey2, emptyHopData)]
      case createBlindedPath testSeed nodes of
        Left err ->
          assertFailure $
            "createBlindedPath failed: " ++ show err
        Right path -> case bpBlindedHops path of
          firstHop : _ -> do
            let pathKey = bpBlindingKey path
            case processBlindedHop testNodeSecKey1
                   pathKey (bhEncryptedData firstHop) of
              Left err -> assertFailure $
                "processBlindedHop failed: " ++ show err
              Right (_, nextPK) -> do
                let serialized =
                      Secp256k1.serialize_point nextPK
                BS.length serialized @?= 33
          [] -> assertFailure "expected non-empty hops"

  , testCase "next_path_key_override is used" $ do
      let overrideKey =
            Secp256k1.serialize_point testNodePubKey3
          hopDataWithOverride' = emptyHopData
            { bhdNextPathKeyOverride = Just overrideKey }
          nodes = [(testNodePubKey1, hopDataWithOverride'),
                   (testNodePubKey2, emptyHopData)]
      case createBlindedPath testSeed nodes of
        Left err ->
          assertFailure $
            "createBlindedPath failed: " ++ show err
        Right path -> case bpBlindedHops path of
          firstHop : _ -> do
            let pathKey = bpBlindingKey path
            case processBlindedHop testNodeSecKey1
                   pathKey (bhEncryptedData firstHop) of
              Left err -> assertFailure $
                "processBlindedHop failed: " ++ show err
              Right (decryptedData, nextPK) -> do
                bhdNextPathKeyOverride decryptedData
                  @?= Just overrideKey
                nextPK @?= testNodePubKey3
          [] -> assertFailure "expected non-empty hops"
  ]

-- Property tests ------------------------------------------------------------

propertyTests :: TestTree
propertyTests = testGroup "invariants" [
    testProperty "ShortChannelId encode/decode roundtrip"
      propScidRoundtrip
  , testProperty "HopPayload encode/decode roundtrip"
      propHopPayloadRoundtrip
  , testProperty "fixed-size newtypes validate length"
      propNewtypeValidation
  , testProperty "FailureMessage encode/decode roundtrip"
      propFailureMessageRoundtrip
  ]

propScidRoundtrip :: Property
propScidRoundtrip =
  forAll (choose (0, 0xFFFFFF)) $ \bh ->
  forAll (choose (0, 0xFFFFFF)) $ \ti ->
  forAll arbitrary $ \oi ->
    case shortChannelId bh ti oi of
      Nothing -> False
      Just scid ->
        let encoded = encodeShortChannelId scid
        in  decodeShortChannelId encoded == Just scid

propHopPayloadRoundtrip :: Property
propHopPayloadRoundtrip =
  forAll genHopPayload $ \hp ->
    let encoded = encodeHopPayload hp
    in  decodeHopPayload encoded == Just hp

genHopPayload :: Gen HopPayload
genHopPayload = do
  amt <- oneof [pure Nothing, Just <$> arbitrary]
  cltv <- oneof [pure Nothing, Just <$> arbitrary]
  sci <- oneof [pure Nothing, genScid]
  pure HopPayload
    { hpAmtToForward = amt
    , hpOutgoingCltv = cltv
    , hpShortChannelId = sci
    , hpPaymentData = Nothing
    , hpEncryptedData = Nothing
    , hpCurrentPathKey = Nothing
    , hpUnknownTlvs = []
    }
  where
    genScid :: Gen (Maybe ShortChannelId)
    genScid = do
      bh <- choose (0, 0xFFFFFF)
      ti <- choose (0, 0xFFFFFF)
      oi <- arbitrary
      pure (shortChannelId bh ti oi)

propNewtypeValidation :: NonNegative Int -> Property
propNewtypeValidation (NonNegative n) = property $
  let len = n `mod` 2000
      bs = BS.replicate len 0x00
      h32 = hmac32 bs
      hp  = hopPayloads bs
      ps  = paymentSecret bs
  in  (case h32 of
         Just _  -> len == 32
         Nothing -> len /= 32)
      &&
      (case hp of
         Just _  -> len == hopPayloadsSize
         Nothing -> len /= hopPayloadsSize)
      &&
      (case ps of
         Just _  -> len == 32
         Nothing -> len /= 32)

propFailureMessageRoundtrip :: Property
propFailureMessageRoundtrip =
  forAll genFailureMessage $ \fm ->
    let encoded = encodeFailureMessage fm
    in  decodeFailureMessage encoded == Just fm

genFailureMessage :: Gen FailureMessage
genFailureMessage = do
  code <- elements
    [ InvalidRealm
    , TemporaryNodeFailure
    , PermanentNodeFailure
    , InvalidOnionHmac
    , TemporaryChannelFailure
    , IncorrectOrUnknownPaymentDetails
    , AmountBelowMinimum
    , FeeInsufficient
    , ExpiryTooSoon
    , MppTimeout
    ]
  dlen <- choose (0, 100 :: Int)
  dat <- BS.pack <$> vectorOf dlen arbitrary
  pure (FailureMessage code dat [])

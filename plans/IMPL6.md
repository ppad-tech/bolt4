# IMPL6: Route Blinding

**Module**: `Lightning.Protocol.BOLT4.Blinding`

**Dependencies**: IMPL1 (Prim), IMPL2 (Types, Codec)

**Can run in parallel with**: IMPL3, IMPL4, IMPL5 (after IMPL1 and IMPL2 complete)

**Priority**: Lower - can be deferred. Core functionality works without this.

## Overview

Route blinding allows a recipient to provide a "blinded path" that hides
the identities of nodes in the path. The sender constructs a route to
the introduction point, then the blinded path takes over.

## Types

```haskell
-- | A blinded route provided by recipient.
data BlindedPath = BlindedPath
  { bpIntroductionNode :: !Secp256k1.PubKey  -- first node (unblinded)
  , bpBlindingKey      :: !Secp256k1.PubKey  -- E_0, initial ephemeral
  , bpBlindedHops      :: ![BlindedHop]
  } deriving (Eq, Show)

-- | A single hop in a blinded path.
data BlindedHop = BlindedHop
  { bhBlindedNodeId   :: !BS.ByteString     -- 33 bytes, blinded pubkey
  , bhEncryptedData   :: !BS.ByteString     -- encrypted routing data
  } deriving (Eq, Show)

-- | Data encrypted for each blinded hop (before encryption).
data BlindedHopData = BlindedHopData
  { bhdPadding          :: !(Maybe BS.ByteString)  -- TLV 1
  , bhdShortChannelId   :: !(Maybe ShortChannelId) -- TLV 2
  , bhdNextNodeId       :: !(Maybe BS.ByteString)  -- TLV 4, 33-byte pubkey
  , bhdPathId           :: !(Maybe BS.ByteString)  -- TLV 6
  , bhdNextPathKeyOverride :: !(Maybe BS.ByteString) -- TLV 8
  , bhdPaymentRelay     :: !(Maybe PaymentRelay)   -- TLV 10
  , bhdPaymentConstraints :: !(Maybe PaymentConstraints) -- TLV 12
  , bhdAllowedFeatures  :: !(Maybe BS.ByteString)  -- TLV 14
  } deriving (Eq, Show)

-- | Payment relay parameters (TLV 10).
data PaymentRelay = PaymentRelay
  { prCltvExpiryDelta    :: {-# UNPACK #-} !Word16
  , prFeeProportional    :: {-# UNPACK #-} !Word32  -- millionths
  , prFeeBaseMsat        :: {-# UNPACK #-} !Word32
  } deriving (Eq, Show)

-- | Payment constraints (TLV 12).
data PaymentConstraints = PaymentConstraints
  { pcMaxCltvExpiry      :: {-# UNPACK #-} !Word32
  , pcHtlcMinimumMsat    :: {-# UNPACK #-} !Word64
  } deriving (Eq, Show)
```

## Path Creation (Recipient)

```haskell
-- | Create a blinded path from a list of nodes.
--
-- The recipient generates this and shares it (e.g., in an invoice).
createBlindedPath
  :: BS.ByteString       -- ^ 32-byte random seed for ephemeral key
  -> [(Secp256k1.PubKey, BlindedHopData)]  -- ^ nodes with their data
  -> Either Error BlindedPath

-- | Errors during blinded path creation.
data BlindingError
  = InvalidSeed
  | EmptyPath
  | InvalidNodeKey Int
  deriving (Eq, Show)
```

## Path Processing (Blinded Node)

```haskell
-- | Process a packet at a blinded node.
--
-- Takes the node's private key, the path key (blinding point), and
-- the encrypted data. Returns decrypted routing data and next path key.
processBlindedHop
  :: Secp256k1.SecKey    -- ^ node's private key
  , Secp256k1.PubKey     -- ^ E_i, current path key (blinding point)
  -> BS.ByteString       -- ^ encrypted_data from onion payload
  -> Either Error (BlindedHopData, Secp256k1.PubKey)
  -- ^ (decrypted data, E_{i+1} next path key)
```

## Internal Functions

### Key Derivation for Blinding

```haskell
-- | Derive blinded node ID.
-- B_i = HMAC256("blinded_node_id", ss_i) * N_i
deriveBlindedNodeId
  :: SharedSecret        -- ^ ss_i
  -> Secp256k1.PubKey    -- ^ N_i, node's real pubkey
  -> Maybe BS.ByteString -- ^ blinded pubkey bytes

-- | Derive rho key for encrypting hop data.
-- Same as regular rho but used with ChaCha20-Poly1305.
deriveBlindingRho :: SharedSecret -> DerivedKey
```

### Ephemeral Key Iteration

```haskell
-- | Compute next ephemeral key pair for path creation.
-- e_{i+1} = SHA256(E_i || ss_i) * e_i
-- E_{i+1} = SHA256(E_i || ss_i) * E_i
nextEphemeral
  :: Secp256k1.SecKey    -- ^ e_i
  -> Secp256k1.PubKey    -- ^ E_i
  -> SharedSecret        -- ^ ss_i
  -> Maybe (Secp256k1.SecKey, Secp256k1.PubKey)  -- ^ (e_{i+1}, E_{i+1})
```

### Encryption

```haskell
-- | Encrypt hop data with ChaCha20-Poly1305.
--
-- Uses rho key and 12-byte zero nonce.
-- NOTE: This requires AEAD, unlike regular packet obfuscation.
encryptHopData
  :: DerivedKey          -- ^ rho key
  -> BlindedHopData      -- ^ plaintext data
  -> BS.ByteString       -- ^ ciphertext with auth tag

-- | Decrypt hop data with ChaCha20-Poly1305.
decryptHopData
  :: DerivedKey          -- ^ rho key
  -> BS.ByteString       -- ^ ciphertext with auth tag
  -> Maybe BlindedHopData
```

## Path Creation Algorithm

```
createBlindedPath(seed, nodes):
  1. (e_0, E_0) = keypair from seed
  2. introduction_node = nodes[0].pubkey

  3. blinded_hops = []
  4. e_i, E_i = e_0, E_0

  For each (N_i, data_i) in nodes:
    5. ss_i = SHA256(ECDH(e_i, N_i))
    6. rho_i = deriveBlindingRho(ss_i)
    7. B_i = deriveBlindedNodeId(ss_i, N_i)
    8. encrypted_i = encryptHopData(rho_i, data_i)
    9. blinded_hops.append(BlindedHop(B_i, encrypted_i))
    10. (e_i, E_i) = nextEphemeral(e_i, E_i, ss_i)

  11. return BlindedPath(introduction_node, E_0, blinded_hops)
```

## Hop Processing Algorithm

```
processBlindedHop(node_seckey, path_key, encrypted_data):
  1. ss = SHA256(ECDH(node_seckey, path_key))
  2. rho = deriveBlindingRho(ss)

  3. hop_data = decryptHopData(rho, encrypted_data)
     If decryption fails: return error

  4. Check for next_path_key_override in hop_data
     If present: E_next = override value
     Else: E_next = SHA256(path_key || ss) * path_key

  5. return (hop_data, E_next)
```

## Integration with Packet Construction

When constructing a packet with a blinded suffix:

1. Construct normal hops up to introduction point
2. At introduction point, include `current_path_key` (TLV 12) = E_0
3. For blinded hops, use blinded node IDs as "pubkeys" and include
   `encrypted_recipient_data` (TLV 10) from BlindedHop

The blinded nodes don't know their position or the path structure.

## Implementation Notes

1. Route blinding uses ChaCha20-Poly1305 (AEAD), not plain ChaCha20.
   This may require ppad-aead as dependency.

2. The "blinded node ID" is a tweaked public key. Nodes must be able
   to derive the corresponding private key tweak.

3. path_key_override allows path creators to inject specific keys,
   useful for multi-path scenarios.

4. This is an optional feature. Core BOLT4 works without it.

## Test Vectors

The spec includes blinded path test vectors. Key values to verify:
- Blinded node ID derivation
- Encrypted data for each hop
- Path key iteration
- Decryption at each blinded node

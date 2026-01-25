# BOLT4 Architecture

## Overview

BOLT4 specifies the onion routing protocol for Lightning Network payments.
The protocol enables source-routed payments where each intermediate node
only learns the identity of its immediate predecessor and successor.

The implementation divides into six logical layers:

```
┌─────────────────────────────────────────────────────────┐
│                    Public API                           │
│   construct, process, unwrapError, createBlindedPath    │
├─────────────────────────────────────────────────────────┤
│                  Packet Construction                    │
│   Session keys, filler generation, layered encryption   │
├──────────────────────┬──────────────────────────────────┤
│  Packet Processing   │       Error Handling             │
│  Decrypt, extract,   │   Failure codes, obfuscation,   │
│  forward/terminate   │   attribution                    │
├──────────────────────┴──────────────────────────────────┤
│                  Route Blinding                         │
│   Blinded paths, encrypted recipient data               │
├─────────────────────────────────────────────────────────┤
│                    Types/Codec                          │
│   OnionPacket, HopPayload, TLV encoding, BigSize        │
├─────────────────────────────────────────────────────────┤
│                 Cryptographic Primitives                │
│   Key derivation, ECDH, blinding, ChaCha20 streams      │
└─────────────────────────────────────────────────────────┘
```

## Module Structure

```
Lightning.Protocol.BOLT4
├── Prim        -- Cryptographic primitives
├── Types       -- Core data types
├── Codec       -- Serialization (BigSize, TLV)
├── Construct   -- Packet construction (sender)
├── Process     -- Packet processing (receiver)
├── Error       -- Failure messages and attribution
└── Blinding    -- Route blinding (optional)
```

## Layer Details

### 1. Cryptographic Primitives (Prim)

Core crypto operations used throughout:

**Key Derivation** (HMAC-SHA256 with key-type prefixes):
- `rho` (0x72686f): generates obfuscation stream
- `mu` (0x6d75): HMAC for packet integrity
- `um` (0x756d): HMAC for error messages
- `pad` (0x706164): filler generation
- `ammag` (0x616d6d6167): error obfuscation

**Shared Secret**: ECDH between ephemeral key and hop pubkey, then SHA256.

**Blinding Factor**: SHA256(ephemeral_pubkey || shared_secret).

**Pseudo-Random Stream**: ChaCha20 with derived key, 96-bit zero nonce,
encrypting zeros to produce keystream.

### 2. Types

**OnionPacket** (1366 bytes):
```
┌─────────┬──────────────┬─────────────┬──────┐
│ version │ ephemeral_pk │ hop_payloads│ hmac │
│ 1 byte  │   33 bytes   │ 1300 bytes  │ 32   │
└─────────┴──────────────┴─────────────┴──────┘
```

**HopPayload**: Variable-length TLV stream with BigSize length prefix.
Contains routing info (amt_to_forward, cltv, short_channel_id, etc.).

**FailureMessage**: 2-byte code + failure-specific data + optional TLV.

### 3. Codec

**BigSize**: Variable-length integer encoding (1, 3, 5, or 9 bytes).

**TLV**: Type-Length-Value records with BigSize type and length fields.

Standard payload TLV types:
- 2: amt_to_forward
- 4: outgoing_cltv_value
- 6: short_channel_id
- 8: payment_data
- 10: encrypted_recipient_data
- 12: current_path_key

### 4. Packet Construction (Sender)

Algorithm (reverse iteration from final hop to first):

1. Generate random session key
2. Derive ephemeral keypair for first hop
3. Compute shared secrets and blinding factors for all hops
4. Initialize 1300-byte buffer with random bytes (using pad key)
5. For each hop (reverse order):
   a. Right-shift buffer by payload size
   b. Insert: BigSize length + payload + HMAC
   c. XOR entire buffer with rho stream
   d. Compute new HMAC using mu key
6. Overwrite tail with filler (accounts for accumulated shifts)
7. Return: version || ephemeral_pk || buffer || final_hmac

### 5. Packet Processing (Receiver)

1. Validate version (must be 0x00)
2. Compute shared secret via ECDH
3. Derive mu, rho keys
4. Verify HMAC (constant-time compare)
5. Generate 2600-byte stream, XOR with hop_payloads (extended)
6. Parse BigSize length, extract payload and next_hmac
7. Decision:
   - next_hmac == 0: final destination
   - next_hmac != 0: forward to next hop
8. For forwarding: compute blinded ephemeral key, shift buffer

### 6. Error Handling

**Construction** (failing node):
1. Build failure message (code + data)
2. Pad to ≥256 bytes
3. Prepend length and compute HMAC using um key
4. XOR with ammag stream

**Unwrapping** (origin):
1. For each hop (forward order):
   - Derive ammag, um keys from shared secret
   - XOR to decrypt
   - Check HMAC
   - If valid: found failing node
   - If invalid: strip layer, continue

### 7. Route Blinding (Optional)

Creates paths where intermediate nodes don't know their position:

1. Generate ephemeral keypair (e₀, E₀)
2. For each node i:
   - Compute shared secret ss_i = SHA256(ECDH(e_i, N_i))
   - Derive rho_i for encrypting recipient data
   - Compute blinded node ID: B_i = HMAC("blinded_node_id", ss_i) × N_i
   - Blind ephemeral key for next hop
3. Encrypt per-hop data with ChaCha20-Poly1305

## Constants

```haskell
onionPacketSize   = 1366  -- total packet size
hopPayloadsSize   = 1300  -- payload area
maxHops           = 20    -- typical maximum
hmacSize          = 32    -- HMAC-SHA256 output
pubkeySize        = 33    -- compressed secp256k1
versionByte       = 0x00  -- protocol version
```

## Dependencies

Internal (ppad-*):
- ppad-secp256k1: ECDH, point multiplication, pubkey parsing
- ppad-sha256: hashing for shared secrets, blinding
- ppad-hmac-sha256: key derivation, packet integrity
- ppad-chacha: pseudo-random stream generation

External: none (besides GHC boot libs).

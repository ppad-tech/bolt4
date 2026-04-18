# ppad-bolt4

[![](https://img.shields.io/hackage/v/ppad-bolt4?color=blue)](https://hackage.haskell.org/package/ppad-bolt4)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-bolt4-lightblue)](https://docs.ppad.tech/bolt4)

A pure Haskell implementation of [BOLT #4][bolt4] (onion routing) from
the Lightning Network protocol specification, including packet
construction and processing, error handling, and route blinding.

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  >
  > -- construct an onion packet for a 3-hop route
  > import qualified Crypto.Curve.Secp256k1 as Secp256k1
  > import qualified Data.ByteString as BS
  > import qualified Lightning.Protocol.BOLT4.Construct as Construct
  > import qualified Lightning.Protocol.BOLT4.Process as Process
  > import Lightning.Protocol.BOLT4.Types
  >
  > -- session key (32 bytes random, use CSPRNG in production)
  > let sessionKey = BS.replicate 32 0x41
  >
  > -- node keys (in production, these come from the network)
  > let Just hop1Sec = Secp256k1.parse_integer (BS.replicate 32 0x01)
  > let Just hop1Pub = Secp256k1.mul Secp256k1._CURVE_G hop1Sec
  >
  > -- build a minimal payload
  > let payload = emptyHopPayload { hpAmtToForward = Just 1000
  >                               , hpOutgoingCltv = Just 144 }
  > let hop = Construct.Hop hop1Pub payload
  >
  > -- construct packet (returns packet + shared secrets for error handling)
  > let assocData = BS.replicate 32 0x00  -- typically payment_hash
  > let Right (packet, secrets) = Construct.construct sessionKey [hop] assocData
  >
  > -- process at receiving node
  > let result = Process.process (BS.replicate 32 0x01) packet assocData
  > case result of
  >   Right (Process.Receive info) -> print (riPayload info)
  >   _ -> putStrLn "not final hop"
```

## Modules

The library is organized into the following modules:

* `Lightning.Protocol.BOLT4.Construct` - onion packet construction
* `Lightning.Protocol.BOLT4.Process` - onion packet processing
* `Lightning.Protocol.BOLT4.Error` - failure message handling
* `Lightning.Protocol.BOLT4.Blinding` - route blinding support
* `Lightning.Protocol.BOLT4.Types` - core data types
* `Lightning.Protocol.BOLT4.Codec` - serialization (BigSize, TLV)
* `Lightning.Protocol.BOLT4.Prim` - cryptographic primitives

## Documentation

Haddocks are hosted at [docs.ppad.tech/bolt4][hadoc].

## Security

This is a pre-release library that claims no security properties whatsoever.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal build
$ cabal test
$ cabal bench
```

[bolt4]: https://github.com/lightning/bolts/blob/master/04-onion-routing.md
[hadoc]: https://docs.ppad.tech/bolt4
[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html

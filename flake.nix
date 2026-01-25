{
  description = "A Haskell implementation of BOLT4 (onion routing).";

  inputs = {
    ppad-aead.url = "path:/Users/jtobin/src/ppad/aead";
    ppad-aead.inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    ppad-aead.inputs.ppad-chacha.follows = "ppad-chacha";

    ppad-base16.url = "path:/Users/jtobin/src/ppad/base16";
    ppad-base16.inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";

    ppad-chacha.url = "path:/Users/jtobin/src/ppad/chacha";
    ppad-chacha.inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";

    ppad-secp256k1.url = "path:/Users/jtobin/src/ppad/secp256k1";
    ppad-secp256k1.inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    ppad-secp256k1.inputs.ppad-sha256.follows = "ppad-sha256";

    ppad-sha256.url = "path:/Users/jtobin/src/ppad/sha256";
    ppad-sha256.inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";

    ppad-nixpkgs.url = "path:/Users/jtobin/src/ppad/nixpkgs";

    flake-utils.follows = "ppad-nixpkgs/flake-utils";
    nixpkgs.follows = "ppad-nixpkgs/nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, ppad-nixpkgs
            , ppad-aead, ppad-base16, ppad-chacha
            , ppad-secp256k1, ppad-sha256
            }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-bolt4";

        pkgs  = import nixpkgs { inherit system; };
        hlib  = pkgs.haskell.lib;
        llvm  = pkgs.llvmPackages_19.llvm;
        clang = pkgs.llvmPackages_19.clang;

        aead = ppad-aead.packages.${system}.default;
        aead-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag aead "llvm")
            [ llvm clang ];

        base16 = ppad-base16.packages.${system}.default;
        base16-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag base16 "llvm")
            [ llvm clang ];

        chacha = ppad-chacha.packages.${system}.default;
        chacha-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag chacha "llvm")
            [ llvm clang ];

        secp256k1 = ppad-secp256k1.packages.${system}.default;
        secp256k1-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag secp256k1 "llvm")
            [ llvm clang ];

        sha256 = ppad-sha256.packages.${system}.default;
        sha256-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag sha256 "llvm")
            [ llvm clang ];

        hpkgs = pkgs.haskell.packages.ghc910.extend (new: old: {
          ppad-aead = aead-llvm;
          ppad-base16 = base16-llvm;
          ppad-chacha = chacha-llvm;
          ppad-secp256k1 = secp256k1-llvm;
          ppad-sha256 = sha256-llvm;
          ${lib} = new.callCabal2nix lib ./. {
            ppad-aead = new.ppad-aead;
            ppad-base16 = new.ppad-base16;
            ppad-chacha = new.ppad-chacha;
            ppad-secp256k1 = new.ppad-secp256k1;
            ppad-sha256 = new.ppad-sha256;
          };
        });

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          packages.default = hpkgs.${lib};

          packages.haddock = hpkgs.${lib}.doc;

          devShells.default = hpkgs.shellFor {
            packages = p: [
              (hlib.doBenchmark p.${lib})
            ];

            buildInputs = [
              cabal
              cc
              llvm
            ];

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "cc:    $(${cc}/bin/cc --version)"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
            '';
          };
        }
      );
}

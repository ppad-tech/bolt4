# ppad-bolt4

A pure Haskell implementation of BOLT4 (onion routing) from the
Lightning Network specification.

The implementation consists of the ppad-bolt4 library, a test suite,
and benchmarks (for time and space).

## build

Builds are handled via Nix and Cabal. Enter a development shell via:

    $ nix develop

and then do Cabal stuff:

    $ cabal build
    $ cabal test
    $ cabal bench

## deps

The following dependencies are allowed freely:

* Any GHC boot library or library included with GHC's normal
  distribution (e.g. bytestring, primitive, etc.).
* Any 'ppad-' library, as found on github.com/ppad-tech or
  git.ppad.tech.

Any other library requires explicit confirmation before being used.

Test and benchmark dependencies (e.g. tasty, criterion, QuickCheck,
etc.) are an exception.

Never use Stack or any non-Nix build or dependency management
tool. Never use 'pip install' or 'npm install' or anything of the
sort. The Nix development environment includes everything one
needs.

## style

Please adhere to the following guidelines:

* Keep lines at less than 80 characters in length.
* The codebase is Haskell2010.
* LANGUAGE pragmas should be added per-module.
* Haddock documentation where appropriate; use `{-# OPTIONS_HADDOCK
  prune #-}` and `-- |`-style comments for public modules.
* Prefer total functions; avoid partial Prelude functions such
  as 'head', 'tail', '!!', etc.
* Use strict annotations (bang patterns, etc.) liberally. Add
  UNPACK pragmas in data types.
* Use newtypes for type safety.
* Use smart constructors for validation.
* Use Maybe/Either for fallible operations.
* Use MagicHash/UnboxedTuples for hot paths.
* Add INLINE pragmas for small functions.

## git

* Never update the git config.
* Never use destructive git commands (such as push --force, hard reset,
  etc.) unless explicitly requested.
* Never skip hooks unless explicitly requested.
* The main branch is `master`, which mostly consists of merge commits.
  Feature branches are branched from and merged (with `--no-ff`) back
  to master.

## misc

* Be very cautious when suggesting changes to the flake.nix file. You
  should fully understand the effect of any change before making it.
* Don't create markdown files, e.g. for documentation purposes.
* When producing plans, highlight any steps that could potentially be
  executed by concurrent subagents. Place plans in the `plans/`
  directory, e.g. as `plans/IMPL1.md`.

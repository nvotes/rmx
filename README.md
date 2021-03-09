# braid

Braid is a verifiable re-encryption mixnet that can serve as the cryptographic core of secure voting systems. 

## Status

Prototype

## Dependencies

The mixnet supports pluggable [discrete log](https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption) backends, there are currently two:

* Curve25519 using the [ristretto group](https://ristretto.group/) via the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) library.
* [Standard multiplicative groups](https://en.wikipedia.org/wiki/Schnorr_group) via the [rug](https://crates.io/crates/rug) arbitrary-precision library, backed by [gmp](https://gmplib.org/).

Other significant dependencies:

* [Git](https://en.wikipedia.org/wiki/Git) is used as the bulletin board, via [git2-rs](https://github.com/rust-lang/git2-rs).
* Compute intensive portions are parallelized using [rayon](https://github.com/rayon-rs/rayon).
* The protocol is declaratively expressed in a [datalog](https://en.wikipedia.org/wiki/Datalog) variant using [crepe](https://github.com/ekzhang/crepe).
* Message signatures are provided by [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek).
* Symmetric encryption of private keys is provided by [RustCrypto](https://github.com/RustCrypto/block-ciphers).

We're also looking into [clingo](https://github.com/potassco/clingo-rs) with which it may be possible to prove certain properties of the protocol.

## Papers

Braid uses standard crytpographic techniques, most significantly

* [Proofs of Restricted Shuffles](http://www.csc.kth.se/~terelius/TeWi10Full.pdf)

* [A Commitment-Consistent Proof of a Shuffle](https://eprint.iacr.org/2011/168.pdf)

* [Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets](https://www.ifca.ai/fc17/voting/papers/voting17_HLKD17.pdf)
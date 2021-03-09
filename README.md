# braid

Braid is a verifiable re-encryption mixnet that can serve as the cryptographic core of secure voting systems. There are currently two [discrete log](https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption) pluggable backends:

* Curve25519 using the [ristretto group](https://ristretto.group/) via the [dalek](https://github.com/dalek-cryptography/curve25519-dalek) library.
* [Standard multiplicative groups](https://en.wikipedia.org/wiki/Schnorr_group) via the [rug](https://crates.io/crates/rug) arbitrary-precision library backed by [gmp](https://gmplib.org/).
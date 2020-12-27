use rand_core::{CryptoRng, RngCore, OsRng};

pub trait Rng: CryptoRng + RngCore + Sync + Send {}

impl Rng for OsRng {}
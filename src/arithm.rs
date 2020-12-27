use std::marker::{Send, Sync};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::hashing::HashBytes;

pub trait Element: HashBytes + Clone + Send + Sync + Serialize {
    type Exp: Exponent;
    type Plaintext: std::hash::Hash + Eq + Send + Sync;
    
    fn mul(&self, other: &Self) -> Self;
    fn div(&self, other: &Self, modulus: &Self) -> Self;
    fn mod_pow(&self, exp: &Self::Exp, modulus: &Self) -> Self;
    fn modulo(&self, modulus: &Self) -> Self;
    fn eq(&self, other: &Self) -> bool;

    fn mul_identity() -> Self;
}

pub trait Exponent: HashBytes + Clone + Send + Sync + Serialize + DeserializeOwned {
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn modulo(&self, modulus: &Self) -> Self;
    fn eq(&self, other: &Self) -> bool;
    
    fn add_identity() -> Self;
    fn mul_identity() -> Self;
}
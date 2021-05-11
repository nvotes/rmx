use std::fs;
use std::io;
use std::path::Path;

use curve25519_dalek::ristretto::RistrettoPoint;
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::prelude::*;
use rug::Integer;
use tempfile::NamedTempFile;

use crate::crypto::backend::ristretto_b::RistrettoGroup;
use crate::crypto::backend::rug_b::RugGroup;
use crate::crypto::base::Element;
use crate::crypto::base::Group;
use crate::crypto::elgamal::*;
use crate::data::artifact::*;

pub fn read_file_bytes(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}

pub fn write_file_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

pub fn write_tmp(bytes: Vec<u8>) -> io::Result<NamedTempFile> {
    let tmp_file = NamedTempFile::new().unwrap();
    let path = tmp_file.path();
    fs::write(path, bytes)?;
    Ok(tmp_file)
}

pub fn to_u8_16(input: &[u8]) -> [u8; 16] {
    assert_eq!(input.len(), 16);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn to_u8_30(input: &[u8]) -> [u8; 30] {
    assert_eq!(input.len(), 30);
    let mut bytes = [0u8; 30];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn to_u8_32(input: &[u8]) -> [u8; 32] {
    assert_eq!(input.len(), 32);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn to_u8_64(input: &[u8]) -> [u8; 64] {
    assert_eq!(input.len(), 64);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn random_ristretto_ballots<G: Group<RistrettoPoint>>(
    n: usize,
    group: &G,
) -> Ballots<RistrettoPoint> {
    let cs = (0..n)
        .into_par_iter()
        .map(|_| Ciphertext {
            a: group.rnd(),
            b: group.rnd(),
        })
        .collect();

    Ballots { ciphertexts: cs }
}

pub fn random_rug_ballots<G: Group<Integer>>(n: usize, group: &G) -> Ballots<Integer> {
    let cs = (0..n)
        .into_par_iter()
        .map(|_| Ciphertext {
            a: group.encode(&group.rnd_exp()),
            b: group.encode(&group.rnd_exp()),
        })
        .collect();

    Ballots { ciphertexts: cs }
}

pub fn random_ristretto_encrypt_ballots(
    n: usize,
    pk: &PublicKey<RistrettoPoint, RistrettoGroup>,
) -> (Vec<[u8; 30]>, Vec<Ciphertext<RistrettoPoint>>) {
    let (plaintexts, cs) = (0..n)
        .into_par_iter()
        .map(|_| {
            let mut csprng = OsRng;
            let mut value = [0u8; 30];
            csprng.fill_bytes(&mut value);
            let encoded = pk.group.encode(&value);
            let encrypted = pk.encrypt(&encoded);
            (value, encrypted)
        })
        .unzip();

    (plaintexts, cs)
}

pub fn random_rug_encrypt_ballots(
    n: usize,
    pk: &PublicKey<Integer, RugGroup>,
) -> (Vec<Integer>, Vec<Ciphertext<Integer>>) {
    let (plaintexts, cs) = (0..n)
        .into_par_iter()
        .map(|_| {
            let value = pk.group.rnd_exp();
            let encoded = pk.group.encode(&value);
            let encrypted = pk.encrypt(&encoded);
            (value, encrypted)
        })
        .unzip();

    (plaintexts, cs)
}

pub fn random_encrypt_ballots<E: Element, G: Group<E>>(
    n: usize,
    pk: &PublicKey<E, G>,
) -> (Vec<E::Plaintext>, Vec<Ciphertext<E>>) {
    let plaintexts: Vec<E::Plaintext> = (0..n)
        .into_par_iter()
        .map(|_| pk.group.rnd_plaintext())
        .collect();

    let cs: Vec<Ciphertext<E>> = plaintexts
        .par_iter()
        .map(|p| {
            let encoded = pk.group.encode(&p);
            pk.encrypt(&encoded)
        })
        .collect();

    (plaintexts, cs)
}

pub(crate) fn short(input: &[u8; 64]) -> Vec<u8> {
    input[0..3].to_vec()
}
pub(crate) fn shortm(input: &[[u8; 64]; crate::protocol::MAX_TRUSTEES]) -> Vec<Vec<u8>> {
    input
        .iter()
        .cloned()
        .filter(|&a| a != [0u8; 64])
        .map(|a| a[0..3].to_vec())
        .collect()
}

pub fn type_name_of<T>(_: &T) -> String {
    std::any::type_name::<T>().to_string()
}

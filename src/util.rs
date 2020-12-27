use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Write;
use std::fs::OpenOptions;
use std::fs;
use std::io;

use rand::rngs::OsRng;
use rand::RngCore;
use curve25519_dalek::ristretto::{RistrettoPoint};
use rug::Integer;
use rayon::prelude::*;
use chrono::{DateTime, Utc};
use tempfile::NamedTempFile;
use uuid::Uuid;

use crate::group::Group;
use crate::arithm::Element;
use crate::elgamal::*;
use crate::artifact::*;
use crate::rug_b::RugGroup;
use crate::ristretto_b::RistrettoGroup;

pub fn read_file_bytes(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}

pub fn write_file_bytes(path: &Path, bytes: &Vec<u8>) -> io::Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

pub fn write_tmp(bytes: Vec<u8>) -> io::Result<NamedTempFile> {
    let tmp_file = NamedTempFile::new().unwrap();
    let path = tmp_file.path();
    fs::write(path, bytes)?;
    Ok(tmp_file)
}

pub fn to_u8_30(input: &Vec<u8>) -> [u8; 30] {
    assert_eq!(input.len(), 30);
    let mut bytes = [0u8; 30];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn to_u8_32(input: &Vec<u8>) -> [u8; 32] {
    assert_eq!(input.len(), 32);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn to_u8_64(input: &Vec<u8>) -> [u8; 64] {
    assert_eq!(input.len(), 64);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn create_random_file(dir: &str) -> PathBuf {
    let mut buff = Uuid::encode_buffer();
    let id = Uuid::new_v4().to_simple().encode_lower(&mut buff);
    let target = Path::new(dir).join(Path::new(&id));
    let mut output = File::create(target.clone()).unwrap();
    let now: DateTime<Utc> = Utc::now();
    writeln!(output, "File created at {}", now).unwrap();
    target
}

pub fn modify_file(file: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .open(file)
        .unwrap();
    
    let now: DateTime<Utc> = Utc::now();

    writeln!(file, "New line at {}", now).unwrap();
}

pub fn random_ristretto_ballots<G: Group<RistrettoPoint>>(n: usize, group: &G) -> Ballots<RistrettoPoint> {

    let cs = (0..n).into_par_iter().map(|_| {
            Ciphertext{
                a: group.rnd(),
                b: group.rnd()
            }
    }).collect();

    Ballots {
        ciphertexts: cs
    }
}

pub fn random_rug_ballots<G: Group<Integer>>(n: usize, group: &G) -> Ballots<Integer> {
    
    let cs = (0..n).into_par_iter().map(|_| {
            Ciphertext{
                a: group.encode(&group.rnd_exp()),
                b: group.encode(&group.rnd_exp())
            }
        
    }).collect();

    Ballots {
        ciphertexts: cs
    }
}

pub fn random_ristretto_encrypt_ballots(n: usize, pk: &PublicKey<RistrettoPoint, RistrettoGroup>) -> (Vec<[u8; 30]>, Vec<Ciphertext<RistrettoPoint>>) {
    
    let (plaintexts,cs) = (0..n).into_par_iter().map(|_| {
        let mut csprng = OsRng;
        let mut value = [0u8;30];
        csprng.fill_bytes(&mut value);        
        let encoded = pk.group.encode(&value);
        let encrypted = pk.encrypt(&encoded);
        (value, encrypted)
        
    }).unzip();

    
    (plaintexts, cs)
}

pub fn random_rug_encrypt_ballots(n: usize, pk: &PublicKey<Integer, RugGroup>) -> (Vec<Integer>, Vec<Ciphertext<Integer>>) {
    
    let (plaintexts,cs) = (0..n).into_par_iter().map(|_| {
            let value = pk.group.rnd_exp();
            let encoded = pk.group.encode(&value);
            let encrypted = pk.encrypt(&encoded);
            (value, encrypted)
        
    }).unzip();

    
    (plaintexts, cs)
}

pub fn random_encrypt_ballots<E: Element, G: Group<E>>(n: usize, pk: &PublicKey<E, G>) -> (Vec<E::Plaintext>, Vec<Ciphertext<E>>) {
    
    let plaintexts: Vec<E::Plaintext> = (0..n).into_par_iter().map(|_| {
        pk.group.rnd_plaintext()
    }).collect();

    let cs: Vec<Ciphertext<E>> = plaintexts.par_iter().map(|p| {
            let encoded = pk.group.encode(&p);
            let encrypted = pk.encrypt(&encoded);
            // (value, encrypted)
            encrypted
        
    }).collect();
    
    (plaintexts, cs)
}


pub(crate) fn short(input: &[u8; 64]) -> Vec<u8> {
    input[0..3].to_vec()
}
pub(crate) fn shortm(input: &[[u8; 64]; 10]) -> Vec<Vec<u8>> {
    input.iter().cloned().filter(|&a| a != [0u8; 64])
        .map(|a| a[0..3].to_vec())        
        .collect()
}

pub(crate) fn clear_zeroes(input: &[[u8; 64]; 10]) -> Vec<[u8; 64]> {
    input.iter().cloned().filter(|&a| a != [0u8; 64])  
        .collect()
}

pub fn type_name_of<T>(_: &T) -> String {
    std::any::type_name::<T>().to_string()
}
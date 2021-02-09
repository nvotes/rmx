use curve25519_dalek::ristretto::{RistrettoPoint,CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
// use sha2::{Sha512, Sha256, Digest};
use rug::{Integer,integer::Order};

use crate::crypto::base::*;
use crate::crypto::elgamal::*;
use crate::crypto::shuffler::{YChallengeInput, TValues};
use crate::util;

use ByteTree::*;

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

trait FromBytes {
    fn from_bytes(bytes: &Vec<u8>) -> Option<Self> where Self: Sized;
}
 
trait ToByteTree {
    fn to_tree(&self) -> ByteTree;
}
trait FromByteTree {
    fn from_tree(tree: &ByteTree) -> Option<Self> where Self: Sized;
}

impl ToBytes for RistrettoPoint {
    fn to_bytes(&self) -> Vec<u8> {
        self.compress().as_bytes().to_vec()
    }
}

impl ToBytes for Scalar {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ToBytes for Integer {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_digits::<u8>(Order::LsfLe)
    }
}

impl FromBytes for Scalar {
    fn from_bytes(bytes: &Vec<u8>) -> Option<Scalar> {
        let b32 = util::to_u8_32(&bytes);
        Scalar::from_canonical_bytes(b32)
    }
}

impl FromBytes for RistrettoPoint {
    fn from_bytes(bytes: &Vec<u8>) -> Option<RistrettoPoint> {
        let b32 = util::to_u8_32(&bytes);
        CompressedRistretto(b32).decompress()
    }
}

impl FromBytes for Integer {
    fn from_bytes(bytes: &Vec<u8>) -> Option<Integer> {
        let ret = Integer::from_digits(bytes, Order::LsfLe);
        Some(ret)
    }
}

impl<E: ToBytes> ToByteTree for Ciphertext<E> {
    fn to_tree(&self) -> ByteTree {
        let mut bytes: Vec<ByteTree> = Vec::with_capacity(2);
        bytes.push(ByteTree::Leaf(self.a.to_bytes()));
        bytes.push(ByteTree::Leaf(self.b.to_bytes()));
        ByteTree::Tree(bytes)
    }
}

impl<E: FromBytes> FromByteTree for Ciphertext<E> {
    
    fn from_tree(tree: &ByteTree) -> Option<Ciphertext<E>> {
        let mut ret = None;
        if let Tree(trees) = tree {
            if let (Leaf(a_), Leaf(b_)) = (&trees[0], &trees[1]) {
                let a = E::from_bytes(a_)?;
                let b = E::from_bytes(b_)?;
                ret = Some(Ciphertext {
                    a,
                    b
                });
            }
        }

        ret
    }
}

fn x<E: FromBytes>(bytes: Vec<u8>) -> Option<E> {
    E::from_bytes(&bytes)
}

fn z<E: FromByteTree>(tree: &ByteTree) -> Option<E> {
    E::from_tree(tree)
}

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
enum ByteTree {
    Leaf(Vec<u8>),
    Tree(Vec<ByteTree>)
}
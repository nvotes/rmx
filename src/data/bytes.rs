use curve25519_dalek::ristretto::{RistrettoPoint,CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::PublicKey as SPublicKey;
// use sha2::{Sha512, Sha256, Digest};
use rug::{Integer,integer::Order};

// use bincode::Result;

use crate::crypto::base::*;
use crate::crypto::elgamal::*;
use crate::data::entity::*;
use crate::crypto::shuffler::{YChallengeInput, TValues};
use crate::util;

const LEAF: u8 = 0;
const TREE: u8 = 1;

quick_error! {
    #[derive(Debug)]
    pub enum ByteError {
        Bincode(err: bincode::Error) {
            from()
        }
        Empty{}
        Custom(message: String) {
            from()
        }
    }
}

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub enum ByteTree {
    Leaf(Vec<u8>),
    Tree(Vec<ByteTree>)
}
use ByteTree::*;
// OPT: try to move instead of copy
impl ByteTree {
    
    fn to_hash_bytes(&self) -> Vec<u8> {
        
        let ret = match self {
            Leaf(bytes) => {
                let mut next: Vec<u8> = vec![];
                let length = bytes.len() as u64;
                next.push(LEAF);
                next.extend(&length.to_le_bytes());
                next.extend(bytes);

                next
            }
                
            Tree(trees) => {
                let mut next: Vec<u8> = vec![];
                let length = trees.len() as u64;
                next.push(TREE);
                next.extend(&length.to_le_bytes());
                for t in trees {
                    next.extend(t.to_hash_bytes());
                }
                next
            }
        };

        ret
    }
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait FromBytes {
    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, ByteError> where Self: Sized;
}
 
pub trait ToByteTree {
    fn to_byte_tree(&self) -> ByteTree;
}
pub trait FromByteTree {
    fn from_byte_tree(tree: &ByteTree) -> Result<Self, ByteError> where Self: Sized;
}

impl<T: ToByteTree> ToBytes for T {
    fn to_bytes(&self) -> Vec<u8> {
        let tree = self.to_byte_tree();
        bincode::serialize(&tree).unwrap()
    }
}

impl<T: FromByteTree> FromBytes for T {
    fn from_bytes(bytes: &Vec<u8>) -> Result<T, ByteError> {
        let tree: ByteTree = bincode::deserialize(bytes)?;
        T::from_byte_tree(&tree)
    }
}

impl ToBytes for Scalar {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl FromBytes for Scalar {
    fn from_bytes(bytes: &Vec<u8>) -> Result<Scalar, ByteError> {
        let b32 = util::to_u8_32(&bytes);
        Scalar::from_canonical_bytes(b32).ok_or(
            ByteError::Empty
        )
    }
}

impl ToBytes for RistrettoPoint {
    fn to_bytes(&self) -> Vec<u8> {
        self.compress().as_bytes().to_vec()
    }
}

impl FromBytes for RistrettoPoint {
    fn from_bytes(bytes: &Vec<u8>) -> Result<RistrettoPoint, ByteError> {
        let b32 = util::to_u8_32(&bytes);
        CompressedRistretto(b32).decompress().ok_or(
            ByteError::Empty
        )
    }
}

impl ToBytes for Integer {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_digits::<u8>(Order::LsfLe)
    }
}

impl FromBytes for Integer {
    fn from_bytes(bytes: &Vec<u8>) -> Result<Integer, ByteError> {
        let ret = Integer::from_digits(bytes, Order::LsfLe);
        Ok(ret)
    }
}



impl<T: ToByteTree> ToByteTree for Vec<T> {
    fn to_byte_tree(&self) -> ByteTree {
        let tree = self.iter().map(|e| e.to_byte_tree()).collect();
        ByteTree::Tree(tree)
    }
}


impl<T: FromByteTree> FromByteTree for Vec<T> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Vec<T>, ByteError> {
        if let Tree(trees) = tree {
            let elements = trees.iter().map(|b| {
                T::from_byte_tree(b)
            }).collect::<Result<Vec<T>, ByteError>>();

            elements
        } else {
            Err(ByteError::Empty)
        }   
    }
}

impl ToByteTree for SPublicKey {
    fn to_byte_tree(&self) -> ByteTree {
        ByteTree::Leaf(self.as_bytes().to_vec())
    }
}

impl<E: ToBytes, G: ToByteTree> ToByteTree for Config<E, G> {
    fn to_byte_tree(&self) -> ByteTree {
        let mut bytes: Vec<ByteTree> = Vec::with_capacity(2);
        bytes.push(ByteTree::Leaf(self.id.to_vec()));
        bytes.push(self.group.to_byte_tree());
        bytes.push(ByteTree::Leaf(self.contests.to_le_bytes().to_vec()));
        bytes.push(self.ballotbox.to_byte_tree());
        bytes.push(self.trustees.to_byte_tree());
        ByteTree::Tree(bytes)
    }
}

impl<E: ToBytes, G: ToByteTree> FromByteTree for Config<E, G> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Config<E, G>, ByteError> {
        Err(ByteError::Custom(String::from("Not implemented")))
    }
}


/*
impl<T: ToBytes> ToByteTree for  {
    fn to_byte_tree(&self) -> ByteTree {
    }
}

impl<T: FromBytes> FromByteTree for  {
    fn from_byte_tree(tree: &ByteTree) -> Option<T> {
    }
}
*/

/* pub struct Config<E, G> {
    pub id: [u8; 16],
    pub group: G,
    pub contests: u32, 
    pub ballotbox: SPublicKey, 
    pub trustees: Vec<SPublicKey>,
    pub phantom_e: PhantomData<E>
}


pub struct Keyshare<E: Element, G> {
    pub share: PublicKey<E, G>,
    pub proof: Schnorr<E>,
    pub encrypted_sk: EncryptedPrivateKey
}


pub struct EncryptedPrivateKey {
    pub bytes: Vec<u8>,
    pub iv: Vec<u8>
}


pub struct Ballots<E> {
    pub ciphertexts: Vec<Ciphertext<E>>
}


pub struct Mix<E: Element> {
    pub mixed_ballots: Vec<Ciphertext<E>>,
    pub proof: ShuffleProof<E>
}


pub struct PartialDecryption<E: Element> {
    pub pd_ballots: Vec<E>,
    pub proofs: Vec<ChaumPedersen<E>>
}


pub struct Plaintexts<E> {
    pub plaintexts: Vec<E>
}


pub struct Schnorr<E: Element> {
    pub commitment: E,
    pub challenge: E::Exp,
    pub response: E::Exp
}


pub struct ChaumPedersen<E: Element> {
    pub commitment1: E,
    pub commitment2: E,
    pub challenge: E::Exp,
    pub response: E::Exp
}
*/

impl<E: ToBytes> ToByteTree for Ciphertext<E> {
    fn to_byte_tree(&self) -> ByteTree {
        let mut bytes: Vec<ByteTree> = Vec::with_capacity(2);
        bytes.push(ByteTree::Leaf(self.a.to_bytes()));
        bytes.push(ByteTree::Leaf(self.b.to_bytes()));
        ByteTree::Tree(bytes)
    }
}

impl<E: FromBytes> FromByteTree for Ciphertext<E> {
    
    fn from_byte_tree(tree: &ByteTree) -> Result<Ciphertext<E>, ByteError> {
        let mut ret = Err(ByteError::Empty);
        if let Tree(trees) = tree {
            if let (Leaf(a_), Leaf(b_)) = (&trees[0], &trees[1]) {
                let a = E::from_bytes(a_)?;
                let b = E::from_bytes(b_)?;
                ret = Ok(Ciphertext {
                    a,
                    b
                });
            }
        }

        ret
    }
}

#[cfg(test)]
mod tests {  
    use crate::data::entity::*;
    use crate::data::bytes::*;
    use crate::crypto::backend::ristretto_b::*;
    use crate::crypto::backend::rug_b::*;

    #[test]
    fn test_ciphertext_bytes() {
        let group = RugGroup::default();
        let c = util::random_rug_ballots(1, &group).ciphertexts.remove(0);
        let bytes = c.to_bytes();
        let back: Ciphertext<Integer> = Ciphertext::<Integer>::from_bytes(&bytes).unwrap();

        assert!(c.a == back.a && c.b == back.b);
    }
}
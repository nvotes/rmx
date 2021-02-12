use std::marker::PhantomData;
use std::convert::TryInto;

use curve25519_dalek::ristretto::{RistrettoPoint,CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::PublicKey as SPublicKey;
// use sha2::{Sha512, Sha256, Digest};
use rug::{Integer,integer::Order};

use crate::crypto::base::*;
use crate::crypto::backend::rug_b::*;
use crate::crypto::backend::ristretto_b::*;
use crate::crypto::elgamal::*;
use crate::data::entity::*;
use crate::crypto::shuffler::{YChallengeInput, TValues};
use crate::util;

const LEAF: u8 = 0;
const TREE: u8 = 1;

quick_error! {
    #[derive(Debug)]
    pub enum ByteError {
        Empty{}
        Bincode(err: bincode::Error) {
            from()
        }
        Signature(err: ed25519_dalek::SignatureError) {
            from()
        }
        Msg(message: String) {
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
    
    fn to_hashable_bytes(&self) -> Vec<u8> {
        
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
                    next.extend(t.to_hashable_bytes());
                }
                next
            }
        };

        ret
    }

    fn leaf(&self) -> Result<&Vec<u8>, ByteError> {
        if let Leaf(bytes) = self {
            Ok(bytes)
        }
        else {
            Err(ByteError::Msg(String::from("ByteTree: unexpected Tree")))
        }
    }

    fn tree(&self, length: usize) -> Result<&Vec<ByteTree>, ByteError> {
        if let Tree(trees) = self {
            if trees.len() == length {
                Ok(trees)
            }
            else {
                Err(ByteError::Msg(String::from("ByteTree: size mismatch")))
            }
        }
        else {
            Err(ByteError::Msg(String::from("ByteTree: unexpected Leaf")))
        }
    }
}
 
pub trait ToByteTree {
    fn to_byte_tree(&self) -> ByteTree;
}
pub trait FromByteTree {
    fn from_byte_tree(tree: &ByteTree) -> Result<Self, ByteError> where Self: Sized;
}

pub trait Ser {
    fn ser(&self) -> Vec<u8>;
}

pub trait Deser {
    fn deser(bytes: &Vec<u8>) -> Result<Self, ByteError> where Self: Sized;
}

impl<T: ToByteTree> Ser for T {
    fn ser(&self) -> Vec<u8> {
        let tree = self.to_byte_tree();
        bincode::serialize(&tree).unwrap()
    }
}

impl<T: FromByteTree> Deser for T {
    fn deser(bytes: &Vec<u8>) -> Result<T, ByteError> {
        let tree: ByteTree = bincode::deserialize(bytes)?;
        T::from_byte_tree(&tree)
    }
}

impl ToByteTree for Scalar {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(self.as_bytes().to_vec())
    }
}

impl FromByteTree for Scalar {
    fn from_byte_tree(tree: &ByteTree) -> Result<Scalar, ByteError> {
        let bytes = tree.leaf()?;
        let b32 = util::to_u8_32(&bytes);
        Scalar::from_canonical_bytes(b32).ok_or(
            ByteError::Empty
        )
    }
}

impl ToByteTree for RistrettoPoint {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(self.compress().as_bytes().to_vec())
    }
}

impl FromByteTree for RistrettoPoint {
    fn from_byte_tree(tree: &ByteTree) -> Result<RistrettoPoint, ByteError> {
        let bytes = tree.leaf()?;
        let b32 = util::to_u8_32(&bytes);
        CompressedRistretto(b32).decompress().ok_or(
            ByteError::Empty
        )
    }
}

impl ToByteTree for Integer {
    fn to_byte_tree(&self) -> ByteTree {
        Leaf(self.to_digits::<u8>(Order::LsfLe))
    }
}

impl FromByteTree for Integer {
    fn from_byte_tree(tree: &ByteTree) -> Result<Integer, ByteError> {
        let bytes = tree.leaf()?;
        let ret = Integer::from_digits(bytes, Order::LsfLe);
        Ok(ret)
    }
}

impl ToByteTree for RugGroup {
    fn to_byte_tree(&self) -> ByteTree {
        let mut bytes: Vec<ByteTree> = Vec::with_capacity(4);
        bytes.push(self.generator.to_byte_tree());
        bytes.push(self.modulus.to_byte_tree());
        bytes.push(self.modulus_exp.to_byte_tree());
        bytes.push(self.co_factor.to_byte_tree());
        ByteTree::Tree(bytes)
    }
}

impl FromByteTree for RugGroup {
    fn from_byte_tree(tree: &ByteTree) -> Result<RugGroup, ByteError> {
        Err(ByteError::Empty)
    }
}

impl<T: ToByteTree> ToByteTree for Vec<T> {
    fn to_byte_tree(&self) -> ByteTree {
        let tree = self.iter().map(|e| {
            e.to_byte_tree()
        }).collect();
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

impl FromByteTree for SPublicKey {
    fn from_byte_tree(tree: &ByteTree) -> Result<SPublicKey, ByteError> {
        if let Leaf(bytes) = tree {
            let signature = SPublicKey::from_bytes(bytes)?;
            Ok(signature)
        }
        else {
            Err(ByteError::Msg(String::from("Expected leaf, found tree")))
        }
    }
}

impl<E: ToByteTree, G: ToByteTree> ToByteTree for Config<E, G> {
    fn to_byte_tree(&self) -> ByteTree {
        let mut trees: Vec<ByteTree> = Vec::with_capacity(5);
        trees.push(ByteTree::Leaf(self.id.to_vec()));
        trees.push(self.group.to_byte_tree());
        trees.push(ByteTree::Leaf(self.contests.to_le_bytes().to_vec()));
        trees.push(self.ballotbox.to_byte_tree());
        trees.push(self.trustees.to_byte_tree());
        ByteTree::Tree(trees)
    }
}

impl<E, G: FromByteTree> FromByteTree for Config<E, G> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Config<E, G>, ByteError> {
        let trees = tree.tree(5)?;
        let id_ = trees[0].leaf()?;
        let id = util::to_u8_16(id_);
        let group = G::from_byte_tree(&trees[1])?;
        let contests_ = trees[2].leaf()?;
        let contests = u32::from_le_bytes(contests_.as_slice().try_into().unwrap());
        let ballotbox = SPublicKey::from_byte_tree(&trees[3])?;
        let trustees = Vec::<SPublicKey>::from_byte_tree(&trees[4])?;
        let config = Config {
            id, group, contests, ballotbox, trustees, phantom_e: PhantomData
        };
        Ok(config)
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

impl<E: ToByteTree> ToByteTree for Ciphertext<E> {
    fn to_byte_tree(&self) -> ByteTree {
        let mut bytes: Vec<ByteTree> = Vec::with_capacity(2);
        bytes.push(self.a.to_byte_tree());
        bytes.push(self.b.to_byte_tree());
        ByteTree::Tree(bytes)
    }
}

impl<E: FromByteTree> FromByteTree for Ciphertext<E> {
    fn from_byte_tree(tree: &ByteTree) -> Result<Ciphertext<E>, ByteError> {
        let trees = tree.tree(2)?;
        let a = E::from_byte_tree(&trees[0])?;
        let b = E::from_byte_tree(&trees[1])?;
        Ok(Ciphertext {
            a,
            b
        })
    }
}

#[cfg(test)]
mod tests {  
    use crate::data::entity::*;
    use crate::data::bytes::*;
    use crate::crypto::backend::ristretto_b::*;
    use crate::crypto::backend::rug_b::*;

    use uuid::Uuid;
    use rug::Integer;
    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;

    #[test]
    fn test_ciphertext_bytes() {
        let group = RugGroup::default();
        let c = util::random_rug_ballots(1, &group).ciphertexts.remove(0);
        let bytes = c.ser();
        let back: Ciphertext<Integer> = Ciphertext::<Integer>::deser(&bytes).unwrap();

        assert!(c.a == back.a && c.b == back.b);
    }

    fn test_config_bytes() {
        let mut csprng = OsRng;
        let group = RugGroup::default();
        let id = Uuid::new_v4();
        let contests = 2;
        let ballotbox_pk = Keypair::generate(&mut csprng).public; 
        let trustees = 3;
        let mut trustee_pks = Vec::with_capacity(trustees);
        
        for _ in 0..trustees {
            let keypair = Keypair::generate(&mut csprng);
            trustee_pks.push(keypair.public);
        }
        let cfg: Config<Integer, RugGroup> = Config {
            id: id.as_bytes().clone(),
            group: group,
            contests: contests, 
            ballotbox: ballotbox_pk, 
            trustees: trustee_pks,
            phantom_e: PhantomData
        };

        let bytes = cfg.ser();
    }
}
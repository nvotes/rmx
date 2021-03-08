use std::marker::{Send, Sync};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha512, Sha256, Digest};
use rug::{Integer,integer::Order};

use crate::crypto::base::*;
use crate::crypto::elgamal::*;
use crate::crypto::shuffler::{YChallengeInput, TValues};

pub type Hash = [u8; 64];

trait ConcatWithLength  {
    fn extendl(&mut self, add: &Vec<u8>);
}

impl ConcatWithLength for Vec<u8> {
    fn extendl(&mut self, add: &Vec<u8>) {
        let length = add.len() as u64;
        self.extend(&length.to_le_bytes());
        self.extend(add);
    }
}

pub trait HashBytes {
    fn get_bytes(&self) -> Vec<u8>;
}

pub trait HashTo<T>: Send + Sync {
    fn hash_to(&self, bytes: &[u8]) -> T;
}

pub struct RugHasher(pub Integer);
pub struct RistrettoHasher;

impl HashTo<Scalar> for RistrettoHasher {
    fn hash_to(&self, bytes: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        Scalar::from_hash(hasher)
    }
}

impl HashTo<RistrettoPoint> for RistrettoHasher {
    fn hash_to(&self, bytes: &[u8]) -> RistrettoPoint {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        RistrettoPoint::from_hash(hasher)
    }
}

impl HashTo<Integer> for RugHasher {
    fn hash_to(&self, bytes: &[u8]) -> Integer {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        let hashed = hasher.finalize();

        let (_, rem) = Integer::from_digits(&hashed, Order::Lsf)
            .div_rem(self.0.clone());

        rem
    }
}

// https://stackoverflow.com/questions/39675949/is-there-a-trait-supplying-iter
fn concat_bytes_iter<'a, H: 'a + HashBytes, I: IntoIterator<Item = &'a H>>(cs: I) -> Vec<u8> {
    cs.into_iter()
    .map(|x| x.get_bytes())
    .fold(vec![], |mut a, b| {
        let length = b.len() as u64;
        a.extend(&length.to_le_bytes());
        a.extend(b);
        a
    })
}

fn concat_bytes<T: HashBytes>(cs: &Vec<T>) -> Vec<u8> {
    concat_bytes_iter(cs)
}

pub fn shuffle_proof_us<E: Element>(es: &Vec<Ciphertext<E>>, e_primes: &Vec<Ciphertext<E>>, 
    cs: &Vec<E>, exp_hasher: &dyn HashTo<E::Exp>, n: usize) -> Vec<E::Exp> {
    
    let mut prefix_vector = concat_bytes(es);
    prefix_vector.extend(concat_bytes(e_primes));
    prefix_vector.extend(concat_bytes(cs));
    
    // optimization: instead of calculating u = H(prefix || i), 
    // we do u = H(H(prefix) || i)
    // that way we avoid allocating prefix-size bytes n times
    let mut hasher = Sha512::new();
    hasher.update(prefix_vector);
    let prefix_hash = hasher.finalize().to_vec();
    let mut ret = Vec::with_capacity(n);
    
    for i in 0..n {
        let mut next = prefix_hash.clone();
        next.extendl(&i.to_le_bytes().to_vec());
        
        let u: E::Exp = exp_hasher.hash_to(&next);
        ret.push(u);
    }

    ret
}

pub fn shuffle_proof_challenge<E: Element, G: Group<E>>(y: &YChallengeInput<E, G>, 
    t: &TValues<E>, exp_hasher: &dyn HashTo<E::Exp>) -> E::Exp {

    let mut bytes = concat_bytes(&y.es);
    bytes.extend(concat_bytes(&y.e_primes));
    bytes.extend(concat_bytes(&y.cs));
    bytes.extend(concat_bytes(&y.c_hats));
    bytes.extend(y.pk.value.get_bytes());
    
    bytes.extend(t.t1.get_bytes());
    bytes.extend(t.t2.get_bytes());
    bytes.extend(t.t3.get_bytes());
    bytes.extend(t.t4_1.get_bytes());
    bytes.extend(t.t4_2.get_bytes());
    bytes.extend(concat_bytes(&t.t_hats));

    exp_hasher.hash_to(&bytes)
}

pub fn schnorr_proof_challenge<E: Element>(g: &E, public: &E, 
    commitment: &E, exp_hasher: &dyn HashTo<E::Exp>) -> E::Exp {
    let values = [g, public, commitment].to_vec();

    let bytes = concat_bytes_iter(values);
    exp_hasher.hash_to(&bytes)
}

pub fn cp_proof_challenge<E: Element>(g1: &E, g2: &E, public1: &E, public2: &E, 
    commitment1: &E, commitment2: &E, exp_hasher: &dyn HashTo<E::Exp>) -> E::Exp {
    let values = [g1, g2, public1, public2, commitment1, commitment2].to_vec();
    
    let bytes = concat_bytes_iter(values);
    exp_hasher.hash_to(&bytes)
}

use crate::util;
use crate::data::bytes::ToByteTree;

pub fn hash<T: HashBytes>(data: &T) -> [u8; 64] {
    let bytes = data.get_bytes();
    hash_bytes(bytes)
}

pub fn hash_<T: ToByteTree>(data: &T) -> [u8; 64] {
    let tree = data.to_byte_tree();
    let bytes = tree.to_hashable_bytes();
    hash_bytes(bytes)
}

pub fn hash_bytes(bytes: Vec<u8>) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    util::to_u8_64(&hasher.finalize().to_vec())
}

// We only use this variant for seeding rngs when deriving independent generators
pub fn hash_bytes_256(bytes: Vec<u8>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    util::to_u8_32(&hasher.finalize().to_vec())
}

impl<E: Element + HashBytes> HashBytes for Ciphertext<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut ret = self.a.get_bytes();
        ret.extend(self.b.get_bytes());

        ret
    }
}

impl HashBytes for RistrettoPoint {
    fn get_bytes(&self) -> Vec<u8> {
        self.compress().as_bytes().to_vec()
    }
}

impl HashBytes for Scalar {
    fn get_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl HashBytes for Integer {
    fn get_bytes(&self) -> Vec<u8> {
        self.to_digits::<u8>(Order::LsfLe)
    }
}

use crate::crypto::backend::rug_b::RugGroup;

impl HashBytes for RugGroup {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.generator.get_bytes();
        bytes.extend(self.modulus.get_bytes());
        bytes.extend(self.modulus_exp.get_bytes());

        bytes
    }
}

impl HashBytes for Option<RugGroup> {
    fn get_bytes(&self) -> Vec<u8> {
        match self {
            Some(g) => g.get_bytes(),
            None => vec![]
        }
    }
}

use crate::crypto::backend::ristretto_b::RistrettoGroup;

impl HashBytes for RistrettoGroup {
    fn get_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

use crate::crypto::base::Schnorr;
use crate::crypto::base::ChaumPedersen;

impl<E: Element> HashBytes for Schnorr<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.commitment.get_bytes();
        bytes.extend(self.challenge.get_bytes());
        bytes.extend(self.response.get_bytes());

        bytes
    }
}

impl<E: Element> HashBytes for ChaumPedersen<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.commitment1.get_bytes();
        bytes.extend(self.commitment2.get_bytes());
        bytes.extend(self.challenge.get_bytes());
        bytes.extend(self.response.get_bytes());

        bytes
    }
}

use crate::crypto::shuffler::ShuffleProof;
use crate::crypto::shuffler::Responses;

impl<E: Element> HashBytes for TValues<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.t1.get_bytes();
        bytes.extend(self.t2.get_bytes());
        bytes.extend(self.t3.get_bytes());
        bytes.extend(self.t4_1.get_bytes());
        bytes.extend(self.t4_2.get_bytes());
        bytes.extend(concat_bytes(&self.t_hats));

        bytes
    }
}

impl<E: Element> HashBytes for Responses<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.s1.get_bytes();
        bytes.extend(self.s2.get_bytes());
        bytes.extend(self.s3.get_bytes());
        bytes.extend(self.s4.get_bytes());
        bytes.extend(concat_bytes(&self.s_hats));
        bytes.extend(concat_bytes(&self.s_primes));

        bytes
    }
}

impl<E: Element> HashBytes for ShuffleProof<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.t.get_bytes();
        bytes.extend(self.s.get_bytes());
        bytes.extend(concat_bytes(&self.cs));
        bytes.extend(concat_bytes(&self.c_hats));

        bytes
    }
}

use crate::crypto::elgamal::PrivateKey;
use crate::crypto::elgamal::PublicKey;

impl<E: Element, G: Group<E>> HashBytes for PrivateKey<E, G> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.value.get_bytes();
        bytes.extend(self.public_value.get_bytes());
        bytes.extend(self.group.get_bytes());

        bytes
    }
}

impl<E: Element, G: Group<E>> HashBytes for PublicKey<E, G> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.value.get_bytes();
        bytes.extend(self.group.get_bytes());

        bytes
    }
}

use ed25519_dalek::PublicKey as SPublicKey;

impl HashBytes for SPublicKey {
    fn get_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

use ed25519_dalek::Signature;

impl HashBytes for Signature {
    fn get_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

use crate::protocol::statement::Statement;
use crate::protocol::statement::SignedStatement;

impl HashBytes for Statement {
    fn get_bytes(&self) -> Vec<u8> {
        let discriminant = self.stype as u8;
        let mut bytes: Vec<u8> = vec![discriminant];
        bytes.extend(&self.contest.to_le_bytes());
        
        for b in self.hashes.iter() {
            bytes.extend(b);
        }

        bytes
    }
}

impl HashBytes for SignedStatement {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.statement.get_bytes();
        bytes.extendl(&self.signature.get_bytes());
        
        bytes
    }
}

use crate::data::artifact::Config;

impl<E: Element, G: Group<E>> HashBytes for Config<E, G> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.id.to_vec();
        bytes.extend(self.group.get_bytes());
        bytes.extend(&self.contests.to_le_bytes());
        bytes.extend(self.ballotbox.get_bytes());
        bytes.extend(concat_bytes(&self.trustees));

        bytes
    }
}

use crate::data::artifact::Keyshare;

impl<E: Element, G: Group<E>> HashBytes for Keyshare<E, G> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.share.get_bytes();
        bytes.extend(self.proof.get_bytes());

        bytes
    }
}

use crate::data::artifact::EncryptedPrivateKey;

impl HashBytes for EncryptedPrivateKey {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.bytes.to_vec();
        bytes.extend(self.iv.clone());

        bytes
    }
}

use crate::data::artifact::Ballots;

impl<E: Element> HashBytes for Ballots<E> {
    fn get_bytes(&self) -> Vec<u8> {
        concat_bytes(&self.ciphertexts)
    }
}

use crate::data::artifact::Mix;

impl<E: Element> HashBytes for Mix<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = concat_bytes(&self.mixed_ballots);
        bytes.extend(self.proof.get_bytes());

        bytes
    }
}

use crate::data::artifact::PartialDecryption;

impl<E: Element> HashBytes for PartialDecryption<E> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = concat_bytes(&self.pd_ballots);
        bytes.extend(concat_bytes(&self.proofs));

        bytes
    }
}

use crate::data::artifact::Plaintexts;

impl<E: Element> HashBytes for Plaintexts<E> {
    fn get_bytes(&self) -> Vec<u8> {
        concat_bytes(&self.plaintexts)
    }
}

use crate::protocol::facts::Act;

impl HashBytes for Hash {
    fn get_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl HashBytes for Act {
    fn get_bytes(&self) -> Vec<u8> {
        match self {
            Act::CheckConfig(h) => {
                let mut v = vec![1u8];
                v.extendl(&h.to_vec());
                v
            },
            Act::PostShare(h, i) => {
                let mut v = vec![2u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v
            },
            Act::CombineShares(h, i, s) => {
                let mut v = vec![3u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&concat_bytes_iter(s));
                v
            },
            Act::CheckPk(h, i, pk, s) => {
                let mut v = vec![4u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&pk.to_vec());
                v.extendl(&concat_bytes_iter(s));
                v
            },
            Act::Mix(h, i, bs, pk_h) => {
                let mut v = vec![5u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&bs.to_vec());
                v.extendl(&pk_h.to_vec());
                v
            }
            Act::CheckMix(h, i, t, m, bs, pk_h) => {
                let mut v = vec![6u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&t.to_le_bytes().to_vec());
                v.extendl(&m.to_vec());
                v.extendl(&bs.to_vec());
                v.extendl(&pk_h.to_vec());
                v
            }
            Act::PartialDecrypt(h, i, bs, share_h) => {
                let mut v = vec![7u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&bs.to_vec());
                v.extendl(&share_h.to_vec());
                v
            }
            Act::CombineDecryptions(h, i, ds, mix_h, shares) => {
                let mut v = vec![8u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&concat_bytes_iter(ds));
                v.extendl(&mix_h.to_vec());
                v.extendl(&concat_bytes_iter(shares));
                v
            }
            Act::CheckPlaintexts(h, i, p, ds, m, shares) => {
                let mut v = vec![9u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&p.to_vec());
                v.extendl(&concat_bytes_iter(ds));
                v.extendl(&m.to_vec());
                v.extendl(&concat_bytes_iter(shares));
                v
            }
        }
    }
}

#[cfg(test)]
mod tests {  
    // use hex_literal::hex;
    use sha2::{Sha512, Digest};
    use rand::RngCore;  
    use rand::rngs::OsRng;
    use rug::{
        Integer,
        integer::Order
    };
    
    #[test]
    fn test_sha512() {
        
        // create a Sha256 object
        let mut hasher = Sha512::new();

        // write input message
        hasher.update(b"hello world");

        // read hash digest and consume hasher
        let mut result = [0u8;64];
        let bytes = hasher.finalize();
        result.copy_from_slice(bytes.as_slice());
    }

    #[test]
    fn test_rug_endian() {
        
        let mut csprng = OsRng;
        let value = csprng.next_u64();
        let i = Integer::from(value);

        let b1 = value.to_le_bytes().to_vec();
        let b2 = i.to_digits::<u8>(Order::LsfLe);

        assert_eq!(b1, b2);
    }

}

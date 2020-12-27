use serde::{Deserialize, Serialize};
use generic_array::{typenum::U32, GenericArray};

use crate::arithm::*;
use crate::group::*;
use crate::artifact::EncryptedPrivateKey;
use crate::symmetric;

#[derive(Serialize, Deserialize, Clone)]
pub struct Ciphertext<E> {
    pub a: E,
    pub b: E
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey<E, G> {
    pub value: E,
    pub group: G
}

impl<E: Element, G: Group<E>> PublicKey<E, G> {
    pub fn encrypt(&self, plaintext: &E) -> Ciphertext<E> {
        
        let randomness = self.group.rnd_exp();
        Ciphertext {
            a: plaintext.mul(&self.value.mod_pow(&randomness, &self.group.modulus()))
                .modulo(&self.group.modulus()),
            b: self.group.generator().mod_pow(&randomness, &self.group.modulus())
        }
    }
    pub fn from(pk_value: &E, group: &G) -> PublicKey<E, G> {
        PublicKey {
            value: pk_value.clone(),
            group: group.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKey<E: Element, G> {
    pub value: E::Exp,
    pub public_value: E,
    pub group: G
}

impl<E: Element, G: Group<E>> PrivateKey<E, G> {
    pub fn decrypt(&self, c: &Ciphertext<E>) -> E {
        let modulus = &self.group.modulus();
        
        c.a.div(&c.b.mod_pow(&self.value, modulus), modulus)
            .modulo(modulus)
    }
    pub fn decrypt_and_prove(&self, c: &Ciphertext<E>) -> (E, ChaumPedersen<E>) {
        let modulus = &self.group.modulus();
        
        let dec_factor = &c.b.mod_pow(&self.value, modulus);

        let proof = self.group.cp_prove(&self.value, &self.public_value, 
            dec_factor, &self.group.generator(), &c.b);
        
        let decrypted = c.a.div(dec_factor, modulus)
            .modulo(modulus);

        (decrypted, proof)
    }
    pub fn decryption_factor(&self, c: &Ciphertext<E>) -> E {
        let modulus = &self.group.modulus();

        c.b.mod_pow(&self.value, modulus)
    }
    pub fn from(secret: &E::Exp, group: &G) -> PrivateKey<E, G> {
        let public_value = group.generator().mod_pow(&secret, &group.modulus());
        PrivateKey {
            value: secret.clone(),
            group: group.clone(),
            public_value: public_value
        }
    }
    pub fn to_encrypted(&self, key: GenericArray<u8, U32>) -> EncryptedPrivateKey {
        let key_bytes = bincode::serialize(&self.value).unwrap();
        let (b, iv) = symmetric::encrypt(key, &key_bytes);
        EncryptedPrivateKey {
            bytes: b,
            iv: iv
        }
    }
    pub fn from_encrypted(key: GenericArray<u8, U32>, encrypted: EncryptedPrivateKey, group: &G) -> PrivateKey<E, G> {
        let key_bytes = symmetric::decrypt(key, &encrypted.iv, &encrypted.bytes);
        let value: E::Exp = bincode::deserialize(&key_bytes).unwrap();
        let public_value = group.generator().mod_pow(&value, &group.modulus());

        PrivateKey {
            value: value.clone(),
            group: group.clone(),
            public_value: public_value
        }
    }
}
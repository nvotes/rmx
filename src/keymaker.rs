use generic_array::{typenum::U32, GenericArray};
use rayon::prelude::*;

use crate::artifact::EncryptedPrivateKey;
use crate::arithm::*;
use crate::group::*;
use crate::elgamal::*;

pub struct Keymaker<E: Element, G> {
    sk: PrivateKey<E, G>,
    pk: PublicKey<E, G>
}

impl<E: Element, G: Group<E>> Keymaker<E, G> {
    
    pub fn gen(group: &G) -> Keymaker<E, G> {
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value.clone(), group);
        
        Keymaker {
            sk: sk,
            pk: pk
        }
    }

    pub fn from_sk(sk: PrivateKey<E, G>, group: &G) -> Keymaker<E, G> {
        let pk = PublicKey::from(&sk.public_value.clone(), group);
        
        Keymaker {
            sk: sk,
            pk: pk
        }
    }
    
    pub fn share(&self) -> (PublicKey<E, G>, Schnorr<E>) {
        let group = &self.sk.group;
        let pk = group.pk_from_value(&self.pk.value);

        let proof = group.schnorr_prove(&self.sk.value, &pk.value, &group.generator());

        (pk, proof)

    }

    pub fn get_encrypted_sk(&self, symmetric: GenericArray<u8, U32>) -> EncryptedPrivateKey {
        self.sk.to_encrypted(symmetric)
    }

    pub fn verify_share(group: &G, pk: &PublicKey<E, G>, proof: &Schnorr<E>) -> bool {
        group.schnorr_verify(&pk.value, &group.generator(), &proof)
    }

    pub fn combine_pks(group: &G, pks: Vec<PublicKey<E, G>>) -> PublicKey<E, G> {
        let mut acc: E = pks[0].value.clone();
        for i in 1..pks.len() {
            acc = acc.mul(&pks[i].value).modulo(&group.modulus());
        }

        group.pk_from_value(&acc)
    }
    
    pub fn decryption_factor(&self, c: &Ciphertext<E>) -> (E, ChaumPedersen<E>) {
        let group = &self.sk.group;
        let dec_factor = self.sk.decryption_factor(c);

        let proof = group.cp_prove(&self.sk.value, &self.pk.value, &dec_factor, 
            &group.generator(), &c.b);

        
        (dec_factor, proof)
    }

    pub fn decryption_factor_many(&self, cs: &Vec<Ciphertext<E>>) -> 
        (Vec<E>, Vec<ChaumPedersen<E>>) {

        let decs_proofs: (Vec<E>, Vec<ChaumPedersen<E>>) = cs.par_iter().map(|c| {
            self.decryption_factor(c)
        }).unzip();
        
        decs_proofs
    }

    pub fn joint_dec(group: &G, decs: Vec<E>, c: &Ciphertext<E>) -> E {
        let mut acc: E = decs[0].clone();
        for i in 1..decs.len() {
            acc = acc.mul(&decs[i]).modulo(&group.modulus());
        }

        c.a.div(&acc, &group.modulus()).modulo(&group.modulus())
    }

    pub fn joint_dec_many(group: &G, decs: &Vec<Vec<E>>, cs: &Vec<Ciphertext<E>>) -> Vec<E> {
        let modulus = group.modulus();
        let decrypted: Vec<E> = cs.par_iter().enumerate().map(|(i, c)| {
            let mut acc: E = decs[0][i].clone();
            for j in 1..decs.len() {
                acc = acc.mul(&decs[j][i]).modulo(&modulus);
            }
            c.a.div(&acc, &modulus).modulo(&modulus)

        }).collect();

        decrypted
    }

    pub fn verify_decryption_factors(group: &G, pk_value: &E, ciphertexts: &Vec<Ciphertext<E>>, 
        decs: &Vec<E>, proofs: &Vec<ChaumPedersen<E>>) -> bool {
        
        assert_eq!(decs.len(), proofs.len());
        assert_eq!(decs.len(), ciphertexts.len());
        let generator = group.generator();
        let bools: Vec<bool> = (0..decs.len()).into_par_iter().map(|i| {
            group.cp_verify(pk_value, &decs[i], &generator, &ciphertexts[i].b, &proofs[i])
        }).collect();

        !bools.contains(&false)
    }
}
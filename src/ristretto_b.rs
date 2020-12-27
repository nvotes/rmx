use rand::rngs::OsRng;
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::traits::Identity;

use crate::arithm::*;
use crate::elgamal::*;
use crate::group::*;
use crate::hashing::{HashTo, RistrettoHasher, hash_bytes_256};
use crate::util;

impl Element for RistrettoPoint {
    type Exp = Scalar;
    type Plaintext = [u8; 30];

    fn mul(&self, other: &Self) -> Self {
        self + other
    }
    fn div(&self, other: &Self, _modulus: &Self) -> Self {
        self - other
    }
    fn mod_pow(&self, other: &Self::Exp, _modulus: &Self) -> Self {
        self * other
    }
    fn modulo(&self, _modulus: &Self) -> Self {
        *self
    }
    fn eq(&self, other: &RistrettoPoint) -> bool {
        self == other
    }
    fn mul_identity() -> RistrettoPoint {
        RistrettoPoint::identity()
    }
}

impl Exponent for Scalar {
    fn add(&self, other: &Scalar) -> Scalar {
        self + other
    }
    fn sub(&self, other: &Scalar) -> Scalar {
        self - other
    }
    fn neg(&self) -> Scalar {
        -self
    }
    fn mul(&self, other: &Scalar) -> Scalar {
        self * other
    }
    fn modulo(&self, _modulus: &Scalar) -> Scalar {
        *self   
    }
    fn eq(&self, other: &Scalar) -> bool {
        self == other
    }
    fn add_identity() -> Scalar {
        Scalar::zero()
    }
    fn mul_identity() -> Scalar {
        Scalar::one()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RistrettoGroup;

impl RistrettoGroup {
    fn encode_test(&self, data: [u8;30]) -> (RistrettoPoint, usize) {
        let mut bytes = [0u8; 32];
        bytes[1..1 + data.len()].copy_from_slice(&data);
        for j in 0..64 {
            bytes[31] = j as u8;
            for i in 0..128 {
                bytes[0] = 2 * i as u8;
                if let Some(point) = CompressedRistretto(bytes).decompress() {
                    return (point, i + j * 128);
                }
            }
        }
        panic!("a very unlikely event occurred");
    }
    
}

impl Group<RistrettoPoint> for RistrettoGroup {
    fn generator(&self) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_POINT
    }
    fn rnd(&self) -> RistrettoPoint {
        let mut rng = OsRng;
        RistrettoPoint::random(&mut rng)
    }
    fn modulus(&self) -> RistrettoPoint {
        RistrettoPoint::default()
    }
    fn rnd_exp(&self) -> Scalar {
        let mut rng = OsRng;
        Scalar::random(&mut rng)
    }
    fn rnd_plaintext(&self) -> [u8; 30] {
        let mut csprng = OsRng;
        let mut value = [0u8;30];
        csprng.fill_bytes(&mut value);

        value
    }
    fn exp_modulus(&self) -> Scalar {
        Scalar::default()
    }

    // see https://github.com/ruescasd/rmx-mg/issues/4
    fn encode(&self, data: &[u8; 30]) -> RistrettoPoint {
        let mut bytes = [0u8; 32];
        bytes[1..1 + data.len()].copy_from_slice(data);
        for j in 0..64 {
            bytes[31] = j as u8;
            for i in 0..128 {
                bytes[0] = 2 * i as u8;
                if let Some(point) = CompressedRistretto(bytes).decompress() {
                    return point;
                }
            }
        }
        panic!("Failed to encode into ristretto point");
    }
    fn decode(&self, element: &RistrettoPoint) -> [u8; 30] {
        let compressed = element.compress();
        let slice = &compressed.as_bytes()[1..31];
        util::to_u8_30(&slice.to_vec())
    }
    fn gen_key(&self) -> PrivateKey<RistrettoPoint, Self> {
        let secret = self.rnd_exp();
        PrivateKey::from(&secret, self)
    }
    fn pk_from_value(&self, value: &RistrettoPoint) -> PublicKey<RistrettoPoint, Self> {
        PublicKey::from(&value, &self.clone())
    }

    fn exp_hasher(&self) -> Box<dyn HashTo<Scalar>> {
        Box::new(RistrettoHasher)
    }

    fn elem_hasher(&self) -> Box<dyn HashTo<RistrettoPoint>> {
        Box::new(RistrettoHasher)
    }
    
    fn generators(&self, size: usize, contest: u32, seed: Vec<u8>) -> Vec<RistrettoPoint> {
        let mut seed_ = seed.to_vec();
        seed_.extend(&contest.to_le_bytes());
        let hashed = hash_bytes_256(seed_);
        let mut csprng: StdRng = SeedableRng::from_seed(hashed);
        let mut ret: Vec<RistrettoPoint> = Vec::with_capacity(size);
        for _ in 0..size {
            let g = RistrettoPoint::random(&mut csprng);
            ret.push(g);
        }

        ret
    }
}


#[cfg(test)]
mod tests {
    extern crate textplots;
    use textplots::{utils, Chart, Plot, Shape};

    use rand::RngCore;  
    use rand::rngs::OsRng;

    use curve25519_dalek::ristretto::{RistrettoPoint};
    use curve25519_dalek::traits::Identity;

    use crate::arithm::*;
    use crate::group::*;
    use crate::keymaker::*;
    use crate::ristretto_b::*;
    use crate::shuffler::*;
    use crate::artifact::*;
    use crate::symmetric;
    use crate::util;

    #[test]
    fn test_ristretto_elgamal() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;
        
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);
        
        let mut fill = [0u8;30];
        csprng.fill_bytes(&mut fill);
        let plaintext = group.encode(&util::to_u8_30(&fill.to_vec()));
        
        let c = pk.encrypt(&plaintext);
        let d = sk.decrypt(&c);
        
        let recovered = group.decode(&d).to_vec();
        assert_eq!(fill.to_vec(), recovered);
    }

    #[test]
    fn test_ristretto_js_encoding() {
        
        let rg = RistrettoGroup;
        
        // since we are not encoding ristretto, this string cannot be changed
        let text = "this has to be exactly 32 bytes!";
        
        // data generated by ristretto255.js
        let skb: [u8;32] = [
            157, 127, 250, 139, 158,  32, 121,
            69, 255, 102, 151, 206, 199, 225,
            118, 203, 168, 220, 193, 198, 226,
            74, 167,  77, 209,  52,  70, 173,
            180, 176, 153,   9
        ];
        let a: [u8;32] = [
            72,  60, 143,  64,  93, 212,  68, 113,
            253,   8, 206,  72, 111,  39,  75, 156,
            189,  63, 176, 223,  97, 221,  58, 132,
                11, 209,  70, 149,  90,  73, 141,  70
        ];
        let b: [u8;32] = [
            182,  67, 141,   0, 95, 109,  54, 179,
            179, 226,  25, 148, 80, 160, 171,  82,
            173, 129,  68,  24, 64, 236,  36, 144,
            183, 193,  36, 180, 82, 206,  98,  41
        ];

        let sk_ = PrivateKey::from(
            &Scalar::from_bytes_mod_order(skb), 
            &rg
        );
        let c_ = Ciphertext {
            a: CompressedRistretto(a).decompress().unwrap(),
            b: CompressedRistretto(b).decompress().unwrap()
        };
        
        let d_: RistrettoPoint = sk_.decrypt(&c_);
        let recovered_ = String::from_utf8(d_.compress().as_bytes().to_vec());
        
        assert_eq!(text, recovered_.unwrap());
    }

    #[test]
    fn test_ristretto_prob_encoding() {
        let mut csprng = OsRng;
        let mut bytes = [00u8; 30];
        let group = RistrettoGroup;

        let iterations = 10000;
        println!("test_r_encoding: running {} encode iterations..", iterations);

        let v: Vec<(f32, f32)> = (0..iterations).map(|i| {
            csprng.fill_bytes(&mut bytes);
            let fixed = util::to_u8_30(&bytes.to_vec());
        
            (i as f32, group.encode_test(fixed).1 as f32)
        }).collect();

        let size: f32 = v.len() as f32;
        let values: Vec<u32> = v.iter().map(|x| x.1 as u32).collect();
        let sum: f32 = v.iter().map(|x| x.1).fold(0f32, |a, b| a + b);
        let sum_f = sum as f32;
        println!("test_r_encoding: average {}", sum_f / size);
        println!("test_r_encoding: max is {}", values.iter().max().unwrap());

        let hist = utils::histogram(&v, 0.0, 30.0, 30);
        Chart::new(380, 100, 0.0, 30.0)
        .lineplot(&Shape::Bars(&hist))
        .nice();
    }

    #[test]
    fn test_ristretto_schnorr() {
        let group = RistrettoGroup;
        let g = group.generator();
        let secret = group.rnd_exp();
        let public = g.mod_pow(&secret, &group.modulus());
        let schnorr = group.schnorr_prove(&secret, &public, &g);
        let verified = group.schnorr_verify(&public, &g, &schnorr);
        assert!(verified == true);
        let public_false = group.generator().mod_pow(&group.rnd_exp(), &group.modulus());
        let verified_false = group.schnorr_verify(&public_false, &g, &schnorr);
        assert!(verified_false == false);
    }

    #[test]
    fn test_ristretto_chaumpedersen() {
        let group = RistrettoGroup;
        let g1 = group.generator();
        let g2 = group.rnd();
        let secret = group.rnd_exp();
        let public1 = g1.mod_pow(&secret, &group.modulus());
        let public2 = g2.mod_pow(&secret, &group.modulus());
        let proof = group.cp_prove(&secret, &public1, &public2, &g1, &g2);
        let verified = group.cp_verify(&public1, &public2, &g1, &g2, &proof);
        
        assert!(verified == true);
        let public_false = group.generator().mod_pow(&group.rnd_exp(), &group.modulus());
        let verified_false = group.cp_verify(&public1, &public_false, &g1, &g2, &proof);
        assert!(verified_false == false);
    }

    #[test]
    fn test_ristretto_vdecryption() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;
        
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);
        
        let mut fill = [0u8;30];
        csprng.fill_bytes(&mut fill);
        let plaintext = group.encode(&util::to_u8_30(&fill.to_vec()));
        
        let c = pk.encrypt(&plaintext);
        let (d, proof) = sk.decrypt_and_prove(&c);

        let dec_factor = c.a.div(&d, &group.modulus()).modulo(&group.modulus());

        let verified = group.cp_verify(&pk.value, &dec_factor, &group.generator(), &c.b, &proof);
        let recovered = group.decode(&d).to_vec();
        assert!(verified == true);
        assert_eq!(fill.to_vec(), recovered);
    }

    #[test]
    fn test_ristretto_distributed() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;
        
        let km1 = Keymaker::gen(&group);
        let km2 = Keymaker::gen(&group);
        let (pk1, proof1) = km1.share();
        let (pk2, proof2) = km2.share();
        
        let verified1 = group.schnorr_verify(&pk1.value, &group.generator(), &proof1);
        let verified2 = group.schnorr_verify(&pk2.value, &group.generator(), &proof2);
        assert!(verified1 == true);
        assert!(verified2 == true);
        
        let mut fill = [0u8;30];
        csprng.fill_bytes(&mut fill);
        let plaintext = group.encode(&util::to_u8_30(&fill.to_vec()));
        
        let pk1_value = &pk1.value.clone();
        let pk2_value = &pk2.value.clone();
        let pks = vec![pk1, pk2];
        
        let pk_combined = Keymaker::combine_pks(&group, pks);
        let c = pk_combined.encrypt(&plaintext);
        
        let (dec_f1, proof1) = km1.decryption_factor(&c);
        let (dec_f2, proof2) = km2.decryption_factor(&c);
        
        let verified1 = group.cp_verify(pk1_value, &dec_f1, &group.generator(), &c.b, &proof1);
        let verified2 = group.cp_verify(pk2_value, &dec_f2, &group.generator(), &c.b, &proof2);
        assert!(verified1 == true);
        assert!(verified2 == true);
        
        let decs = vec![dec_f1, dec_f2];
        let d = Keymaker::joint_dec(&group, decs, &c);
        let recovered = group.decode(&d).to_vec();
        assert_eq!(fill.to_vec(), recovered);
    }
    
    #[test]
    fn test_ristretto_distributed_serde() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;
        
        let km1 = Keymaker::gen(&group);
        let km2 = Keymaker::gen(&group);
        let (pk1, proof1) = km1.share();
        let (pk2, proof2) = km2.share();
        let sym1 = symmetric::gen_key();
        let sym2 = symmetric::gen_key();
        let esk1 = km1.get_encrypted_sk(sym1);
        let esk2 = km2.get_encrypted_sk(sym2);

        let share1 = Keyshare {
            share: pk1,
            proof: proof1,
            encrypted_sk: esk1
        };
        let share2 = Keyshare {
            share: pk2,
            proof: proof2,
            encrypted_sk: esk2
        };

        let share1_b = bincode::serialize(&share1).unwrap();
        let share2_b = bincode::serialize(&share2).unwrap();
        let share1_d: Keyshare<RistrettoPoint, RistrettoGroup> = bincode::deserialize(&share1_b).unwrap();
        let share2_d: Keyshare<RistrettoPoint, RistrettoGroup> = bincode::deserialize(&share2_b).unwrap();
        
        let verified1 = Keymaker::verify_share(&group, &share1_d.share, &share1_d.proof);
        let verified2 = Keymaker::verify_share(&group, &share2_d.share, &share2_d.proof);
       
        assert!(verified1 == true);
        assert!(verified2 == true);
        
        let pk1_value = &share1_d.share.value.clone();
        let pk2_value = &share2_d.share.value.clone();
        let pks = vec![share1_d.share, share2_d.share];
        
        let pk_combined = Keymaker::combine_pks(&group, pks);
        let mut cs = Vec::with_capacity(10);
        let mut bs = Vec::with_capacity(10);
        
        for _ in 0..10 {
            let mut fill = [0u8;30];
            csprng.fill_bytes(&mut fill);
            let encoded = group.encode(&util::to_u8_30(&fill.to_vec()));
            let c = pk_combined.encrypt(&encoded);
            bs.push(fill.to_vec());
            cs.push(c);
        }
        
        let (decs1, proofs1) = km1.decryption_factor_many(&cs);
        let (decs2, proofs2) = km2.decryption_factor_many(&cs);
        
        let pd1 = PartialDecryption {
            pd_ballots: decs1,
            proofs: proofs1
        };
        let pd2 = PartialDecryption {
            pd_ballots: decs2,
            proofs: proofs2
        };
        
        let pd1_b = bincode::serialize(&pd1).unwrap();
        let pd2_b = bincode::serialize(&pd2).unwrap();
        let pd1_d: PartialDecryption<RistrettoPoint> = bincode::deserialize(&pd1_b).unwrap();
        let pd2_d: PartialDecryption<RistrettoPoint> = bincode::deserialize(&pd2_b).unwrap();
        
        let verified1 = Keymaker::verify_decryption_factors(&group, pk1_value, &cs, 
            &pd1_d.pd_ballots, &pd1_d.proofs);
        let verified2 = Keymaker::verify_decryption_factors(&group, pk2_value, &cs, 
                &pd2_d.pd_ballots, &pd2_d.proofs);
        
        assert!(verified1 == true);
        assert!(verified2 == true);
        
        let decs = vec![pd1_d.pd_ballots, pd2_d.pd_ballots];
        let ds = Keymaker::joint_dec_many(&group, &decs, &cs);

        let recovered: Vec<Vec<u8>> = ds.into_iter()
            .map(|d| group.decode(&d).to_vec())
            .collect();
        
        assert_eq!(bs, recovered);
    }

    #[test]
    fn test_identity() {
        let mut csprng = OsRng;
        let x = RistrettoPoint::random(&mut csprng);
        assert_eq!(x + RistrettoPoint::identity(), x);
    }

    #[test]
    fn test_ristretto_shuffle_serde() {
        let group = RistrettoGroup;
        let exp_hasher = &*group.exp_hasher();
        
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);

        let es = util::random_ristretto_ballots(10, &group).ciphertexts;
        let seed = vec![];
        let hs = generators(es.len() + 1, &group, 0, seed);
        let shuffler = Shuffler {
            pk: &pk,
            generators: &hs,
            hasher: exp_hasher
        };
        let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);
        let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm);
        let ok = shuffler.check_proof(&proof, &es, &e_primes);

        let mix = Mix{
            mixed_ballots: e_primes,
            proof: proof
        };
        
        let _group_b = bincode::serialize(&group).unwrap();
        let _sk_b = bincode::serialize(&sk).unwrap();
        let pk_b = bincode::serialize(&pk).unwrap();
        let es_b = bincode::serialize(&es).unwrap();
        let mix_b = bincode::serialize(&mix).unwrap();        

        assert!(ok == true);

        let pk_d: PublicKey<RistrettoPoint, RistrettoGroup> = bincode::deserialize(&pk_b).unwrap();
        let es_d: Vec<Ciphertext<RistrettoPoint>> = bincode::deserialize(&es_b).unwrap();
        let mix_d: Mix<RistrettoPoint> = bincode::deserialize(&mix_b).unwrap();
        
        let shuffler_d = Shuffler {
            pk: &pk_d,
            generators: &hs,
            hasher: exp_hasher
        };
        let ok_d = shuffler_d.check_proof(&mix_d.proof, &es_d, &mix_d.mixed_ballots);
        
        assert!(ok_d == true);
    }

    #[test]
    fn test_ristretto_encrypted_pk() {
        let mut csprng = OsRng;
        let group = RistrettoGroup;
        
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);
        
        let mut fill = [0u8;30];
        csprng.fill_bytes(&mut fill);
        let plaintext = group.encode(&util::to_u8_30(&fill.to_vec()));
        let c = pk.encrypt(&plaintext);
        let sym_key = symmetric::gen_key();
        let enc_sk = sk.to_encrypted(sym_key);
        let enc_sk_b = bincode::serialize(&enc_sk).unwrap();
        let enc_sk_d: EncryptedPrivateKey = bincode::deserialize(&enc_sk_b).unwrap();
        let sk_d = PrivateKey::from_encrypted(sym_key, enc_sk_d, &group);
        let d = sk_d.decrypt(&c);
        
        let recovered = group.decode(&d).to_vec();
        assert_eq!(fill.to_vec(), recovered);
    }
}
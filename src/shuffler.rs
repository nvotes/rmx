use std::sync::Mutex;

use rand::Rng;
use rand::rngs::OsRng;

use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::arithm::*;
use crate::group::*;
use crate::elgamal::*;
use crate::hashing;
use crate::hashing::{HashBytes, HashTo};

pub struct YChallengeInput<'a, E: Element + HashBytes, G: Group<E>> {
    pub es: &'a Vec<Ciphertext<E>>,
    pub e_primes: &'a Vec<Ciphertext<E>>,
    pub cs: &'a Vec<E>,
    pub c_hats: &'a Vec<E>,
    pub pk: &'a PublicKey<E, G>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TValues<E: Element> {
    pub t1: E,
    pub t2: E,
    pub t3: E,
    pub t4_1: E,
    pub t4_2: E,
    pub t_hats: Vec<E>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Responses<E: Element> {
    pub s1: E::Exp,
    pub s2: E::Exp,
    pub s3: E::Exp,
    pub s4: E::Exp,
    pub s_hats: Vec<E::Exp>,
    pub s_primes: Vec<E::Exp>
}

#[derive(Serialize, Deserialize)]
pub struct ShuffleProof<E: Element> {
    pub t: TValues<E>,
    pub s: Responses<E>,
    pub cs: Vec<E>,
    pub c_hats: Vec<E>
}

pub struct Shuffler<'a, E: Element, G: Group<E>> {
    pub pk: &'a PublicKey<E, G>,
    pub generators: &'a Vec<E>,
    pub hasher: &'a dyn HashTo<E::Exp>,
}

impl<'a, E: Element, G: Group<E>> Shuffler<'a, E, G> {
    
    pub fn gen_shuffle
    (&self, ciphertexts: &Vec<Ciphertext<E>>) -> (Vec<Ciphertext<E>>, Vec<E::Exp>, Vec<usize>) {
        
        let perm: Vec<usize> = gen_permutation(ciphertexts.len());
    
        let rs_temp: Vec<Option<E::Exp>> = vec![None;ciphertexts.len()];
        let rs_mutex = Mutex::new(rs_temp);
        let group = &self.pk.group;
        let length = perm.len();
        
        let e_primes = perm.par_iter().map(|p| {
            let c = &ciphertexts[*p];
    
            let r = group.rnd_exp();
            
            let a = c.a.mul(&self.pk.value.mod_pow(&r, &group.modulus()))
                .modulo(&group.modulus());
            let b = c.b.mul(&group.generator().mod_pow(&r, &group.modulus()))
                .modulo(&group.modulus());
            
            let c_ = Ciphertext {
                a: a, 
                b: b
            };
            rs_mutex.lock().unwrap()[*p] = Some(r);
            c_
        }).collect();
         
    
        let mut rs = Vec::with_capacity(ciphertexts.len());
    
        for _ in 0..length {
            let r = rs_mutex.lock().unwrap().remove(0);
            rs.push(r.unwrap());
        }
        
        (e_primes, rs, perm)
    }
    
    pub fn gen_proof
        (&self, es: &Vec<Ciphertext<E>>, e_primes: &Vec<Ciphertext<E>>, 
        r_primes: &Vec<E::Exp>, perm: &Vec<usize>) -> ShuffleProof<E> {
    
        let group = &self.pk.group;
        
        #[allow(non_snake_case)]
        let N = es.len();
        
        let h_generators = &self.generators[1..];
        let h_initial = &self.generators[0];
        
        assert!(N == e_primes.len());
        assert!(N == r_primes.len());
        assert!(N == perm.len());
        assert!(N == h_generators.len());
    
        let gmod = &group.modulus();
        let xmod = &group.exp_modulus();
    
//        let now = std::time::Instant::now();
        let (cs, rs) = self.gen_commitments(&perm, h_generators, &group);
//        println!("Commitments {}", now.elapsed().as_millis());
        
        let us = hashing::shuffle_proof_us(&es, &e_primes, &cs, self.hasher, N);
        
        let mut u_primes: Vec<&E::Exp> = Vec::with_capacity(N);
        for &i in perm.iter() {
            u_primes.push(&us[i]);
        }
        
//        let now = std::time::Instant::now();
        let (c_hats, r_hats) = self.gen_commitment_chain(h_initial, &u_primes, &group);
//        println!("CommitmentChain {}", now.elapsed().as_millis());
        
        // 0
        let mut vs = vec![E::Exp::mul_identity();N];
        for i in (0..N - 1).rev() {
            vs[i] = u_primes[i+1].mul(&vs[i+1]).modulo(xmod);
        }
    
        let mut r_bar = E::Exp::add_identity();
        let mut r_hat: E::Exp = E::Exp::add_identity();
        let mut r_tilde: E::Exp = E::Exp::add_identity();
        let mut r_prime: E::Exp = E::Exp::add_identity();
        
        // 0
        for i in 0..N {
            r_bar = r_bar.add(&rs[i]);
            r_hat = r_hat.add(&r_hats[i].mul(&vs[i]));
            r_tilde = r_tilde.add(&rs[i].mul(&us[i]));
            r_prime = r_prime.add(&r_primes[i].mul(&us[i]));
        }
        
        r_bar = r_bar.modulo(xmod);
        r_hat = r_hat.modulo(xmod);
        r_tilde = r_tilde.modulo(xmod);
        r_prime = r_prime.modulo(xmod);
        
        let omegas = vec![group.rnd_exp();4];
        let omega_hats = vec![group.rnd_exp();N];
        let omega_primes = vec![group.rnd_exp();N];
    
        let t1 = group.generator().mod_pow(&omegas[0], gmod);
        let t2 = group.generator().mod_pow(&omegas[1], gmod);
    
        let mut t3_temp = E::mul_identity();
        let mut t4_1_temp = E::mul_identity();
        let mut t4_2_temp = E::mul_identity();
        
//        let now = std::time::Instant::now();
        let values: Vec<(E, E, E)> = (0..N).into_par_iter().map(|i| {
            (
            h_generators[i].mod_pow(&omega_primes[i], gmod),
            e_primes[i].a.mod_pow(&omega_primes[i], gmod),
            e_primes[i].b.mod_pow(&omega_primes[i], gmod)
            )
        }).collect();
//        println!("values loop {}", now.elapsed().as_millis());

        // ~0
        for i in 0..N {
            t3_temp = t3_temp.mul(&values[i].0)
                .modulo(gmod);
            t4_1_temp = t4_1_temp.mul(&values[i].1)
                .modulo(gmod);
            t4_2_temp = t4_2_temp.mul(&values[i].2)
                .modulo(gmod);
        }
        
        let t3 = (group.generator().mod_pow(&omegas[2], gmod)).mul(&t3_temp)
            .modulo(gmod);
        let t4_1 = (self.pk.value.mod_pow(&omegas[3].neg(), gmod)).mul(&t4_1_temp)
            .modulo(gmod);
        let t4_2 = (group.generator().mod_pow(&omegas[3].neg(), gmod)).mul(&t4_2_temp)
            .modulo(gmod);
    
//        let now = std::time::Instant::now();
        let t_hats = (0..c_hats.len()).into_par_iter().map(|i| {
            let previous_c = if i == 0 {
                h_initial 
            } else {
                &c_hats[i-1]
            };
            
            let next = (group.generator().mod_pow(&omega_hats[i], gmod))
                    .mul(&previous_c.mod_pow(&omega_primes[i], gmod))
                    .modulo(gmod);
            
            next
        }).collect();
//        println!("t-hats loop {}", now.elapsed().as_millis());

        let y = YChallengeInput {
            es: es,
            e_primes: e_primes,
            cs: &cs,
            c_hats: &c_hats,
            pk: self.pk
        };
    
        let t = TValues {
            t1,
            t2,
            t3,
            t4_1,
            t4_2,
            t_hats
        };
    
        // ~0
        let c: E::Exp = hashing::shuffle_proof_challenge(&y, &t, self.hasher);
     
        let s1 = omegas[0].add(&c.mul(&r_bar)).modulo(xmod);
        let s2 = omegas[1].add(&c.mul(&r_hat)).modulo(xmod);
        let s3 = omegas[2].add(&c.mul(&r_tilde)).modulo(xmod);
        let s4 = omegas[3].add(&c.mul(&r_prime)).modulo(xmod);
    
        let mut s_hats: Vec<E::Exp> = Vec::with_capacity(N);
        let mut s_primes: Vec<E::Exp> = Vec::with_capacity(N);
        
        // 0
        for i in 0..N {
            s_hats.push(omega_hats[i].add(&c.mul(&r_hats[i])).modulo(xmod));
            s_primes.push(omega_primes[i].add(&c.mul(&u_primes[i])).modulo(xmod));
        }
    
        let s = Responses {
            s1,
            s2,
            s3,
            s4,
            s_hats,
            s_primes
        };
    
        ShuffleProof {
            t,
            s,
            cs,
            c_hats
        }
    }

    pub fn check_proof(&self, proof: &ShuffleProof<E>, es: &Vec<Ciphertext<E>>, 
        e_primes: &Vec<Ciphertext<E>>) -> bool {
        
        let group = &self.pk.group;
        
        #[allow(non_snake_case)]
        let N = es.len();
        
        let h_generators = &self.generators[1..];
        let h_initial = &self.generators[0];
        
        assert!(N == e_primes.len());
        assert!(N == h_generators.len());
    
        let gmod = &group.modulus();
        let xmod = &group.exp_modulus();
    
        let us: Vec<E::Exp> = hashing::shuffle_proof_us(es, e_primes, &proof.cs, self.hasher, N);
         
        let mut c_bar_num: E = E::mul_identity();
        let mut c_bar_den: E = E::mul_identity();
        let mut u: E::Exp = E::Exp::mul_identity();
        let mut c_tilde: E = E::mul_identity();
        let mut a_prime: E = E::mul_identity();
        let mut b_prime: E = E::mul_identity();
        
        let mut t_tilde3_temp: E = E::mul_identity();
        let mut t_tilde41_temp: E = E::mul_identity();
        let mut t_tilde42_temp: E = E::mul_identity();
    
        let values: Vec<(E, E, E, E, E, E)> =
        (0..N).into_par_iter().map(|i| {
            (
            proof.cs[i].mod_pow(&us[i], gmod),
            es[i].a.mod_pow(&us[i], gmod),
            es[i].b.mod_pow(&us[i], gmod),
            h_generators[i].mod_pow(&proof.s.s_primes[i], gmod),
            e_primes[i].a.mod_pow(&proof.s.s_primes[i], gmod),
            e_primes[i].b.mod_pow(&proof.s.s_primes[i], gmod)
            )
        }).collect();
    
        for i in 0..N {
            c_bar_num = c_bar_num.mul(&proof.cs[i]).modulo(gmod);
            c_bar_den = c_bar_den.mul(&h_generators[i]).modulo(gmod);
            u = u.mul(&us[i]).modulo(xmod);
            
            c_tilde = c_tilde.mul(&values[i].0)
                .modulo(gmod);
            a_prime = a_prime.mul(&&values[i].1)
                .modulo(gmod);
            b_prime = b_prime.mul(&&values[i].2)
                .modulo(gmod);
            t_tilde3_temp = t_tilde3_temp.mul(&values[i].3)
                .modulo(gmod);
            t_tilde41_temp = t_tilde41_temp.mul(&values[i].4)
                .modulo(gmod);
            t_tilde42_temp = t_tilde42_temp.mul(&values[i].5)
                .modulo(gmod);
            
        }
        
        let c_bar = c_bar_num.div(&c_bar_den, gmod)
            .modulo(gmod);
        
        let c_hat = proof.c_hats[N - 1].div(&h_initial.mod_pow(&u, gmod), gmod)
            .modulo(gmod);
            
        let y = YChallengeInput {
            es: es,
            e_primes: e_primes,
            cs: &proof.cs,
            c_hats: &proof.c_hats,
            pk: self.pk
        };
    
        let c = hashing::shuffle_proof_challenge(&y, &proof.t, self.hasher);
        
        let t_prime1 = (c_bar.mod_pow(&c.neg(), gmod))
            .mul(&group.generator().mod_pow(&proof.s.s1, gmod))
            .modulo(gmod);
        
        let t_prime2 = (c_hat.mod_pow(&c.neg(), gmod))
            .mul(&group.generator().mod_pow(&proof.s.s2, gmod))
            .modulo(gmod);
        
        let t_prime3 = (c_tilde.mod_pow(&c.neg(), gmod))
            .mul(&group.generator().mod_pow(&proof.s.s3, gmod))
            .mul(&t_tilde3_temp)
            .modulo(gmod);
        
        let t_prime41 = (a_prime.mod_pow(&c.neg(), gmod))
            .mul(&self.pk.value.mod_pow(&proof.s.s4.neg(), gmod))
            .mul(&t_tilde41_temp)
            .modulo(gmod);
    
        let t_prime42 = (b_prime.mod_pow(&c.neg(), gmod))
            .mul(&group.generator().mod_pow(&proof.s.s4.neg(), gmod))
            .mul(&t_tilde42_temp)
            .modulo(gmod);
    
        let t_hat_primes: Vec<E> = (0..N).into_par_iter().map(|i| {
            let c_term = if i == 0 {
                h_initial 
            } else {
                &proof.c_hats[i - 1]
            };
            
            let next = (proof.c_hats[i].mod_pow(&c.neg(), gmod)) 
                .mul(&group.generator().mod_pow(&proof.s.s_hats[i], gmod))
                .mul(&c_term.mod_pow(&proof.s.s_primes[i], gmod))
                .modulo(gmod);
            
            next
        }).collect();
    
    
        let mut checks = Vec::with_capacity(5 + N);
        checks.push(proof.t.t1.eq(&t_prime1));
        checks.push(proof.t.t2.eq(&t_prime2));
        checks.push(proof.t.t3.eq(&t_prime3));
        checks.push(proof.t.t4_1.eq(&t_prime41));
        checks.push(proof.t.t4_2.eq(&t_prime42));
        for i in 0..N {
            checks.push(proof.t.t_hats[i].eq(&t_hat_primes[i]));
        }
        
        !checks.contains(&false)
    }

    fn gen_commitments
        (&self, perm: &Vec<usize>, generators: &[E], group: &G)  -> (Vec<E>, Vec<E::Exp>) {
        

        assert!(generators.len() == perm.len());

        let rs: Vec<Option<E::Exp>> = vec![None;perm.len()];
        let cs: Vec<Option<E>> = vec![None;perm.len()];
        let rs_mutex = Mutex::new(rs);
        let cs_mutex = Mutex::new(cs);

        perm.par_iter().enumerate().for_each(|(i, p)| {
            let r = group.rnd_exp();
            let c = generators[i].mul(&group.generator().mod_pow(&r, &group.modulus()))
                .modulo(&group.modulus());

            rs_mutex.lock().unwrap()[*p] = Some(r);
            cs_mutex.lock().unwrap()[*p] = Some(c);
        });

        let mut ret1: Vec<E> = Vec::with_capacity(perm.len());
        let mut ret2: Vec<E::Exp> = Vec::with_capacity(perm.len());
        
        for _ in 0..perm.len() {
            let c = cs_mutex.lock().unwrap().remove(0);
            let r = rs_mutex.lock().unwrap().remove(0);

            ret1.push(c.unwrap());
            ret2.push(r.unwrap());
        }

        (ret1, ret2)
    }

    fn gen_commitment_chain
        (&self, initial: &E, us: &Vec<&E::Exp>, group: &G)  -> (Vec<E>, Vec<E::Exp>) {
        
        let mut cs: Vec<E> = Vec::with_capacity(us.len());
        
        let (firsts, rs): (Vec<E>, Vec<E::Exp>) = (0..us.len()).into_par_iter().map(|_| {
            let r = group.rnd_exp();
            let first = group.generator().mod_pow(&r, &group.modulus())
                .modulo(&group.modulus());

            (first, r)
        }).unzip();
        
        
        for i in 0..us.len() {
            let c_temp = if i == 0 {
                initial
            } else {
                &cs[i-1]
            };
            
            let second = c_temp.mod_pow(&us[i], &group.modulus()).
                modulo(&group.modulus());
            let c = firsts[i].mul(&second).modulo(&group.modulus());

            cs.push(c);
        }

        (cs, rs)
    }
}

// FIXME not kosher
pub fn generators<E: Element, G: Group<E>> (size: usize, group: &G, contest: u32, seed: Vec<u8>) -> Vec<E> {
    group.generators(size, contest, seed)
}

fn gen_permutation(size: usize) -> Vec<usize> {
    let mut ret = Vec::with_capacity(size);
    
    let mut rng = OsRng;

    let mut ordered: Vec<usize> = (0..size).collect();

    for i in 0..size {
        let k = rng.gen_range(i, size);
        let j = ordered[k];
        ordered[k] = ordered[i];
        ret.push(j);
    }

    return ret;
}



#[cfg(test)]
mod tests {    
    use crate::group::*;
    use crate::rug_b::*;
    use crate::ristretto_b::*;
    use crate::shuffler::*;
    use rug::Integer;


    #[test]
    fn test_ristretto_shuffle() {
        let group = RistrettoGroup;
        let exp_hasher = &*group.exp_hasher();

        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);
        
        let mut es = Vec::with_capacity(10);
        let n = 100;

        for _ in 0..n {
            let plaintext = group.rnd();
            let c = pk.encrypt(&plaintext);
            es.push(c);
        }
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

        assert!(ok == true);
    }

    #[test]
    fn test_rug_shuffle() {
        let group = RugGroup::default();
        let exp_hasher = &*group.exp_hasher();
            
        let sk = group.gen_key();
        let pk = PublicKey::from(&sk.public_value, &group);
        let n = 100;
    
        let mut es: Vec<Ciphertext<Integer>> = Vec::with_capacity(10);
        
        for _ in 0..n {
            let plaintext: Integer = group.encode(&group.rnd_exp());
            let c = pk.encrypt(&plaintext);
            es.push(c);
        }
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

        assert!(ok == true);
    }
}
use rmx::util;
use rmx::ristretto_b::*;
use rmx::rug_b::*;
use rmx::group::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rug::Integer;

#[test]
fn test_size() {
    let n = 1000;
    let n_f = 1000 as f32;
    let group1 = RistrettoGroup;
    let exps1: Vec<Scalar> = (0..n).into_iter().map(|_| group1.rnd_exp()).collect();
    let mut bytes = bincode::serialize(&exps1).unwrap();
    println!("{} ristretto exps: {}, {}", n, bytes.len(), (bytes.len() as f32 / n_f));
    let elements1: Vec<RistrettoPoint> = (0..n).into_iter().map(|_| group1.rnd()).collect();
    bytes = bincode::serialize(&elements1).unwrap();
    println!("{} ristretto elements: {}, {}", n, bytes.len(), (bytes.len() as f32 / n_f));
    let es1 = util::random_ristretto_ballots(n, &group1).ciphertexts;
    bytes = bincode::serialize(&es1).unwrap();
    println!("{} ciphertexts in Ballots: {}, {}", n, bytes.len(), (bytes.len() as f32 / n_f));
    // 100k = 100M
    let group2 = RugGroup::default();
    let exps2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd_exp()).collect();
    bytes = bincode::serialize(&exps2).unwrap();
    println!("{} rug exps: {}, {}", n, bytes.len(), (bytes.len() as f32 / n_f));
    let elements2: Vec<Integer> = (0..n).into_iter().map(|_| group2.rnd()).collect();
    bytes = bincode::serialize(&elements2).unwrap();
    println!("{} rug elements: {}, {}", n, bytes.len(), (bytes.len() as f32 / n_f));
    let es2 = util::random_rug_ballots(1000, &group2).ciphertexts;
    bytes = bincode::serialize(&es2).unwrap();
    println!("{} ciphertexts in Ballots: {}, {}", n, bytes.len(), (bytes.len() as f32/ n_f));
}
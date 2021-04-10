#![allow(dead_code)]

use std::collections::HashSet;
use std::fs;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::Path;

use ed25519_dalek::{Keypair, PublicKey as SPublicKey};
use rand::rngs::OsRng;
use uuid::Uuid;

use braid::bulletinboard::basic::*;
use braid::bulletinboard::generic::*;
use braid::bulletinboard::git;
use braid::bulletinboard::*;
use braid::crypto::backend::ristretto_b::*;
use braid::crypto::backend::rug_b::*;
use braid::crypto::base::Element;
use braid::crypto::base::Group;
use braid::crypto::elgamal::PublicKey;
use braid::crypto::hashing;
use braid::data::artifact::*;
use braid::data::bytes::*;
use braid::protocol::logic::Driver;
use braid::protocol::statement::SignedStatement;
use braid::protocol::trustee::Trustee;
use braid::protocol::trustee::TrusteeError;
use braid::util;

use simplelog::*;

#[test]
fn run_rug_mem() {
    // setup_log();
    let group = RugGroup::default();
    run(group, MBasic::default()).unwrap();
}

#[test]
fn run_ristretto_mem() {
    // setup_log();
    let group = RistrettoGroup;
    run(group, MBasic::default()).unwrap();
}

#[ignore]
#[test]
fn run_rug_git() {
    // setup_log();
    let group = RugGroup::default();
    let bb = git::test_config();
    bb.__clear().unwrap();
    run(group, bb).unwrap();
}

#[ignore]
#[test]
fn run_ristretto_git() {
    // setup_log();
    let group = RistrettoGroup;
    let bb = git::test_config();
    bb.__clear().unwrap();
    run(group, bb).unwrap();
}

fn run<
    E: Element + std::cmp::PartialEq,
    G: Group<E>,
    B: BasicBoard,
>(
    group: G,
    basic: B,
) -> Result<(), TrusteeError>
where
    <E as Element>::Plaintext: std::hash::Hash,
{
    let local1 = "/tmp/local";
    let local2 = "/tmp/local2";
    let local_path = Path::new(&local1);
    // we do not care about these errors
    fs::remove_dir_all(local_path).ok();
    fs::create_dir(local_path).ok();
    let local_path = Path::new(&local2);
    fs::remove_dir_all(local_path).ok();
    fs::create_dir(local_path).ok();

    let trustee1: Trustee<E, G> = Trustee::new(local1.to_string());
    let trustee2: Trustee<E, G> = Trustee::new(local2.to_string());
    let mut csprng = OsRng;
    let bb_keypair = Keypair::generate(&mut csprng);

    let mut bb = GenericBulletinBoard::<E, G, B>::new(basic);

    let mut trustee_pks = Vec::new();
    trustee_pks.push(trustee1.keypair.public);
    trustee_pks.push(trustee2.keypair.public);

    let contests = 3;
    let ballots = 200;
    let cfg = gen_config(&group, contests, trustee_pks, bb_keypair.public);
    let cfg_b = cfg.ser();

    let tmp_file = util::write_tmp(cfg_b)?;

    bb.add_config(&ConfigPath(tmp_file.path().to_path_buf()))?;

    let prot1: Driver<E, G, GenericBulletinBoard<E, G, B>> = Driver::new(trustee1);
    let prot2: Driver<E, G, GenericBulletinBoard<E, G, B>> = Driver::new(trustee2);

    // mix position 0
    prot1.step(&mut bb)?;
    // verify mix position 0
    prot2.step(&mut bb)?;

    // nothing
    prot1.step(&mut bb)?;
    // mix position 1
    prot2.step(&mut bb)?;

    // check mix position 1
    prot1.step(&mut bb)?;
    // partial decryptions
    prot2.step(&mut bb)?;

    // partial decryptions
    prot1.step(&mut bb)?;
    // nothing
    prot2.step(&mut bb)?;

    // combine decryptions
    prot1.step(&mut bb)?;

    let mut all_plaintexts = Vec::with_capacity(contests as usize);

    println!("=================== ballots ===================");
    for i in 0..contests {
        let pk_b = bb
            .get_unsafe(GenericBulletinBoard::<E, G, B>::public_key(i, 0))
            .unwrap()
            .unwrap();
        let pk = PublicKey::<E, G>::deser(&pk_b).unwrap();

        let (plaintexts, ciphertexts) = util::random_encrypt_ballots(ballots, &pk);
        all_plaintexts.push(plaintexts);
        let ballots = Ballots { ciphertexts };
        let ballots_b = ballots.ser();
        let ballots_h = hashing::hash(&ballots);
        let cfg_h = hashing::hash(&cfg);
        let ss = SignedStatement::ballots(&cfg_h, &ballots_h, i, &bb_keypair);

        let ss_b = ss.ser();

        let f1 = util::write_tmp(ballots_b).unwrap();
        let f2 = util::write_tmp(ss_b).unwrap();
        println!(">> Adding {} ballots", ballots.ciphertexts.len());
        bb.add_ballots(
            &BallotsPath(f1.path().to_path_buf(), f2.path().to_path_buf()),
            i,
        )?;
    }
    println!("===============================================");

    // mix position 0
    prot1.step(&mut bb)?;
    // verify mix position 0
    prot2.step(&mut bb)?;

    // nothing
    prot1.step(&mut bb)?;
    // mix position 1
    prot2.step(&mut bb)?;

    // check mix position 1
    prot1.step(&mut bb)?;
    // partial decryptions
    prot2.step(&mut bb)?;

    // partial decryptions
    prot1.step(&mut bb)?;
    // nothing
    prot2.step(&mut bb)?;

    // combine decryptions
    prot1.step(&mut bb)?;

    for i in 0..contests {
        let decrypted_b = bb
            .get_unsafe(GenericBulletinBoard::<E, G, B>::plaintexts(i, 0))
            .unwrap()
            .unwrap();
        let decrypted = Plaintexts::<E>::deser(&decrypted_b).unwrap();
        let decoded: Vec<E::Plaintext> = decrypted
            .plaintexts
            .iter()
            .map(|p| group.decode(&p))
            .collect();
        let p1: HashSet<&E::Plaintext> =
            HashSet::from_iter(all_plaintexts[i as usize].iter().clone());
        let p2: HashSet<&E::Plaintext> = HashSet::from_iter(decoded.iter().clone());

        print!("Checking plaintexts contest=[{}]...", i);
        assert!(p1 == p2);
        println!("Ok");
    }

    Ok(())
}

fn gen_config<E: Element, G: Group<E>>(
    group: &G,
    contests: u32,
    trustee_pks: Vec<SPublicKey>,
    ballotbox_pk: SPublicKey,
) -> braid::data::artifact::Config<E, G> {
    let id = Uuid::new_v4();

    let cfg = braid::data::artifact::Config {
        id: *id.as_bytes(),
        group: group.clone(),
        contests,
        ballotbox: ballotbox_pk,
        trustees: trustee_pks,
        phantom_e: PhantomData,
    };

    cfg
}

use std::sync::Once;

static INIT: Once = Once::new();

/// Setup function that is only run once, even if called multiple times.
fn setup_log() {
    INIT.call_once(|| {
        CombinedLogger::init(vec![TermLogger::new(
            LevelFilter::Info,
            simplelog::Config::default(),
            TerminalMode::Mixed,
        )])
        .unwrap();
    });
}

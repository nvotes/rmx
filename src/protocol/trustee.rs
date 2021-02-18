
use generic_array::{typenum::U32, GenericArray};

use serde::de::DeserializeOwned;
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use log::info;

use crate::data::entity::*;
use crate::protocol::statement::*;
use crate::protocol::facts::*;
use crate::crypto::elgamal::{PublicKey, Ciphertext, PrivateKey};
use crate::crypto::shuffler::*;
use crate::crypto::keymaker::Keymaker;
use crate::crypto::base::Element;
use crate::crypto::base::Group;
use crate::crypto::symmetric;
use crate::crypto::hashing;
use crate::crypto::hashing::*;
use crate::bulletinboard::*;
use crate::bulletinboard::localstore::LocalStore;
use crate::util;
use crate::util::short;

pub struct Trustee<E, G> {
    pub keypair: Keypair,
    pub localstore: LocalStore<E, G>,
    pub symmetric: GenericArray<u8, U32>
}

impl<E: Element + DeserializeOwned + std::cmp::PartialEq, G: Group<E> + DeserializeOwned> Trustee<E, G> {
    
    pub fn new(local_store: String) -> Trustee<E, G> {
        let mut csprng = OsRng;
        let localstore = LocalStore::new(local_store);
        let keypair = Keypair::generate(&mut csprng);
        let symmetric = symmetric::gen_key();

        Trustee {
            keypair,
            localstore,
            symmetric
        }
    }
    
    pub fn run<B: BulletinBoard<E, G>>(&self, facts: AllFacts, board: &mut B) -> u32 {
        let self_index = facts.get_self_index();
        let trustees = facts.get_trustee_count();
        let actions = facts.all_actions;
        let ret = actions.len();
        
        info!(">>>> Trustee::run: found {} actions", ret);
        let now = std::time::Instant::now();
        for action in actions {
            match action {
                Act::CheckConfig(cfg_h) => {
                    info!(">> Action: checking config..");
                    // FIXME validate the config somehow
                    let ss = SignedStatement::config(&cfg_h, &self.keypair);
                    let stmt_path = self.localstore.set_config_stmt(&action, &ss);
                    board.add_config_stmt(&stmt_path, self_index.unwrap());
                    info!(">> OK");
                }
                Act::PostShare(cfg_h, cnt) => {
                    info!(">> Action: Computing shares (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let cfg = board.get_config(cfg_h).unwrap();
                    let share = self.gen_share(&cfg.group);
                    let share_h = hashing::hash(&share);
                    let ss = SignedStatement::keyshare(&cfg_h, &share_h, cnt, &self.keypair);
                    let share_path = self.localstore.set_share(&action, share, &ss);
                    
                    board.add_share(&share_path, cnt, self_index.unwrap());
                    info!(">> OK");
                }
                Act::CombineShares(cfg_h, cnt, hs) => {
                    info!(">> Action: Combining shares (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let cfg = board.get_config(cfg_h).unwrap();
                    let hashes = util::clear_zeroes(&hs);
                    assert!(hashes.len() as u32 == trustees.unwrap());
                    let pk = self.get_pk(board, hashes, &cfg.group, cnt).unwrap();
                    let pk_h = hashing::hash(&pk);
                    let ss = SignedStatement::public_key(&cfg_h, &pk_h, cnt, &self.keypair);
                    
                    let pk_path = self.localstore.set_pk(&action, pk, &ss);
                    board.set_pk(&pk_path, cnt);
                    info!(">> OK");
                }
                Act::CheckPk(cfg_h, cnt, pk_h, hs) => {
                    info!(">> Action: Verifying pk (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let cfg = board.get_config(cfg_h).unwrap();
                    let hashes = util::clear_zeroes(&hs);
                    let pk = self.get_pk(board, hashes, &cfg.group, cnt).unwrap();
                    let pk_h_ = hashing::hash(&pk);
                    assert!(pk_h == pk_h_);
                    let ss = SignedStatement::public_key(&cfg_h, &pk_h, cnt, &self.keypair);
                    
                    let pk_stmt_path = self.localstore.set_pk_stmt(&action, &ss);
                    board.set_pk_stmt(&pk_stmt_path, cnt, self_index.unwrap());
                    info!(">> OK");
                }
                Act::Mix(cfg_h, cnt, ballots_h, pk_h) => {
                    let self_t = self_index.unwrap();
                    info!(">> Computing mix (contest=[{}], self=[{}])..", cnt, self_t);
                    let cfg = board.get_config(cfg_h).unwrap();
                    let ciphertexts = self.get_mix_src(board, cnt, self_t, ballots_h);
                    let pk = board.get_pk(cnt, pk_h).unwrap();
                    let group = &cfg.group;
                    
                    let hs = generators(ciphertexts.len() + 1, group, cnt, cfg.id.to_vec());
                    
                    let exp_hasher = &*group.exp_hasher();
                    let shuffler = Shuffler {
                        pk: &pk,
                        generators: &hs,
                        hasher: exp_hasher
                    };
                    
                    let now_ = std::time::Instant::now();
                    let (e_primes, rs, perm) = shuffler.gen_shuffle(&ciphertexts);                    
                    let proof = shuffler.gen_proof(&ciphertexts, &e_primes, &rs, &perm);
                    // assert!(shuffler.check_proof(&proof, &ciphertexts, &e_primes));
                    let rate = ciphertexts.len() as f32 / now_.elapsed().as_millis() as f32;
                    info!("Shuffle + Proof ({:.1} ciphertexts/s)", 1000.0 * rate);
                    
                    let mix = Mix {
                        mixed_ballots: e_primes,
                        proof: proof
                    };
                    let mix_h = hashing::hash(&mix);
                    
                    let ss = SignedStatement::mix(&cfg_h, &mix_h, &ballots_h, None, cnt, &self.keypair);
                    
                    let now_ = std::time::Instant::now();
                    let mix_path = self.localstore.set_mix(&action, mix, &ss);
                    let rate = ciphertexts.len() as f32 / now_.elapsed().as_millis() as f32;
                    info!("IO Write ({:.1} ciphertexts/s)", 1000.0 * rate);
                    
                    board.add_mix(&mix_path, cnt, self_index.unwrap());  
                    info!(">> Mix generated {:?} <- {:?}", short(&mix_h), short(&ballots_h));
                }
                Act::CheckMix(cfg_h, cnt, trustee, mix_h, ballots_h, pk_h) => {
                    let cfg = board.get_config(cfg_h).unwrap();
                    info!(">> Action:: Verifying mix (contest=[{}], self=[{}])..", cnt, self_index.unwrap());

                    let mix = board.get_mix(cnt, trustee, mix_h).unwrap();
                    let ciphertexts = self.get_mix_src(board, cnt, trustee, ballots_h);
                    let pk = board.get_pk(cnt, pk_h).unwrap();
                    let group = &cfg.group;
                    
                    let hs = generators(ciphertexts.len() + 1, group, cnt, cfg.id.to_vec());
                    let exp_hasher = &*group.exp_hasher();
                    let shuffler = Shuffler {
                        pk: &pk,
                        generators: &hs,
                        hasher: exp_hasher
                    };
                    let proof = mix.proof;
                    info!("Verifying shuffle {:?} <- {:?}", short(&mix_h), short(&ballots_h));

                    let now_ = std::time::Instant::now();
                    assert!(shuffler.check_proof(&proof, &ciphertexts, &mix.mixed_ballots));
                    let rate = ciphertexts.len() as f32 / now_.elapsed().as_millis() as f32;
                    info!("Check proof ({:.1} ciphertexts/s)", 1000.0 * rate);
            
                    let ss = SignedStatement::mix(&cfg_h, &mix_h, &ballots_h, Some(trustee), cnt, &self.keypair);
                    let mix_path = self.localstore.set_mix_stmt(&action, &ss);
                    board.add_mix_stmt(&mix_path, cnt, self_index.unwrap(), trustee);
                    
                    info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);
                }
                Act::PartialDecrypt(cfg_h, cnt, mix_h, share_h) => {
                    info!(">> Action: Computing partial decryptions (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let now_ = std::time::Instant::now();
                    let cfg = board.get_config(cfg_h).unwrap();
                    let mix = board.get_mix(cnt, (cfg.trustees.len() - 1) as u32, mix_h).unwrap();
                    let share = board.get_share(cnt, self_index.unwrap(), share_h).unwrap();
                    let encrypted_sk = share.encrypted_sk;
                    let sk: PrivateKey<E, G> = PrivateKey::from_encrypted(self.symmetric, encrypted_sk, &cfg.group);
                    let keymaker = Keymaker::from_sk(sk, &cfg.group);

                    let (decs, proofs) = keymaker.decryption_factor_many(&mix.mixed_ballots);
                    let rate = mix.mixed_ballots.len() as f32 / now_.elapsed().as_millis() as f32;
                    let pd = PartialDecryption {
                        pd_ballots: decs,
                        proofs: proofs
                    };
                    let pd_h = hashing::hash(&pd);
                    let ss = SignedStatement::pdecryptions(&cfg_h, &pd_h, cnt, &self.keypair);
                    let pd_path = self.localstore.set_pdecryptions(&action, pd, &ss);
                    board.add_decryption(&pd_path, cnt, self_index.unwrap());
                    
                    info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);
                }
                Act::CombineDecryptions(cfg_h, cnt, decryption_hs, mix_h, share_hs) => {
                    let cfg = board.get_config(cfg_h).unwrap();
                    info!(">> Action: Combining decryptions (contest=[{}], self=[{}])..", cnt, self_index.unwrap());
                    let now_ = std::time::Instant::now();
                    let d_hs = util::clear_zeroes(&decryption_hs);
                    let s_hs = util::clear_zeroes(&share_hs);
                    let pls = self.get_plaintexts(board, cnt, d_hs, mix_h, s_hs, &cfg).unwrap();
                    let rate = pls.len() as f32 / now_.elapsed().as_millis() as f32;
                    let plaintexts = Plaintexts {
                        plaintexts: pls
                    };
                    let p_h = hashing::hash(&plaintexts);
                    let ss = SignedStatement::plaintexts(&cfg_h, &p_h, cnt, &self.keypair);
                    let p_path = self.localstore.set_plaintexts(&action, plaintexts, &ss);
                    board.set_plaintexts(&p_path, cnt);
                    
                    info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);
                }
                Act::CheckPlaintexts(cfg_h, cnt, plaintexts_h, decryption_hs, mix_h, share_hs) => {
                    let cfg = board.get_config(cfg_h).unwrap();
                    info!(">> Action: Checking plaintexts (contest=[{}], self=[{}])", cnt, self_index.unwrap());
                    let now_ = std::time::Instant::now();
                    let s_hs = util::clear_zeroes(&share_hs);
                    let d_hs = util::clear_zeroes(&decryption_hs);
                    let pls = self.get_plaintexts(board, cnt, d_hs, mix_h, s_hs, &cfg).unwrap();
                    let rate = pls.len() as f32 / now_.elapsed().as_millis() as f32;
                    let pls_board = board.get_plaintexts(cnt, plaintexts_h).unwrap();
                    assert!(pls == pls_board.plaintexts);
            
                    let ss = SignedStatement::plaintexts(&cfg_h, &plaintexts_h, cnt, &self.keypair);
                    let p_path = self.localstore.set_plaintexts_stmt(&action, &ss);
                    board.set_plaintexts_stmt(&p_path, cnt, self_index.unwrap());
                    info!(">> OK ({:.1} ciphertexts/s)", 1000.0 * rate);
                }
            }
        }
         
        info!(">>>> Trustee::run finished in [{}ms]", now.elapsed().as_millis());
        ret as u32
    }
    
    // ballots may come from the ballot box, or an earlier mix
    fn get_mix_src<B: BulletinBoard<E, G>>(&self, board: &B, contest: u32, 
        mixing_trustee: u32, ballots_h: Hash) -> Vec<Ciphertext<E>> {

        if mixing_trustee == 0 {
            let ballots = board.get_ballots(contest, ballots_h).unwrap();
            ballots.ciphertexts
        }
        else {
            let mix = board.get_mix(contest, mixing_trustee - 1, ballots_h).unwrap();
            mix.mixed_ballots
        }
    }

    fn get_plaintexts<B: BulletinBoard<E, G>>(&self, board: &B, cnt: u32, hs: Vec<Hash>, 
        mix_h: Hash, share_hs: Vec<Hash>, cfg: &Config<E, G>) -> Option<Vec<E>> {
        
        assert!(hs.len() == share_hs.len());
        
        let mut decryptions: Vec<Vec<E>> = Vec::with_capacity(hs.len());
        let last_trustee = cfg.trustees.len() - 1;
        let mix = board.get_mix(cnt, last_trustee as u32, mix_h).unwrap();
        let ciphertexts = mix.mixed_ballots;
        for (i, h) in hs.iter().enumerate() {
            let next_d = board.get_decryption(cnt, i as u32, *h).unwrap();
            let next_s = board.get_share(cnt, i as u32, share_hs[i]).unwrap();
            info!("Verifying decryption share..");
            let ok = Keymaker::verify_decryption_factors(&cfg.group, &next_s.share.value, &ciphertexts,
                &next_d.pd_ballots, &next_d.proofs);
            assert!(ok);
            
            if ok {
                decryptions.push(next_d.pd_ballots);
            }
            else { 
                break;
            }
        }
        if decryptions.len() == hs.len() {
            let plaintexts = Keymaker::joint_dec_many(&cfg.group, &decryptions, &ciphertexts);
            Some(plaintexts)
        }
        else {
            None
        }
    }

    fn get_pk<B: BulletinBoard<E, G>>(&self, board: &B, hs: Vec<Hash>, group: &G, 
        cnt: u32) -> Option<PublicKey<E, G>> {
        
        let mut shares = Vec::with_capacity(hs.len());
        for (i, h) in hs.iter().enumerate() {
            let next = board.get_share(cnt, i as u32, *h).unwrap();
            info!("Verifying share proof..");
            let ok = Keymaker::verify_share(group, &next.share, &next.proof);
            if ok {
                shares.push(next.share);
            }
            else { 
                break;
            }
        }
        if shares.len() == hs.len() {
            let pk = Keymaker::combine_pks(group, shares);
            Some(pk)
        }
        else {
            None
        }
    }

    fn gen_share(&self, group: &G) -> Keyshare<E, G> {
        let keymaker = Keymaker::gen(group);
        let (share, proof) = keymaker.share();
        let encrypted_sk = keymaker.get_encrypted_sk(self.symmetric);
        
        Keyshare {
            share,
            proof,
            encrypted_sk
        }
    }
}
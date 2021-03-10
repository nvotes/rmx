pub mod actions;

use generic_array::{typenum::U32, GenericArray};

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use log::info;

use crate::data::artifact::*;

use crate::protocol::facts::*;
use crate::crypto::elgamal::{PublicKey, Ciphertext};

use crate::crypto::keymaker::Keymaker;
use crate::crypto::base::Element;
use crate::crypto::base::Group;
use crate::crypto::symmetric;

use crate::crypto::hashing::*;
use crate::bulletinboard::*;
use crate::bulletinboard::work_cache::WorkCache;


quick_error! {
    #[derive(Debug)]
    pub enum TrusteeError {
        Empty{}
        BBError(err: BBError) {
            from()
        }
        IOError(err: std::io::Error) {
            from()
        }
        Msg(message: String) {
            from()
        }
    }
}

pub struct Trustee<E, G> {
    pub keypair: Keypair,
    pub work_cache: WorkCache<E, G>,
    pub symmetric: GenericArray<u8, U32>
}

impl<E: Element, G: Group<E>> Trustee<E, G> {
    
    pub fn new(local_store: String) -> Trustee<E, G> {
        let mut csprng = OsRng;
        let work_cache = WorkCache::new(local_store);
        let keypair = Keypair::generate(&mut csprng);
        let symmetric = symmetric::gen_key();

        Trustee {
            keypair,
            work_cache,
            symmetric
        }
    }
    
    pub fn run<B: BulletinBoard<E, G>>(&self, facts: AllFacts, board: &mut B) -> Result<u32, TrusteeError> {
        let self_index = facts.get_self_index();
        let actions = facts.all_actions;
        let ret = actions.len();
        
        info!(">>>> Trustee::run: found {} actions", ret);
        let now = std::time::Instant::now();
        for action in actions {
            let self_t = self_index
                .ok_or(TrusteeError::Msg("Could not find self index".to_string()))?;
            
            match action {
                Act::CheckConfig(cfg_h) => {
                    self.check_config(action, self_t, cfg_h, board)?;
                }
                Act::PostShare(cfg_h, cnt) => {
                    self.post_share(action, self_t, cfg_h, cnt, board)?;
                }
                Act::CombineShares(cfg_h, cnt, hs) => {
                    self.combine_shares(action, self_t, cfg_h, cnt, hs, board)?;
                }
                Act::CheckPk(cfg_h, cnt, pk_h, hs) => {
                    self.check_pk(action, self_t, cfg_h, cnt, pk_h, hs, board)?;
                }
                Act::Mix(cfg_h, cnt, ballots_h, pk_h) => {
                    self.mix(action, self_t, cfg_h, cnt, ballots_h, pk_h, board)?;
                }
                Act::CheckMix(cfg_h, cnt, trustee, mix_h, ballots_h, pk_h) => {
                    self.check_mix(action, self_t, cfg_h, cnt, trustee, mix_h, ballots_h, pk_h, board)?;
                }
                Act::PartialDecrypt(cfg_h, cnt, mix_h, share_h) => {
                    self.partial_decrypt(action, self_t, cfg_h, cnt, mix_h, share_h, board)?;
                }
                Act::CombineDecryptions(cfg_h, cnt, decryption_hs, mix_h, share_hs) => {
                    self.combine_decryptions(action, self_t, cfg_h, cnt, decryption_hs, mix_h, share_hs, board)?;
                }
                Act::CheckPlaintexts(cfg_h, cnt, plaintexts_h, decryption_hs, mix_h, share_hs) => {
                    self.check_plaintexts(action, self_t, cfg_h, cnt, plaintexts_h, decryption_hs, mix_h, share_hs, board)?;
                }
            }
        }
         
        info!(">>>> Trustee::run finished in [{}ms]", now.elapsed().as_millis());
        Ok(ret as u32)
    }
    
    // ballots may come from the ballot box, or an earlier mix
    fn get_mix_src<B: BulletinBoard<E, G>>(&self, board: &B, contest: u32, 
        mixing_trustee: u32, ballots_h: Hash) -> Option<Vec<Ciphertext<E>>> {

        if mixing_trustee == 0 {
            let ballots = board.get_ballots(contest, ballots_h).ok()?;
            Some(ballots?.ciphertexts)
        }
        else {
            let mix = board.get_mix(contest, mixing_trustee - 1, ballots_h).ok()?;
            Some(mix?.mixed_ballots)
        }
    }

    fn get_plaintexts<B: BulletinBoard<E, G>>(&self, board: &B, cnt: u32, hs: Vec<Hash>, 
        mix_h: Hash, share_hs: Vec<Hash>, cfg: &Config<E, G>) -> Option<Vec<E>> {
        
        assert!(hs.len() == share_hs.len());
        assert!(hs.len() == cfg.trustees.len());
        assert!(share_hs.len() == cfg.trustees.len());
        
        let mut decryptions: Vec<Vec<E>> = Vec::with_capacity(hs.len());
        let last_trustee = cfg.trustees.len() - 1;

        let mix = board.get_mix(cnt, last_trustee as u32, mix_h).ok()?;
        let ciphertexts = mix?.mixed_ballots;
        for (i, h) in hs.iter().enumerate() {
            let next_d = board.get_decryption(cnt, i as u32, *h).ok()??;
            let next_s = board.get_share(cnt, i as u32, share_hs[i]).ok()??;
            
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
            let next = board.get_share(cnt, i as u32, *h).ok()??;
            
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
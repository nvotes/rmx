use std::convert::TryInto;

use ed25519_dalek::PublicKey as SPublicKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::Signature;
use ed25519_dalek::{Keypair, Signer};

use serde::{Deserialize, Serialize};

use crate::util;
use crate::protocol::facts::InputFact;
use crate::protocol::logic::ContestIndex;
use crate::protocol::logic::TrusteeIndex;
use crate::crypto::base::Element;
use crate::crypto::base::Group;
use crate::crypto::hashing;
use crate::bulletinboard::*;

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Statement {
    pub stype: StatementType, 
    pub contest: ContestIndex,
    // special case for mixes where we need to keep track of 
    // target trustee (the trustee producing the mix
    // which the local trustee is signing)
    pub trustee_aux: Option<TrusteeIndex>,
    pub hashes: Vec<VHash>
}

impl Statement {
    pub fn config(config: VHash) -> Statement {
        Statement {
            stype: StatementType::Config,
            contest: 0,
            trustee_aux: None,
            hashes: vec![config]
        }
    }
    pub fn keyshare(config: VHash, contest: u32, share: VHash) -> Statement {
        Statement {
            stype: StatementType::Keyshare,
            contest: contest,
            trustee_aux: None,
            hashes: vec![config, share]
        }
    }
    pub fn public_key(config: VHash, contest: u32, public_key: VHash) -> Statement {
        Statement {
            stype: StatementType::PublicKey,
            contest: contest,
            trustee_aux: None,
            hashes: vec![config, public_key]
        }
    }
    pub fn ballots(config: VHash, contest: u32, ballots: VHash) -> Statement {
        Statement {
            stype: StatementType::Ballots,
            contest: contest,
            trustee_aux: None,
            hashes: vec![config, ballots]
        }
    }
    pub fn mix(config: VHash, contest: u32, mix: VHash, ballots: VHash, mixing_trustee: Option<u32>) -> Statement {
        Statement {
            stype: StatementType::Mix,
            contest: contest,
            trustee_aux: mixing_trustee,
            hashes: vec![config, mix, ballots]
        }
    }
    pub fn partial_decryption(config: VHash, contest: u32, partial_decryptions: VHash) -> Statement {
        Statement {
            stype: StatementType::PDecryption,
            contest: contest,
            trustee_aux: None,
            hashes: vec![config, partial_decryptions]
        }
    }
    pub fn plaintexts(config: VHash, contest: u32, plaintexts: VHash) -> Statement {
        Statement {
            stype: StatementType::Plaintexts,
            contest: contest,
            trustee_aux: None,
            hashes: vec![config, plaintexts]
        }
    }
}

#[repr(u8)]
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, Copy)]
pub enum StatementType {
    Config,
    Keyshare,
    PublicKey,
    Ballots,
    Mix,
    PDecryption,
    Plaintexts
}

#[derive(Debug)]
pub struct StatementVerifier {
    pub statement: SignedStatement,
    pub trustee: i32,
    pub contest: u32
}

impl StatementVerifier {
    
    pub(super) fn verify<E: Element, G: Group<E>, B: BulletinBoard<E, G>>(&self, board: &B) -> Option<InputFact> {
        let statement = &self.statement.statement;
        let config = board.get_config_unsafe()?;
        
        let (pk, self_t): (SPublicKey, u32) =
        if self.trustee >= 0 {
            (config.trustees[self.trustee as usize], self.trustee.try_into().unwrap())
        } else {
            (config.ballotbox, 0)
        };
        
        let statement_hash = hashing::hash(statement);
        let verified = pk.verify(&statement_hash, &self.statement.signature);
        let config_h = util::to_u8_64(&statement.hashes[0]);
        // info!("* Verify returns: [{}] on [{:?}] from trustee [{}] for contest [{}]", verified.is_ok(), 
        //    &self.statement.statement.stype, &self.trustee, &self.contest
        //);
        
        let mixer_t = statement.trustee_aux.unwrap_or(self_t);

        match statement.stype {
            StatementType::Config => {
                self.ret(
                    InputFact::config_signed_by(config_h, self_t),
                    verified.is_ok()
                )
            },
            StatementType::Keyshare => {
                let share_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::share_signed_by(config_h, self.contest, share_h, self_t),
                    verified.is_ok()
                )
            },
            StatementType::PublicKey => {
                let pk_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::pk_signed_by(config_h, self.contest, pk_h, self_t),
                    verified.is_ok()
                )
            },
            StatementType::Ballots => {
                let ballots_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::ballots_signed(config_h, self.contest, ballots_h),
                    verified.is_ok()
                )
            },
            StatementType::Mix => {
                let mix_h = util::to_u8_64(&statement.hashes[1]);
                let ballots_h = util::to_u8_64(&statement.hashes[2]);
                self.ret(
                    InputFact::mix_signed_by(config_h, self.contest, mix_h, ballots_h, mixer_t, self_t),
                    verified.is_ok()
                )

            },
            StatementType::PDecryption => {
                let pdecryptions_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::decryption_signed_by(config_h, self.contest, pdecryptions_h, self_t),
                    verified.is_ok()
                )

            },
            StatementType::Plaintexts => {
                let plaintexts_h = util::to_u8_64(&statement.hashes[1]);
                self.ret(
                    InputFact::plaintexts_signed_by(config_h, self.contest, plaintexts_h, self_t),
                    verified.is_ok()
                )
            }
        }
    }

    fn ret(&self, fact: InputFact, verified: bool) -> Option<InputFact> {
        if verified {
            Some(fact)
        } else {
            None
        }
    }
}



type VHash = Vec<u8>;

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedStatement {
    pub statement: Statement, 
    pub signature: Signature
}

impl SignedStatement {
    pub fn config(cfg_h: &hashing::Hash, pk: &Keypair) -> SignedStatement {
        let statement = Statement::config(cfg_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
    pub fn keyshare(cfg_h: &hashing::Hash, share_h: &hashing::Hash, contest: u32, pk: &Keypair) -> SignedStatement {
        let statement = Statement::keyshare(cfg_h.to_vec(), contest, share_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
    pub fn public_key(cfg_h: &hashing::Hash, pk_h: &hashing::Hash, contest: u32, pk: &Keypair) -> SignedStatement {
        let statement = Statement::public_key(cfg_h.to_vec(), contest, pk_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
    pub fn ballots(cfg_h: &hashing::Hash, ballots_h: &hashing::Hash, contest: u32, pk: &Keypair) -> SignedStatement {
        let statement = Statement::ballots(cfg_h.to_vec(), contest, ballots_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
    pub fn mix(cfg_h: &hashing::Hash, mix_h: &hashing::Hash, ballots_h: &hashing::Hash, contest: u32, 
        pk: &Keypair, mixing_trustee: Option<TrusteeIndex>) -> SignedStatement {
        
        let statement = Statement::mix(cfg_h.to_vec(), contest, mix_h.to_vec(), 
            ballots_h.to_vec(), mixing_trustee);
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
    
    pub fn pdecryptions(cfg_h: &hashing::Hash, contest: u32, pd_h: &hashing::Hash, pk: &Keypair) -> SignedStatement {
        let statement = Statement::partial_decryption(cfg_h.to_vec(), contest, pd_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
    pub fn plaintexts(cfg_h: &hashing::Hash, contest: u32, plaintext_h: &hashing::Hash, pk: &Keypair) -> SignedStatement {
        let statement = Statement::plaintexts(cfg_h.to_vec(), contest, plaintext_h.to_vec());
        let stmt_h = hashing::hash(&statement);
        let signature = pk.sign(&stmt_h);
        SignedStatement {
            statement,
            signature
        }
    }
    
}
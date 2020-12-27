use ed25519_dalek::Signature;
use ed25519_dalek::{Keypair, Signer};
use serde::{Deserialize, Serialize};

use crate::hashing;
use crate::protocol::ContestIndex;
use crate::protocol::TrusteeIndex;

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
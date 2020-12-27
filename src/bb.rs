use crate::hashing::{Hash};
use crate::artifact::*;
use crate::elgamal::PublicKey;
use crate::arithm::Element;
use crate::group::Group;
use crate::protocol::SVerifier;

pub trait Names {
    const CONFIG: &'static str = "config";
    const CONFIG_STMT: &'static str = "config.stmt";
    const PAUSE: &'static str = "pause";
    const ERROR: &'static str = "error";

    fn config_stmt(auth: u32) -> String { format!("{}/config.stmt", auth).to_string() }

    fn share(contest: u32, auth: u32) -> String { format!("{}/{}/share", auth, contest).to_string() }
    fn share_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/share.stmt", auth, contest).to_string() }
    

    fn public_key(contest: u32, auth: u32) -> String { format!("{}/{}/public_key", auth, contest).to_string() }
    fn public_key_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/public_key.stmt", auth, contest).to_string() }
    

    fn ballots(contest: u32) -> String { format!("ballotbox/{}/ballots", contest).to_string() }
    fn ballots_stmt(contest: u32) -> String { format!("ballotbox/{}/ballots.stmt", contest).to_string() }
    
    
    fn mix(contest: u32, auth: u32) -> String { format!("{}/{}/mix", auth, contest).to_string() }
    fn mix_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/mix.stmt", auth, contest).to_string() }
    fn mix_stmt_other(contest: u32, auth: u32, other_t: u32) -> String { format!("{}/{}/mix.{}.stmt", auth, contest, other_t).to_string() }

    fn decryption(contest: u32, auth: u32) -> String { format!("{}/{}/decryption", auth, contest).to_string() }
    fn decryption_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/decryption.stmt", auth, contest).to_string() }
    

    fn plaintexts(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts", auth, contest).to_string() }
    fn plaintexts_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts.stmt", auth, contest).to_string() }
    
    
    fn auth_error(auth: u32) -> String { format!("{}/error", auth).to_string() }
}

use crate::localstore::*;

/*trait BasicBulletinBoard {
    fn list(&self) -> Vec<String>;
    fn get_stmts(&self) -> Vec<String> {
        self.list().into_iter().filter(|s| {
            s.ends_with(".stmt")
        }).collect()
    }
    fn get_config_unsafe(&self) -> Option<Config>;
    fn get<A: HashBytes + DeserializeOwned>(&self, target: String, hash: Hash) -> Result<A, String>;
    fn put(&mut self, name: &str, data: &Path);
}*/

pub trait BulletinBoard<E: Element, G: Group<E>> {

    fn list(&self) -> Vec<String>;
    
    fn add_config(&mut self, config: &ConfigPath);
    fn get_config_unsafe(&self) -> Option<Config<E, G>>;
    
    fn add_config_stmt(&mut self, stmt: &ConfigStmtPath, trustee: u32);
    fn get_config(&self, hash: Hash) -> Option<Config<E, G>>;
    
    fn add_share(&mut self, path: &KeysharePath, contest: u32, trustee: u32);
    fn get_share(&self, contest: u32, trustee: u32, hash: Hash) -> Option<Keyshare<E, G>>;
    
    fn set_pk(&mut self, path: &PkPath, contest: u32);
    fn set_pk_stmt(&mut self, path: &PkStmtPath, contest: u32, trustee: u32);
    fn get_pk(&mut self, contest: u32, hash: Hash) -> Option<PublicKey<E, G>>;

    fn add_ballots(&mut self, path: &BallotsPath, contest: u32);
    fn get_ballots(&self, contest: u32, hash: Hash) -> Option<Ballots<E>>;
    
    fn add_mix(&mut self, path: &MixPath, contest: u32, trustee: u32);
    fn add_mix_stmt(&mut self, path: &MixStmtPath, contest: u32, trustee: u32, other_t: u32);
    fn get_mix(&self, contest: u32, trustee: u32, hash: Hash) -> Option<Mix<E>>;

    fn add_decryption(&mut self, path: &PDecryptionsPath, contest: u32, trustee: u32);
    fn get_decryption(&self, contest: u32, trustee: u32, hash: Hash) -> Option<PartialDecryption<E>>;

    fn set_plaintexts(&mut self, path: &PlaintextsPath, contest: u32);
    fn set_plaintexts_stmt(&mut self, path: &PlaintextsStmtPath, contest: u32, trustee: u32);
    fn get_plaintexts(&self, contest: u32, hash: Hash) -> Option<Plaintexts<E>>;

    fn get_statements(&self) -> Vec<SVerifier>;
    fn get_stmts(&self) -> Vec<String> {
        self.list().into_iter().filter(|s| {
            s.ends_with(".stmt")
        }).collect()
    }
    
    /*fn add_error(&self, error: Path, position: u32);
  
    fn get_config_statement(&self) -> Option<Vec<u8>>;

    fn get_config_signature(&self, auth: u32) -> Option<Vec<u8>>;

    
    fn get_share_statement(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn get_share_signature(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn add_public_key(&self, public_key: Path, stmt: Path, sig: Path, contest: u32, auth: u32);

    fn add_public_key_signature(&self, sig: Path, contest: u32, auth: u32);

    fn get_public_key(&self, contest: u32) -> Option<Vec<u8>>;

    fn get_public_key_statement(&self, contest: u32) -> Option<Vec<u8>>;

    fn get_public_key_signature(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn get_ballots(&self, contest: u32) -> Option<Vec<u8>>;

    fn get_ballots_statement(&self, contest: u32) -> Option<Vec<u8>>;

    fn get_ballots_signature(&self, contest: u32) -> Option<Vec<u8>>;

    fn add_ballots(&self, ballots: Path, stmt: Path, sig: Path, contest: u32);

    fn get_mix(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn get_mix_statement(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn get_mix_signature(&self, contest: u32, auth: u32, auth2: u32) -> Option<Vec<u8>>;

    fn add_mix(&self, mix: Path, stmt: Path, sig: Path, contest: u32, auth: u32);

    fn add_mix_signature(&self, sig: Path, contest: u32, auth_mixer: u32, auth_signer: u32);

    fn get_decryption(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn get_decryption_statement(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn get_decryption_signature(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn add_decryption(&self, decryption: Path, stmt: Path, sig: Path, contest: u32, auth: u32);

    fn get_plaintexts(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn get_plaintexts_statement(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn get_plaintexts_signature(&self, contest: u32, auth: u32) -> Option<Vec<u8>>;

    fn add_plaintexts(&self, plau32exts: Path, stmt: Path, sig: Path, contest: u32, auth: u32);

    fn add_plaintexts_signature(&self, sig: Path, contest: u32, auth: u32);*/
}
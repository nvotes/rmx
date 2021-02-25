// pub mod memory_bb;
pub mod basic;
pub mod generic;
pub mod git;
pub mod localstore;

use std::path::PathBuf;
use std::path::Path;

use crate::data::entity::*;
use crate::crypto::hashing::Hash;
use crate::crypto::elgamal::PublicKey;
use crate::crypto::base::Element;
use crate::crypto::base::Group;
use crate::data::bytes::ByteError;
use crate::protocol::statement::StatementVerifier;

quick_error! {
    #[derive(Debug)]
    pub enum BBError {
        Empty{}
        GitError(err: git2::Error) {
            from()
        }
        IOError(err: std::io::Error) {
            from()
        }
        ByteError(err: ByteError) {
            from()
        }
        Msg(message: String) {
            from()
        }
    }
}

pub trait BulletinBoard<E: Element, G: Group<E>> {

    fn list(&self) -> Result<Vec<String>, BBError>;
    
    fn add_config(&mut self, config: &ConfigPath) -> Result<(), BBError>;
    fn get_config_unsafe(&self) -> Result<Option<Config<E, G>>, BBError>;
    
    fn add_config_stmt(&mut self, stmt: &ConfigStmtPath, trustee: u32) -> Result<(), BBError>;
    fn get_config(&self, hash: Hash) -> Result<Option<Config<E, G>>, BBError>;
    
    fn add_share(&mut self, path: &KeysharePath, contest: u32, trustee: u32) -> Result<(), BBError>;
    fn get_share(&self, contest: u32, trustee: u32, hash: Hash) -> Result<Option<Keyshare<E, G>>, BBError>;
    
    fn set_pk(&mut self, path: &PkPath, contest: u32) -> Result<(), BBError>;
    fn set_pk_stmt(&mut self, path: &PkStmtPath, contest: u32, trustee: u32) -> Result<(), BBError>;
    fn get_pk(&mut self, contest: u32, hash: Hash) -> Result<Option<PublicKey<E, G>>, BBError>;

    fn add_ballots(&mut self, path: &BallotsPath, contest: u32) -> Result<(), BBError>;
    fn get_ballots(&self, contest: u32, hash: Hash) -> Result<Option<Ballots<E>>, BBError>;
    
    fn add_mix(&mut self, path: &MixPath, contest: u32, trustee: u32) -> Result<(), BBError>;
    fn add_mix_stmt(&mut self, path: &MixStmtPath, contest: u32, trustee: u32, other_t: u32) -> Result<(), BBError>;
    fn get_mix(&self, contest: u32, trustee: u32, hash: Hash) -> Result<Option<Mix<E>>, BBError>;

    fn add_decryption(&mut self, path: &PDecryptionsPath, contest: u32, trustee: u32) -> Result<(), BBError>;
    fn get_decryption(&self, contest: u32, trustee: u32, hash: Hash) -> Result<Option<PartialDecryption<E>>, BBError>;

    fn set_plaintexts(&mut self, path: &PlaintextsPath, contest: u32) -> Result<(), BBError>;
    fn set_plaintexts_stmt(&mut self, path: &PlaintextsStmtPath, contest: u32, trustee: u32) -> Result<(), BBError>;
    fn get_plaintexts(&self, contest: u32, hash: Hash) -> Result<Option<Plaintexts<E>>, BBError>;

    fn get_statements(&self) -> Result<Vec<StatementVerifier>, BBError>;
    fn get_stmts(&self) -> Result<Vec<String>, BBError> {
        let items = self.list()?;
        let ret = items.into_iter().filter(|s| {
            s.ends_with(".stmt")
        }).collect();

        Ok(ret)
    }

    fn artifact_location(&self, path: &str) -> (i32, u32) {
        let p = Path::new(&path);
        let comp: Vec<&str> = p.components()
            .take(2)
            .map(|comp| comp.as_os_str().to_str().unwrap())
            .collect();
        
        let trustee: i32 =
        if comp[0] == "ballotbox" {
            -1
        }
        else {
            comp[0].parse().unwrap()
        };
        // root artifacts (eg config) have no contest
        let contest: u32 = comp[1].parse().unwrap_or(0);
    
        (trustee, contest)
    }
}


pub struct ConfigPath(pub PathBuf);
pub struct ConfigStmtPath(pub PathBuf);
pub struct KeysharePath(pub PathBuf, pub PathBuf);
pub struct PkPath(pub PathBuf, pub PathBuf);
pub struct PkStmtPath(pub PathBuf);
pub struct BallotsPath(pub PathBuf, pub PathBuf);
pub struct MixPath(pub PathBuf, pub PathBuf);
pub struct MixStmtPath(pub PathBuf);
pub struct PDecryptionsPath(pub PathBuf, pub PathBuf);
pub struct PlaintextsPath(pub PathBuf, pub PathBuf);
pub struct PlaintextsStmtPath(pub PathBuf);
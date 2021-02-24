// pub mod memory_bb;
pub mod basic;
pub mod generic;
pub mod git;
pub mod localstore;

use std::path::PathBuf;
use std::path::Path;

use crate::data::entity::*;
use crate::crypto::hashing::{Hash};
use crate::crypto::elgamal::PublicKey;
use crate::crypto::base::Element;
use crate::crypto::base::Group;
use crate::protocol::statement::StatementVerifier;

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

    fn get_statements(&self) -> Vec<StatementVerifier>;
    fn get_stmts(&self) -> Vec<String> {
        self.list().into_iter().filter(|s| {
            s.ends_with(".stmt")
        }).collect()
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


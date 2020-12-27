use std::path::{Path,PathBuf};
use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use crate::hashing;
use crate::util;
use crate::action::Act;
use crate::artifact::*;
use crate::statement::*;
use crate::elgamal::PublicKey;
use crate::arithm::Element;
use crate::group::Group;

pub struct ConfigPath(pub PathBuf);
pub struct ConfigStmtPath(pub PathBuf);
pub struct KeysharePath(pub PathBuf, pub PathBuf);
pub struct PkPath(pub PathBuf, pub PathBuf);
pub struct PkStmtPath(pub PathBuf);
pub struct BallotsPath(pub PathBuf, pub PathBuf);
pub struct MixPath(pub PathBuf, pub PathBuf);
pub struct MixStmtPath(pub PathBuf);
pub struct PDecryptionsPath(pub PathBuf, pub PathBuf);
// pub struct PDecryptionsStmtPath(pub PathBuf);
pub struct PlaintextsPath(pub PathBuf, pub PathBuf);
pub struct PlaintextsStmtPath(pub PathBuf);

pub struct LocalStore<E, G> {
    pub fs_path: PathBuf,
    phantom_e: PhantomData<E>,
    phantom_g: PhantomData<G>
}

impl<E: Element + DeserializeOwned, 
    G: Group<E> + DeserializeOwned> 
    LocalStore<E, G> {
    
    pub fn new(fs_path: String) -> LocalStore<E, G> {
        let target = Path::new(&fs_path);
        assert!(target.exists() && target.is_dir());
        LocalStore {
            fs_path: target.to_path_buf(),
            phantom_e: PhantomData,
            phantom_g: PhantomData
        }
    }
    pub fn set_config_stmt(&self, act: &Act, stmt: &SignedStatement) -> ConfigStmtPath {
        assert!(matches!(act, Act::CheckConfig(_)));
        assert!(matches!(stmt.statement.stype, StatementType::Config));
        let stmt_b = bincode::serialize(&stmt).unwrap();
        ConfigStmtPath (
            self.set_work(act, vec![stmt_b]).remove(0)
        )
    }
    pub fn set_share(&self, act: &Act, share: Keyshare<E, G>, stmt: &SignedStatement) -> KeysharePath {
        assert!(matches!(act, Act::PostShare(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Keyshare));
        let share_b = bincode::serialize(&share).unwrap();
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![share_b, stmt_b]);
        let share_p = paths.remove(0);
        let stmt_p = paths.remove(0);
        
        KeysharePath (share_p, stmt_p)
    }
    pub fn set_pk(&self, act: &Act, pk: PublicKey<E, G>, stmt: &SignedStatement) -> PkPath {
        assert!(matches!(act, Act::CombineShares(..)));
        assert!(matches!(stmt.statement.stype, StatementType::PublicKey));
        let pk_b = bincode::serialize(&pk).unwrap();
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![pk_b, stmt_b]);
        let pk_p = paths.remove(0);
        let stmt_p = paths.remove(0);
        
        PkPath(pk_p, stmt_p)
    }
    pub fn set_pk_stmt(&self, act: &Act, stmt: &SignedStatement) -> PkStmtPath {
        assert!(matches!(act, Act::CheckPk(..)));
        assert!(matches!(stmt.statement.stype, StatementType::PublicKey));
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![stmt_b]);
        let stmt_p = paths.remove(0);
        
        PkStmtPath(stmt_p)
    }
    pub fn set_mix(&self, act: &Act, mix: Mix<E>, stmt: &SignedStatement) -> MixPath {
        assert!(matches!(act, Act::Mix(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Mix));
        let mix_b = bincode::serialize(&mix).unwrap();
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![mix_b, stmt_b]);
        let pk_p = paths.remove(0);
        let stmt_p = paths.remove(0);
        
        MixPath(pk_p, stmt_p)
    }
    pub fn set_mix_stmt(&self, act: &Act, stmt: &SignedStatement) -> MixStmtPath {
        assert!(matches!(act, Act::CheckMix(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Mix));
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![stmt_b]);
        let stmt_p = paths.remove(0);
        
        MixStmtPath(stmt_p)
    }


    pub fn set_pdecryptions(&self, act: &Act, pdecryptions: PartialDecryption<E>, stmt: &SignedStatement) -> PDecryptionsPath {
        assert!(matches!(act, Act::PartialDecrypt(..)));
        assert!(matches!(stmt.statement.stype, StatementType::PDecryption));
        let pdecryptions_b = bincode::serialize(&pdecryptions).unwrap();
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![pdecryptions_b, stmt_b]);
        let pdecryptions_p = paths.remove(0);
        let stmt_p = paths.remove(0);
        
        PDecryptionsPath(pdecryptions_p, stmt_p)
    }
    
    pub fn set_plaintexts(&self, act: &Act, plaintexts: Plaintexts<E>, stmt: &SignedStatement) -> PlaintextsPath {
        assert!(matches!(act, Act::CombineDecryptions(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Plaintexts));
        let plaintexts_b = bincode::serialize(&plaintexts).unwrap();
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![plaintexts_b, stmt_b]);
        let plaintexts_p = paths.remove(0);
        let stmt_p = paths.remove(0);
        
        PlaintextsPath(plaintexts_p, stmt_p)
    }
    pub fn set_plaintexts_stmt(&self, act: &Act, stmt: &SignedStatement) -> PlaintextsStmtPath {
        assert!(matches!(act, Act::CheckPlaintexts(..)));
        assert!(matches!(stmt.statement.stype, StatementType::Plaintexts));
        let stmt_b = bincode::serialize(&stmt).unwrap();
        let mut paths = self.set_work(act, vec![stmt_b]);
        let stmt_p = paths.remove(0);
        
        PlaintextsStmtPath(stmt_p)
    }
    
    pub fn get_work(&self, action: &Act, _hash: hashing::Hash) -> Option<Vec<PathBuf>> {
        let target = self.path_for_action(action);
        let mut ret = Vec::new();
        for i in 0..10 {
            let with_ext = target.with_extension(i.to_string());
            if with_ext.exists() && with_ext.is_file() {
                ret.push(with_ext);
            }
            else {
                break;
            }
        }

        if ret.len() > 0 {
            Some(ret)
        }
        else {
            None
        }
    }

    fn set_work(&self, action: &Act, work: Vec<Vec<u8>>) -> Vec<PathBuf> {
        let target = self.path_for_action(action);
        let mut ret = Vec::new();
        
        for (i, item) in work.iter().enumerate() {
            let with_ext = target.with_extension(i.to_string());
            assert!(!with_ext.exists());
            util::write_file_bytes(&with_ext, item).unwrap();
            ret.push(with_ext);
        }
        ret
    }
    
    fn path_for_action(&self, action: &Act) -> PathBuf {
        let hash = hashing::hash(action);
        let encoded = hex::encode(&hash);
        let work_path = Path::new(&encoded);
        let ret = Path::new(&self.fs_path).join(work_path);
        // println!("action {:?}, returning path {:?}", action, ret);

        ret
    }
}


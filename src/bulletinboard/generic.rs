use std::marker::PhantomData;
use std::path::Path;
use serde::de::DeserializeOwned;

use rug::Integer;
use curve25519_dalek::ristretto::RistrettoPoint;
use log::info;

use crate::bulletinboard::*;
use crate::data::entity::*;
use crate::data::bytes::*;
use crate::crypto::hashing::{HashBytes, Hash};
use crate::crypto::elgamal::PublicKey;
use crate::crypto::base::Element;
use crate::crypto::base::Group;
use crate::crypto::backend::rug_b::RugGroup;
use crate::crypto::backend::ristretto_b::RistrettoGroup;
use crate::bulletinboard::basic::BasicBoard;
use crate::protocol::statement::SignedStatement;
use crate::protocol::statement::StatementVerifier;

pub struct GenericBulletinBoard<E, G, B> {
    basic: B,
    phantom_e: PhantomData<E>,
    phantom_g: PhantomData<G>,
}

impl<
    E: Element + DeserializeOwned + FromByteTree, 
    G: Group<E> + DeserializeOwned + FromByteTree,
    B: BasicBoard
    > GenericBulletinBoard<E, G, B> {    
    
    pub fn new(basic: B) -> GenericBulletinBoard<E, G, B> {
        GenericBulletinBoard {
            basic: basic,
            phantom_e: PhantomData,
            phantom_g: PhantomData
        }
    }
    fn put(&mut self, entries: Vec<(&str, &Path)>) {
        self.basic.put(entries);
    }
    fn get<A: HashBytes + DeserializeOwned + FromByteTree>(&self, target: String, hash: Hash) -> Result<A, String> {
        self.basic.get(target, hash)
    }
    pub fn get_unsafe(&self, target: String) -> Option<&Vec<u8>> {
        self.basic.get_unsafe(&target)
    }

    const CONFIG: &'static str = "config";
    const CONFIG_STMT: &'static str = "config.stmt";
    const PAUSE: &'static str = "pause";
    const ERROR: &'static str = "error";

    fn config_stmt(auth: u32) -> String { format!("{}/config.stmt", auth).to_string() }

    fn share(contest: u32, auth: u32) -> String { format!("{}/{}/share", auth, contest).to_string() }
    fn share_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/share.stmt", auth, contest).to_string() }
    

    pub fn public_key(contest: u32, auth: u32) -> String { format!("{}/{}/public_key", auth, contest).to_string() }
    fn public_key_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/public_key.stmt", auth, contest).to_string() }
    

    pub fn ballots(contest: u32) -> String { format!("ballotbox/{}/ballots", contest).to_string() }
    fn ballots_stmt(contest: u32) -> String { format!("ballotbox/{}/ballots.stmt", contest).to_string() }
    
    
    fn mix(contest: u32, auth: u32) -> String { format!("{}/{}/mix", auth, contest).to_string() }
    fn mix_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/mix.stmt", auth, contest).to_string() }
    fn mix_stmt_other(contest: u32, auth: u32, other_t: u32) -> String { format!("{}/{}/mix.{}.stmt", auth, contest, other_t).to_string() }

    fn decryption(contest: u32, auth: u32) -> String { format!("{}/{}/decryption", auth, contest).to_string() }
    fn decryption_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/decryption.stmt", auth, contest).to_string() }
    

    pub fn plaintexts(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts", auth, contest).to_string() }
    fn plaintexts_stmt(contest: u32, auth: u32) -> String { format!("{}/{}/plaintexts.stmt", auth, contest).to_string() }
    
    
    fn auth_error(auth: u32) -> String { format!("{}/error", auth).to_string() }
}

impl<
    E: Element + DeserializeOwned + FromByteTree, 
    G: Group<E> + DeserializeOwned + FromByteTree,
    B: BasicBoard
    > 
    BulletinBoard<E, G> for GenericBulletinBoard<E, G, B> {
    
    fn list(&self) -> Vec<String> {
        self.basic.list()
    }
    fn add_config(&mut self, path: &ConfigPath) {
        self.put(
            vec![(Self::CONFIG, &path.0)]
        );
    }
    fn get_config_unsafe(&self) -> Option<Config<E, G>> {
        let bytes = self.basic.get_unsafe(Self::CONFIG)?;
        // let ret: Config<E, G> = bincode::deserialize(bytes).unwrap();
        let ret = Config::<E, G>::deser(bytes).unwrap();

        Some(ret)
    }
    
    fn get_config(&self, hash: Hash) -> Option<Config<E, G>> {
        let ret = self.get(Self::CONFIG.to_string(), hash).ok()?;

        Some(ret)
    }
    fn add_config_stmt(&mut self, path: &ConfigStmtPath, trustee: u32) {
        self.put(
            vec![(&Self::config_stmt(trustee), &path.0)]
        );
    }
    
    fn add_share(&mut self, path: &KeysharePath, contest: u32, trustee: u32) {
        self.put(
            vec![(&Self::share(contest, trustee), &path.0),
                 (&Self::share_stmt(contest, trustee), &path.1)]
        );
    }
    fn get_share(&self, contest: u32, auth: u32, hash: Hash) -> Option<Keyshare<E, G>> {
        let key = Self::share(contest, auth).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }
    
    fn set_pk(&mut self, path: &PkPath, contest: u32) {
        // 0: trustee 0 combines shares into pk
        self.put(
            vec![(&Self::public_key(contest, 0), &path.0),
                (&Self::public_key_stmt(contest, 0), &path.1)]
        );
    }
    fn set_pk_stmt(&mut self, path: &PkStmtPath, contest: u32, trustee: u32) {
        self.put(vec![(&Self::public_key_stmt(contest, trustee), &path.0)]);
    }
    fn get_pk(&mut self, contest: u32, hash: Hash) -> Option<PublicKey<E, G>> {
        // 0: trustee 0 combines shares into pk
        let key = Self::public_key(contest, 0).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }

    fn add_ballots(&mut self, path: &BallotsPath, contest: u32) {
        self.put(
            vec![(&Self::ballots(contest), &path.0),
                (&Self::ballots_stmt(contest), &path.1)]
        );
    }
    fn get_ballots(&self, contest: u32, hash: Hash) -> Option<Ballots<E>> {
        let key = Self::ballots(contest).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }

    fn add_mix(&mut self, path: &MixPath, contest: u32, trustee: u32) {
        self.put(
            vec![(&Self::mix(contest, trustee), &path.0),
                (&Self::mix_stmt(contest, trustee), &path.1)]
        );
    }
    fn add_mix_stmt(&mut self, path: &MixStmtPath, contest: u32, trustee: u32, other_t: u32) {
        self.put(vec![(&Self::mix_stmt_other(contest, trustee, other_t), &path.0)]);
    }
    fn get_mix(&self, contest: u32, trustee: u32, hash: Hash) -> Option<Mix<E>> {
        let key = Self::mix(contest, trustee).to_string();
        let now_ = std::time::Instant::now();
        let ret = self.get(key, hash).ok()?;
        info!(">> Get mix {}", now_.elapsed().as_millis());

        Some(ret)
    }

    fn add_decryption(&mut self, path: &PDecryptionsPath, contest: u32, trustee: u32) {
        self.put(
            vec![(&Self::decryption(contest, trustee), &path.0),
                (&Self::decryption_stmt(contest, trustee), &path.1)]
        );
    }
    fn get_decryption(&self, contest: u32, trustee: u32, hash: Hash) -> Option<PartialDecryption<E>> {
        let key = Self::decryption(contest, trustee).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }

    fn set_plaintexts(&mut self, path: &PlaintextsPath, contest: u32) {
        // 0: trustee 0 combines shares into pk
        self.put(
            vec![(&Self::plaintexts(contest, 0), &path.0),
                (&Self::plaintexts_stmt(contest, 0), &path.1)]
        );
    }
    fn set_plaintexts_stmt(&mut self, path: &PlaintextsStmtPath, contest: u32, trustee: u32) {
        self.put(vec![(&Self::plaintexts_stmt(contest, trustee), &path.0)]);
    }
    fn get_plaintexts(&self, contest: u32, hash: Hash) -> Option<Plaintexts<E>> {
        // 0: trustee 0 combines shares into pk
        let key = Self::plaintexts(contest, 0).to_string();
        let ret = self.get(key, hash).ok()?;

        Some(ret)
    }

    fn get_statements(&self) -> Vec<StatementVerifier> {
        
        let sts = self.get_stmts();
        let mut ret = Vec::new();
        // println!("Statements {:?}", sts);
        
        for s in sts.iter() {
            let s_bytes = self.basic.get_unsafe(s).unwrap().to_vec();
            let (trustee, contest) = self.artifact_location(s);
            // let stmt: SignedStatement = bincode::deserialize(&s_bytes).unwrap();
            let stmt = SignedStatement::deser(&s_bytes).unwrap();

            let next = StatementVerifier {
                statement: stmt,
                trustee: trustee,
                contest: contest
            };
            ret.push(next);
        }

        ret
    }
}


#[cfg(test)]
mod tests {

    use uuid::Uuid;
    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;
    use tempfile::NamedTempFile;
    
    use rug::Integer;

    use crate::crypto::hashing;
    use crate::crypto::backend::rug_b::*;
    use crate::data::entity::Config;
    use crate::bulletinboard::generic::*;
    use crate::bulletinboard::basic::*;

        
    #[test]
    fn test_membb_putget() {
        let mut csprng = OsRng;
        let id = Uuid::new_v4();
        let group = RugGroup::default();
        let contests = 2;
        let ballotbox_pk = Keypair::generate(&mut csprng).public; 
        let trustees = 3;
        let mut trustee_pks = Vec::with_capacity(trustees);
        
        for _ in 0..trustees {
            let keypair = Keypair::generate(&mut csprng);
            trustee_pks.push(keypair.public);
        }
        let mut cfg = Config {
            id: id.as_bytes().clone(),
            group: group,
            contests: contests, 
            ballotbox: ballotbox_pk, 
            trustees: trustee_pks,
            phantom_e: PhantomData
        };

        let mut bb = GenericBulletinBoard::<Integer, RugGroup, MBasic>::new(MBasic::new());
        // let cfg_b = bincode::serialize(&cfg).unwrap();
        let cfg_b = cfg.ser();
        
        let tmp_file = NamedTempFile::new().unwrap();
        let target = "test";
        let path = tmp_file.path();
        std::fs::write(path, &cfg_b).unwrap();
        bb.put(vec![("test", path)]);
        
        let hash = hashing::hash(&cfg);
        let mut cfg_result = bb.get::<Config<Integer, RugGroup>>(target.to_string(), hash);
        assert!(cfg_result.is_ok());

        cfg.id = Uuid::new_v4().as_bytes().clone();
        let bad_hash = hashing::hash(&cfg);
        cfg_result = bb.get::<Config<Integer, RugGroup>>(target.to_string(), bad_hash);
        assert!(cfg_result.is_err());
    }
}
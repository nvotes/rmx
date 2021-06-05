use std::marker::PhantomData;
use std::path::Path;

use log::info;

use crate::bulletinboard::basic::BasicBoard;
use crate::bulletinboard::bulletinboard::*;
use crate::crypto::elgamal::PublicKey;
use crate::crypto::group::Element;
use crate::crypto::group::Group;
use crate::crypto::hashing::Hash;
use crate::data::artifact::*;
use crate::data::byte_tree::*;
use crate::protocol::statement::SignedStatement;
use crate::protocol::statement::StatementVerifier;

pub struct GenericBulletinBoard<E, G, B> {
    basic: B,
    phantom_e: PhantomData<E>,
    phantom_g: PhantomData<G>,
}

impl<E: Element + FromByteTree, G: Group<E> + FromByteTree, B: BasicBoard>
    GenericBulletinBoard<E, G, B>
{
    pub fn new(basic: B) -> GenericBulletinBoard<E, G, B> {
        GenericBulletinBoard {
            basic,
            phantom_e: PhantomData,
            phantom_g: PhantomData,
        }
    }
    fn put(&mut self, entries: Vec<(&str, &Path)>) -> Result<(), BBError> {
        let entries_ = entries.iter().map(|(a, b)| (Path::new(a), *b)).collect();
        self.basic.put(entries_)
    }
    fn get<A: ToByteTree + FromByteTree>(
        &self,
        target: String,
        hash: Hash,
    ) -> Result<Option<A>, BBError> {
        self.basic.get(target, hash)
    }
    pub fn get_unsafe(&self, target: String) -> Result<Option<Vec<u8>>, BBError> {
        self.basic.get_unsafe(&target)
    }

    fn config_stmt(auth: u32) -> String {
        format!("{}/{}.stmt", auth, CONFIG)
    }

    fn share(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}", auth, contest, SHARE)
    }
    fn share_stmt(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}.stmt", auth, contest, SHARE)
    }

    pub fn public_key(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}", auth, contest, PUBLIC_KEY)
    }
    fn public_key_stmt(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}.stmt", auth, contest, PUBLIC_KEY)
    }

    pub fn ballots(contest: u32) -> String {
        format!("ballotbox/{}/{}", contest, BALLOTS)
    }
    fn ballots_stmt(contest: u32) -> String {
        format!("ballotbox/{}/{}.stmt", contest, BALLOTS)
    }

    fn mix(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}", auth, contest, MIX)
    }
    fn mix_stmt(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}.stmt", auth, contest, MIX)
    }
    fn mix_stmt_other(contest: u32, auth: u32, other_t: u32) -> String {
        format!("{}/{}/{}.{}.stmt", auth, contest, MIX, other_t)
    }

    fn decryption(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}", auth, contest, DECRYPTION)
    }
    fn decryption_stmt(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}.stmt", auth, contest, DECRYPTION)
    }

    pub fn plaintexts(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}", auth, contest, PLAINTEXTS)
    }
    fn plaintexts_stmt(contest: u32, auth: u32) -> String {
        format!("{}/{}/{}.stmt", auth, contest, PLAINTEXTS)
    }

    fn auth_error(auth: u32) -> String {
        format!("{}/error", auth)
    }
}

impl<E: Element + FromByteTree, G: Group<E> + FromByteTree, B: BasicBoard> BulletinBoard<E, G>
    for GenericBulletinBoard<E, G, B>
{
    fn list(&self) -> Result<Vec<String>, BBError> {
        self.basic.list()
    }

    fn add_config(&mut self, path: &ConfigPath) -> Result<(), BBError> {
        self.put(vec![(CONFIG, &path.0)])
    }
    fn get_config_unsafe(&self) -> Result<Option<Config<E, G>>, BBError> {
        let bytes_option = self.basic.get_unsafe(CONFIG)?;

        if let Some(bytes) = bytes_option {
            let ret = Config::<E, G>::deser(&bytes)?;
            Ok(Some(ret))
        } else {
            Ok(None)
        }
    }

    fn get_config(&self, hash: Hash) -> Result<Option<Config<E, G>>, BBError> {
        self.get(CONFIG.to_string(), hash)
    }
    fn add_config_stmt(&mut self, path: &ConfigStmtPath, trustee: u32) -> Result<(), BBError> {
        self.put(vec![(&Self::config_stmt(trustee), &path.0)])
    }

    fn add_share(
        &mut self,
        path: &KeysharePath,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError> {
        self.put(vec![
            (&Self::share(contest, trustee), &path.0),
            (&Self::share_stmt(contest, trustee), &path.1),
        ])
    }
    fn get_share(
        &self,
        contest: u32,
        auth: u32,
        hash: Hash,
    ) -> Result<Option<Keyshare<E, G>>, BBError> {
        let key = Self::share(contest, auth);
        self.get(key, hash)
    }

    fn set_pk(&mut self, path: &PkPath, contest: u32) -> Result<(), BBError> {
        // 0: trustee 0 combines shares into pk
        self.put(vec![
            (&Self::public_key(contest, 0), &path.0),
            (&Self::public_key_stmt(contest, 0), &path.1),
        ])
    }
    fn set_pk_stmt(
        &mut self,
        path: &PkStmtPath,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError> {
        self.put(vec![(&Self::public_key_stmt(contest, trustee), &path.0)])
    }
    fn get_pk(&mut self, contest: u32, hash: Hash) -> Result<Option<PublicKey<E, G>>, BBError> {
        // 0: trustee 0 combines shares into pk
        let key = Self::public_key(contest, 0);
        self.get(key, hash)
    }

    fn add_ballots(&mut self, path: &BallotsPath, contest: u32) -> Result<(), BBError> {
        self.put(vec![
            (&Self::ballots(contest), &path.0),
            (&Self::ballots_stmt(contest), &path.1),
        ])
    }
    fn get_ballots(&self, contest: u32, hash: Hash) -> Result<Option<Ballots<E>>, BBError> {
        let key = Self::ballots(contest);
        self.get(key, hash)
    }

    fn add_mix(&mut self, path: &MixPath, contest: u32, trustee: u32) -> Result<(), BBError> {
        self.put(vec![
            (&Self::mix(contest, trustee), &path.0),
            (&Self::mix_stmt(contest, trustee), &path.1),
        ])
    }
    fn add_mix_stmt(
        &mut self,
        path: &MixStmtPath,
        contest: u32,
        trustee: u32,
        other_t: u32,
    ) -> Result<(), BBError> {
        self.put(vec![(
            &Self::mix_stmt_other(contest, trustee, other_t),
            &path.0,
        )])
    }
    fn get_mix(&self, contest: u32, trustee: u32, hash: Hash) -> Result<Option<Mix<E>>, BBError> {
        let key = Self::mix(contest, trustee);
        let now_ = std::time::Instant::now();
        let ret = self.get(key, hash);
        info!(">> Get mix {}", now_.elapsed().as_millis());

        ret
    }

    fn add_decryption(
        &mut self,
        path: &PDecryptionsPath,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError> {
        self.put(vec![
            (&Self::decryption(contest, trustee), &path.0),
            (&Self::decryption_stmt(contest, trustee), &path.1),
        ])
    }
    fn get_decryption(
        &self,
        contest: u32,
        trustee: u32,
        hash: Hash,
    ) -> Result<Option<PartialDecryption<E>>, BBError> {
        let key = Self::decryption(contest, trustee);
        self.get(key, hash)
    }

    fn set_plaintexts(&mut self, path: &PlaintextsPath, contest: u32) -> Result<(), BBError> {
        // 0: trustee 0 combines shares into pk
        self.put(vec![
            (&Self::plaintexts(contest, 0), &path.0),
            (&Self::plaintexts_stmt(contest, 0), &path.1),
        ])
    }
    fn set_plaintexts_stmt(
        &mut self,
        path: &PlaintextsStmtPath,
        contest: u32,
        trustee: u32,
    ) -> Result<(), BBError> {
        self.put(vec![(&Self::plaintexts_stmt(contest, trustee), &path.0)])
    }
    fn get_plaintexts(&self, contest: u32, hash: Hash) -> Result<Option<Plaintexts<E>>, BBError> {
        // 0: trustee 0 combines shares into pk
        let key = Self::plaintexts(contest, 0);
        self.get(key, hash)
    }

    fn get_statements(&self) -> Result<Vec<StatementVerifier>, BBError> {
        let sts = self.get_stmts()?;
        let mut ret = Vec::new();

        for s in sts.iter() {
            let s_bytes = self
                .basic
                .get_unsafe(s)?
                .ok_or_else(|| BBError::Msg("Statement not found".to_string()))?;
            let (name, trustee, contest) = self.artifact_location(s);

            let stmt = SignedStatement::deser(&s_bytes)?;

            let next = StatementVerifier {
                statement: stmt,
                trustee,
                contest,
                artifact_name: name,
            };
            ret.push(next);
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {

    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use tempfile::NamedTempFile;
    use uuid::Uuid;

    use rug::Integer;

    use crate::bulletinboard::basic::*;
    use crate::bulletinboard::generic::*;
    use crate::crypto::backend::rug_b::*;
    use crate::crypto::hashing;
    use crate::data::artifact::Config;

    #[test]
    fn test_mbasic_putget() {
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
        let mut cfg: Config<Integer, RugGroup> = Config {
            id: id.as_bytes().clone(),
            group: group,
            contests: contests,
            ballotbox: ballotbox_pk,
            trustees: trustee_pks,
            phantom_e: PhantomData,
        };

        let mut bb = GenericBulletinBoard::<Integer, RugGroup, MBasic>::new(MBasic::default());
        let cfg_b = cfg.ser();

        let tmp_file = NamedTempFile::new().unwrap();
        let target = "test";
        let path = tmp_file.path();
        std::fs::write(path, &cfg_b).unwrap();
        bb.put(vec![("test", path)]).unwrap();

        let hash = hashing::hash(&cfg);
        let mut cfg_result = bb.get::<Config<Integer, RugGroup>>(target.to_string(), hash);
        assert!(cfg_result.is_ok());

        cfg.id = Uuid::new_v4().as_bytes().clone();
        let bad_hash = hashing::hash(&cfg);
        cfg_result = bb.get::<Config<Integer, RugGroup>>(target.to_string(), bad_hash);
        assert!(cfg_result.is_err());
    }
}

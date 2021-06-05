use std::marker::PhantomData;

use ed25519_dalek::PublicKey as SPublicKey;
use serde::Serialize;

use crate::crypto::elgamal::*;
use crate::crypto::group::*;
use crate::crypto::shuffler::*;

#[derive(Serialize, Eq, PartialEq, Debug)]
pub struct Config<E, G> {
    pub id: [u8; 16],
    pub group: G,
    pub contests: u32,
    pub ballotbox: SPublicKey,
    pub trustees: Vec<SPublicKey>,
    pub phantom_e: PhantomData<E>,
}

impl<E, G> Config<E, G> {
    pub fn label(&self) -> Vec<u8> {
        self.id.to_vec()
    }
}

#[derive(Serialize)]
pub struct Keyshare<E: Element, G> {
    pub share: PublicKey<E, G>,
    pub proof: Schnorr<E>,
    pub encrypted_sk: EncryptedPrivateKey,
}

#[derive(Serialize, Eq, PartialEq)]
pub struct EncryptedPrivateKey {
    pub bytes: Vec<u8>,
    pub iv: Vec<u8>,
}

#[derive(Serialize, Eq, PartialEq)]
pub struct Ballots<E> {
    pub ciphertexts: Vec<Ciphertext<E>>,
}

#[derive(Serialize)]
pub struct Mix<E: Element> {
    pub mixed_ballots: Vec<Ciphertext<E>>,
    pub proof: ShuffleProof<E>,
}

#[derive(Serialize)]
pub struct PartialDecryption<E: Element> {
    pub pd_ballots: Vec<E>,
    pub proofs: Vec<ChaumPedersen<E>>,
}

#[derive(Serialize, Eq, PartialEq)]
pub struct Plaintexts<E> {
    pub plaintexts: Vec<E>,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use rug::Integer;
    use uuid::Uuid;

    use crate::crypto::backend::rug_b::*;
    use crate::data::artifact::*;
    use crate::data::byte_tree::*;

    #[test]
    fn test_config_serde() {
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
        let cfg = Config {
            id: id.as_bytes().clone(),
            group: group,
            contests: contests,
            ballotbox: ballotbox_pk,
            trustees: trustee_pks,
            phantom_e: PhantomData,
        };

        let cfg_b = cfg.ser();
        let cfg_d = Config::<Integer, RugGroup>::deser(&cfg_b).unwrap();

        assert_eq!(cfg, cfg_d);
    }
}

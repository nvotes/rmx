use std::marker::PhantomData;

use ed25519_dalek::PublicKey as SPublicKey;
use serde::{Deserialize, Serialize};

use crate::arithm::*;
use crate::elgamal::*;
use crate::group::*;
use crate::shuffler::*;

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Config<E, G> {
    pub id: [u8; 16],
    pub group: G,
    pub contests: u32, 
    pub ballotbox: SPublicKey, 
    pub trustees: Vec<SPublicKey>,
    pub phantom_e: PhantomData<E>
}

#[derive(Serialize, Deserialize)]
pub struct Keyshare<E: Element, G> {
    pub share: PublicKey<E, G>,
    pub proof: Schnorr<E>,
    pub encrypted_sk: EncryptedPrivateKey
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedPrivateKey {
    pub bytes: Vec<u8>,
    pub iv: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct Ballots<E> {
    pub ciphertexts: Vec<Ciphertext<E>>
}

#[derive(Serialize, Deserialize)]
pub struct Mix<E: Element> {
    pub mixed_ballots: Vec<Ciphertext<E>>,
    pub proof: ShuffleProof<E>
}

#[derive(Serialize, Deserialize)]
pub struct PartialDecryption<E: Element> {
    pub pd_ballots: Vec<E>,
    pub proofs: Vec<ChaumPedersen<E>>
}

#[derive(Serialize, Deserialize)]
pub struct Plaintexts<E> {
    pub plaintexts: Vec<E>
}

#[cfg(test)]
mod tests {  
    use uuid::Uuid;
    use rug::Integer;
    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;
    use crate::rug_b::*;
    use crate::artifact::*;

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
            phantom_e: PhantomData
        };

        let cfg_b = bincode::serialize(&cfg).unwrap();
        let cfg_d: Config<Integer, RugGroup> = bincode::deserialize(&cfg_b).unwrap();

        assert_eq!(cfg, cfg_d);
    }
}
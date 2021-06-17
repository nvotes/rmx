use std::collections::HashMap;
use std::path::Path;

use crate::bulletinboard::mixnetboard::BBError;

pub trait Board {
    fn list(&self) -> Result<Vec<String>, BBError>;
    // fn get<A: ToByteTree + Deser>(&self, target: String, hash: Hash) -> Result<Option<A>, BBError>;
    // fn put(&mut self, entries: Vec<(&Path, &Path)>, message: String) -> Result<(), BBError>;
    fn get(&self, target: String) -> Result<Option<Vec<u8>>, BBError>;
    fn add(&mut self, entries: Vec<(&Path, Vec<u8>)>, message: String) -> Result<(), BBError>;
    fn post(&self) -> Result<(), BBError>;
    fn get_unsafe(&self, target: &str) -> Result<Option<Vec<u8>>, BBError>;
}

#[derive(Default)]
pub struct MBoard {
    data: HashMap<String, Vec<u8>>,
}

impl Board for MBoard {
    fn list(&self) -> Result<Vec<String>, BBError> {
        Ok(self.data.iter().map(|(a, _)| a.clone()).collect())
    }
    fn get(&self, target: String) -> Result<Option<Vec<u8>>, BBError> {
        Ok(self.data.get(&target).map(|v| v.to_vec()))
        /* let key = target;
        if let Some(bytes) = self.data.get(&key) {
            let _now_ = std::time::Instant::now();

            let artifact = A::deser(bytes)?;
            // info!(">> Deser {}, bytes {}", now_.elapsed().as_millis(), bytes.len());

            let _now_ = std::time::Instant::now();
            let hashed = hashing::hash(&artifact);
            // info!(">> Hash {}", now_.elapsed().as_millis());

            if hashed == hash {
                Ok(Some(artifact))
            } else {
                Err(BBError::Msg("Hash mismatch".to_string()))
            }
        } else {
            Ok(None)
        }*/
    }
    fn add(&mut self, entries: Vec<(&Path, Vec<u8>)>, _message: String) -> Result<(), BBError> {
        for (name, data) in entries {
            let key = name
                .to_str()
                .ok_or_else(|| BBError::Msg("Invalid path string when putting".to_string()))?
                .to_string();
            if self.data.contains_key(&key) {
                panic!(
                    "Attempted to overwrite bulletin board value for key '{}'",
                    key
                );
            }
            self.data.insert(key, data.to_vec());
        }

        Ok(())
    }

    fn post(&self) -> Result<(), BBError> {
        Ok(())
    }
    fn get_unsafe(&self, target: &str) -> Result<Option<Vec<u8>>, BBError> {
        Ok(self.data.get(target).map(|v| v.to_vec()))
    }
    /* fn get_config_type(&self, target: &str) -> Option<bool> {
        let bytes = self.data.get(target)?;
        // let config_rug = bincode::deserialize::<Config<Integer, RugGroup>>(bytes);
        let config_rug = Config::<Integer, RugGroup>::deser(bytes);

        // let config_ristretto = bincode::deserialize::<Config<RistrettoPoint, RistrettoGroup>>(bytes);
        let config_ristretto = Config::<RistrettoPoint, RistrettoGroup>::deser(bytes);
        if config_rug.is_ok() {
            Some(true)
        }
        else if config_ristretto.is_ok() {
            Some(false)
        }
        else {
            None
        }
    }
    fn clear(&mut self) {
        self.data.clear();
    }*/
}

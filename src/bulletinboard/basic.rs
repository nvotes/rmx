use serde::de::DeserializeOwned;
use std::path::Path;
use std::collections::HashMap;

use log::info;

use crate::data::bytes::*;
use crate::crypto::hashing;
use crate::crypto::hashing::{HashBytes, Hash};
use crate::util;

pub trait BasicBoard {
    fn list(&self) -> Vec<String>;
    fn get<A: HashBytes + DeserializeOwned + Deser>(&self, target: String, hash: Hash) -> Result<A, String>;
    fn put(&mut self, entries: Vec<(&str, &Path)>);
    fn get_unsafe(&self, target: &str) -> Option<&Vec<u8>>;
}

pub struct MBasic {
    data: HashMap<String, Vec<u8>>
}

impl MBasic {
    pub fn new() -> MBasic {
        MBasic {
            data: HashMap::new()
        }
    }
}

impl BasicBoard for MBasic {
    fn list(&self) -> Vec<String> {
        self.data.iter().map(|(a, _)| a.clone()).collect()
    }
    fn get<A: HashBytes + DeserializeOwned + Deser>(&self, target: String, hash: Hash) -> Result<A, String> {
        let key = target;
        let bytes = self.data.get(&key).ok_or("Not found")?;

        let now_ = std::time::Instant::now();
        // let artifact = bincode::deserialize::<A>(bytes)
        //    .map_err(|e| std::format!("serde error {}", e))?;
        let artifact = A::deser(bytes)
            .map_err(|e| std::format!("serde error {}", e))?;
        info!(">> Deser {}, bytes {}", now_.elapsed().as_millis(), bytes.len());
        
        let now_ = std::time::Instant::now();
        let hashed = hashing::hash(&artifact);
        info!(">> Hash {}", now_.elapsed().as_millis());

        
        if hashed == hash {
            Ok(artifact)
        }
        else {
            Err("Hash mismatch".to_string())
        }
    }
    fn put(&mut self, entries: Vec<(&str, &Path)>) {
        for (name, data) in entries {
            let bytes = util::read_file_bytes(data).unwrap();
            if self.data.contains_key(name) {
                panic!("Attempted to overwrite bulletin board value for key '{}'", name);
            }
            self.data.insert(name.to_string(), bytes);
        }
    }
    fn get_unsafe(&self, target: &str) -> Option<&Vec<u8>> {
        self.data.get(target)
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
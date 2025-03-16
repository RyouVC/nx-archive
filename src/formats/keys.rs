use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, KeyInit};
// use cipher::{BlockDecrypt, KeyInit};
// use cipher::generic_array::GenericArray;
use hex::decode as hex_decode;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid key format: {0}")]
    InvalidFormat(String),

    #[error("Failed to decode hex value: {0}")]
    HexDecodeError(#[from] hex::FromHexError),

    #[error("Key not found: {0}")]
    KeyNotFound(String),
}

/// Stores title keys for decryption
#[derive(Default, Debug)]
pub struct TitleKeys {
    keys: HashMap<String, Vec<u8>>,
}

impl TitleKeys {
    /// Create a new empty TitleKeys instance
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add a title key to the database
    pub fn add_title_key(&mut self, rights_id: &str, key: Vec<u8>) {
        self.keys.insert(rights_id.to_uppercase(), key);
    }

    /// Get a title key by rights ID
    pub fn get_title_key(&self, rights_id: &str) -> Option<&Vec<u8>> {
        self.keys.get(&rights_id.to_uppercase())
    }

    /// Decrypt a title key using the title KEK
    pub fn decrypt_title_key(
        &self,
        rights_id: &str,
        title_kek: &[u8],
    ) -> Result<[u8; 16], KeyError> {
        let enc_key = self
            .get_title_key(rights_id)
            .ok_or_else(|| KeyError::KeyNotFound(rights_id.to_string()))?;

        let mut key_bytes = [0u8; 16];
        key_bytes.copy_from_slice(&enc_key[0..16]);

        let mut block = GenericArray::from(key_bytes);
        let key = GenericArray::from_slice(title_kek);

        Aes128::new(key).decrypt_block(&mut block);

        Ok(*block.as_ref())
    }

    /// Load title keys from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let file = File::open(path)?;
        let reader = io::BufReader::new(file);

        let mut keys = TitleKeys::new();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            // Parse key-value format "rights_id = key"
            if let Some(pos) = line.find('=') {
                let rights_id = line[..pos].trim();
                let key_hex = line[pos + 1..].trim();

                // Check if this is a valid format for a title key
                if rights_id.len() == 32 {
                    match hex_decode(key_hex) {
                        Ok(key) => {
                            if key.len() == 16 {
                                keys.add_title_key(rights_id, key);
                                info!("Loaded title key for rights ID: {}", rights_id);
                            } else {
                                warn!(
                                    "Invalid key length for rights ID {}: expected 16 bytes",
                                    rights_id
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to decode hex key for rights ID {}: {}",
                                rights_id, e
                            );
                        }
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Get the number of keys in the database
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if the database is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

use aes::Aes128;
use cipher::{generic_array, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use generic_array::GenericArray;
use hex::FromHex;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Result, Seek};
use std::path::Path;
use xts_mode::Xts128;

/// Builds a tweak for Nintendo XTS encryption
/// This is a non-standard tweak that has reversed endianness compared to normal XTS
/// Builds a tweak for Nintendo XTS encryption
/// This is a non-standard tweak that has reversed endianness compared to normal XTS
pub fn get_nintendo_tweak(sector_index: u128) -> [u8; 16] {
    sector_index.to_be_bytes()
}

#[derive(Clone, Default)]
pub struct Keyset {
    pub header_key: [u8; 0x20],
    pub key_area_keys_application: Vec<[u8; 0x10]>,
    pub key_area_keys_ocean: Vec<[u8; 0x10]>,
    pub key_area_keys_system: Vec<[u8; 0x10]>,
    pub title_key_encryption_keys: Vec<[u8; 0x10]>,
}

impl fmt::Debug for Keyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct HexBytes<'a>(&'a [u8]);

        impl fmt::Debug for HexBytes<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:.X?}", self.0)
            }
        }

        // Helper to wrap arrays in vectors in our HexBytes formatter
        fn hex_vec<const N: usize>(v: &[[u8; N]]) -> Vec<HexBytes> {
            v.iter().map(|arr| HexBytes(arr)).collect()
        }

        f.debug_struct("Keyset")
            .field("header_key", &HexBytes(&self.header_key))
            .field(
                "key_area_keys_application",
                &hex_vec(&self.key_area_keys_application),
            )
            .field("key_area_keys_ocean", &hex_vec(&self.key_area_keys_ocean))
            .field("key_area_keys_system", &hex_vec(&self.key_area_keys_system))
            .field(
                "title_key_encryption_keys",
                &hex_vec(&self.title_key_encryption_keys),
            )
            .finish()
    }
}

impl Keyset {
    fn get_key_name_idx(base_name: &str, name: &str) -> Option<usize> {
        if name.starts_with(base_name) && (name.len() == base_name.len() + 2) {
            let idx_str = &name[name.len() - 2..];
            u8::from_str_radix(idx_str, 16).ok().map(|s| s as usize)
        } else {
            None
        }
    }

    /// Create a new keyset from a file path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        Self::from_reader(file)
    }

    /// Creates an XTS128 cipher for NCA header encryption/decryption
    ///
    /// The header key is split into two 128-bit keys for XTS, with the first half used for the data unit key and the second half used for the tweak key.
    ///
    pub fn header_crypt(&self) -> Xts128<Aes128> {
        let cipher_1 = Aes128::new(GenericArray::from_slice(&self.header_key[..0x10]));
        let cipher_2 = Aes128::new(GenericArray::from_slice(&self.header_key[0x10..]));
        Xts128::new(cipher_1, cipher_2)
        // Xts128::new(&self.header_key)
    }

    pub fn from_reader(reader: impl Read + Seek) -> Result<Self> {
        let lines = BufReader::new(reader).lines();

        let mut keyset = Keyset::default();

        for line in lines {
            let line_str = line?;
            let items: Vec<_> = line_str.split('=').collect();
            if items.len() != 2 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid keyset key-value",
                ));
            }

            let key = items[0].trim().to_string();
            let value = items[1].trim().to_string();

            let key_data = Vec::from_hex(&value)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid hex key"))?;

            match key.as_str() {
                "header_key" => {
                    keyset.header_key = key_data
                        .try_into()
                        .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid key length"))?;
                }
                _ => {
                    if let Some(idx) = Self::get_key_name_idx("key_area_key_application_", &key) {
                        if idx >= keyset.key_area_keys_application.len() {
                            keyset.key_area_keys_application.resize(idx + 1, [0; 0x10]);
                        }
                        keyset.key_area_keys_application[idx] =
                            key_data.try_into().map_err(|_| {
                                Error::new(ErrorKind::InvalidInput, "Invalid key length")
                            })?;
                    } else if let Some(idx) = Self::get_key_name_idx("key_area_key_ocean_", &key) {
                        if idx >= keyset.key_area_keys_ocean.len() {
                            keyset.key_area_keys_ocean.resize(idx + 1, [0; 0x10]);
                        }
                        keyset.key_area_keys_ocean[idx] = key_data.try_into().map_err(|_| {
                            Error::new(ErrorKind::InvalidInput, "Invalid key length")
                        })?;
                    } else if let Some(idx) = Self::get_key_name_idx("key_area_key_system_", &key) {
                        if idx >= keyset.key_area_keys_system.len() {
                            keyset.key_area_keys_system.resize(idx + 1, [0; 0x10]);
                        }
                        keyset.key_area_keys_system[idx] = key_data.try_into().map_err(|_| {
                            Error::new(ErrorKind::InvalidInput, "Invalid key length")
                        })?;
                    } else if let Some(idx) = Self::get_key_name_idx("titlekek_", &key) {
                        if idx >= keyset.title_key_encryption_keys.len() {
                            keyset.title_key_encryption_keys.resize(idx + 1, [0; 0x10]);
                        }
                        keyset.title_key_encryption_keys[idx] =
                            key_data.try_into().map_err(|_| {
                                Error::new(ErrorKind::InvalidInput, "Invalid key length")
                            })?;
                    }
                }
            }
        }

        Ok(keyset)
    }

    /// Get an application key area key by index
    pub fn get_key_area_key_application(&self, idx: usize) -> Option<&[u8; 0x10]> {
        self.key_area_keys_application.get(idx)
    }

    /// Get an ocean key area key by index
    pub fn get_key_area_key_ocean(&self, idx: usize) -> Option<&[u8; 0x10]> {
        self.key_area_keys_ocean.get(idx)
    }

    /// Get a system key area key by index
    pub fn get_key_area_key_system(&self, idx: usize) -> Option<&[u8; 0x10]> {
        self.key_area_keys_system.get(idx)
    }

    /// Get the title KEK for the specified key generation
    pub fn get_title_kek(&self, key_generation: usize) -> Option<&[u8]> {
        if key_generation < self.title_key_encryption_keys.len() {
            Some(&self.title_key_encryption_keys[key_generation])
        } else {
            None
        }
    }

    /// Check if the keyset has the necessary keys for NCA decryption
    pub fn has_required_nca_keys(&self) -> bool {
        !self.header_key.iter().all(|&b| b == 0)
            && !self.key_area_keys_application.is_empty()
            && !self.title_key_encryption_keys.is_empty()
    }

    /// Get key area key by key type and crypto index
    pub fn get_key_area_key(&self, key_type: u8, crypto_type: u8) -> Option<&[u8; 0x10]> {
        let idx = crypto_type as usize;
        match key_type {
            0 => self.get_key_area_key_application(idx),
            1 => self.get_key_area_key_ocean(idx),
            2 => self.get_key_area_key_system(idx),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;
    #[test]
    #[traced_test]
    fn test_load_keyset() {
        let keyset = Keyset::from_file("prod.keys").unwrap();

        tracing::info!("{:#?}", keyset);
    }
}

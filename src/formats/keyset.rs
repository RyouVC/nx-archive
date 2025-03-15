use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Result, Seek};
use hex::FromHex;
#[derive(Clone, Debug)]
pub struct Keyset {
    pub header_key: [u8; 0x20],
    pub key_area_keys_application: Vec<[u8; 0x10]>,
    pub key_area_keys_ocean: Vec<[u8; 0x10]>,
    pub key_area_keys_system: Vec<[u8; 0x10]>,
    pub title_key_encryption_keys: Vec<[u8; 0x10]>
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

    pub fn from_reader(reader: impl Read + Seek) -> Result<Self> {
        let lines = BufReader::new(reader).lines();

        let mut keyset = Keyset {
            header_key: [0; 0x20],
            key_area_keys_application: Vec::new(),
            key_area_keys_ocean: Vec::new(),
            key_area_keys_system: Vec::new(),
            title_key_encryption_keys: Vec::new()
        };

        for line in lines {
            let line_str = line?;
            let items: Vec<_> = line_str.split('=').collect();
            if items.len() != 2 {
                return Err(Error::new(ErrorKind::InvalidInput, "Invalid keyset key-value"));
            }

            let key = items[0].trim().to_string();
            let value = items[1].trim().to_string();

            let key_data = Vec::from_hex(&value).map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid hex key"))?;

            match key.as_str() {
                "header_key" => {
                    keyset.header_key = key_data.try_into().map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid key length"))?;
                },
                _ => {
                    if let Some(idx) = Self::get_key_name_idx("key_area_key_application_", &key) {
                        if idx >= keyset.key_area_keys_application.len() {
                            keyset.key_area_keys_application.resize(idx + 1, [0; 0x10]);
                        }
                        keyset.key_area_keys_application[idx] = key_data.try_into().map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid key length"))?;
                    } else if let Some(idx) = Self::get_key_name_idx("key_area_key_ocean_", &key) {
                        if idx >= keyset.key_area_keys_ocean.len() {
                            keyset.key_area_keys_ocean.resize(idx + 1, [0; 0x10]);
                        }
                        keyset.key_area_keys_ocean[idx] = key_data.try_into().map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid key length"))?;
                    } else if let Some(idx) = Self::get_key_name_idx("key_area_key_system_", &key) {
                        if idx >= keyset.key_area_keys_system.len() {
                            keyset.key_area_keys_system.resize(idx + 1, [0; 0x10]);
                        }
                        keyset.key_area_keys_system[idx] = key_data.try_into().map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid key length"))?;
                    } else if let Some(idx) = Self::get_key_name_idx("titlekek_", &key) {
                        if idx >= keyset.title_key_encryption_keys.len() {
                            keyset.title_key_encryption_keys.resize(idx + 1, [0; 0x10]);
                        }
                        keyset.title_key_encryption_keys[idx] = key_data.try_into().map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid key length"))?;
                    }
                }
            }
        }

        Ok(keyset)
    }
}
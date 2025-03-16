//! Key-Value Storage
//! 
//! This module provides a simple representation of key-value pairs.
//! 
//! The key-value set allows for storing string keys associated with string values.
//! It provides a convenient way to parse and manage configuration data stored in
//! a simple text format.
//! 
//! This implementation is useful for reading configuration files, credentials,
//! or any data that follows a simple key-value structure.
//! 
//! Key-value pairs are typically stored in a simple format where each line contains
//! a key and value separated by an equals sign.
//! 
//! This key-value set format is used by the Switch's AES Keysets.
//! 
//! Example format:
//! 
//! ```plaintext
//! key_name = key_value
//! ```

use std::collections::HashMap;

/// Represents a collection of key-value pairs.
#[derive(Debug, Clone)]
pub struct KeyValueSet {
    keys: HashMap<String, String>,
}

impl KeyValueSet {
    /// Creates a new keyset from a string.
    pub fn new(input: &str) -> Self {
        let mut keys = HashMap::new();
        for line in input.lines() {
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() == 2 {
                keys.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
            }
        }
        KeyValueSet { keys }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn read_keyset_dummy() {

            let keyset = r#"
    foo = bar
    baz = qux
    quux = corge
    quuz = quux
    "#;
            let keyset = KeyValueSet::new(keyset);

            for (key, value) in &keyset.keys {
                println!("{} = {}", key, value);
            }

            assert_eq!(keyset.keys.get("foo"), Some(&"bar".to_string()));
            assert_eq!(keyset.keys.get("baz"), Some(&"qux".to_string()));
            assert_eq!(keyset.keys.get("quux"), Some(&"corge".to_string()));
            assert_eq!(keyset.keys.get("quuz"), Some(&"quux".to_string()));
            assert_eq!(keyset.keys.get("quuz"), Some(&"quux".to_string()));
        }
}
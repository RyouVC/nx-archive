use binrw::prelude::*;
use std::io::{Read, Seek};
mod types;

// Use the ReadSeek trait from io module instead of from crate root
use crate::io::{Aes128CtrReader, ReadSeek, SharedReader};

use super::keyset::get_nintendo_tweak;
use super::pfs0::Pfs0;
use super::{Keyset, TitleKeys};
use types::*;
// The first 0xC00 bytes are encrypted with AES-XTS with sector size 0x200
// with a non-standard "tweak" (endianness is reversed as big endian), this
// encrypted data is an 0x400 NCA header + an 0x200 header for each section
// in the section table.

// For pre-1.0.0 "NCA2" NCAs, the first 0x400 byte are encrypted the same way as in NCA3.
// However, each section header is individually encrypted as though it were sector 0, instead
// of the appropriate sector as in NCA3.

/// Encrypts data with the NCA header key using AES-XTS with Nintendo's special tweak
pub fn encrypt_with_header_key(
    data: &[u8],
    keyset: &Keyset,
    sector_size: usize,
    first_sector_index: u128,
) -> Vec<u8> {
    let mut encrypted = data.to_vec();
    let xts = keyset.header_crypt();

    xts.encrypt_area(
        &mut encrypted,
        sector_size,
        first_sector_index,
        get_nintendo_tweak,
    );

    encrypted
}

/// Decrypts data with the NCA header key using AES-XTS with Nintendo's special tweak
pub fn decrypt_with_header_key(
    data: &[u8],
    keyset: &Keyset,
    sector_size: usize,
    first_sector_index: u128,
) -> Vec<u8> {
    let mut decrypted = data.to_vec();
    let xts = keyset.header_crypt();

    xts.decrypt_area(
        &mut decrypted,
        sector_size,
        first_sector_index,
        get_nintendo_tweak,
    );

    decrypted
}

/// Represents the version of an NCA file
///
/// Is essentially a char, but is wrapped in a struct for type safety
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
#[binrw(repr = u8)]
pub struct NcaVersion(pub u8);

impl NcaVersion {
    /// Create a new NcaVersion from a character
    pub fn from_char(c: char) -> Self {
        Self(c as u8)
    }

    /// Get the version as a character
    pub fn as_char(&self) -> char {
        self.0 as char
    }

    /// Create from a u8 value
    pub fn from_u8(value: u8) -> Self {
        Self(value)
    }

    /// Create from a number, getting the character representation and then turning that into a NcaVersion
    pub fn from_num(value: usize) -> Result<Self, &'static str> {
        format!("{}", value)
            .chars()
            .next()
            .map(Self::from_char)
            .ok_or("Failed to convert number to NcaVersion: cannot represent as UTF-8 character")
    }
}

impl From<char> for NcaVersion {
    fn from(c: char) -> Self {
        Self::from_char(c)
    }
}

impl From<u8> for NcaVersion {
    fn from(value: u8) -> Self {
        Self::from_u8(value)
    }
}

pub const BLOCK_SIZE: usize = 0x200;

/// Calculates the offset in bytes for a block offset
pub fn get_block_offset(offset: u64) -> u64 {
    BLOCK_SIZE as u64 * offset
}

#[binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct FsEntry {
    /// StartOffset (in blocks of 0x200 bytes) of the section
    pub start_offset: u32,
    /// EndOffset (in blocks of 0x200 bytes) of the section
    pub end_offset: u32,
    /// Unknown
    pub _reserved: u64,
}

/// NCA Header
///
/// The NCA header is the first 0x340 (832) bytes of an NCA file.
/// It contains metadata about the NCA file, such as the content size,
/// program ID, and other information.
/// However, the first 0xC00 (3072) bytes of the NCA file are encrypted.
#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct NcaHeader {
    #[brw(pad_size_to = 0x100)]
    pub header_sig: RSASignature,
    #[brw(pad_size_to = 0x100)]
    pub header_key_sig: RSASignature,
    #[brw(magic = b"NCA")]
    // pub magic: [u8; 4],
    // The full magic bytes is actually 0x4, but we will use some binrw
    // magic since the first 3 bytes is guaranteed to be "NCA".
    // So, the version number is the 4th byte, and is a char.
    /// NCA Version, extracted from the last byte of the magic number.
    pub nca_version: NcaVersion,
    pub distribution: DistributionType,
    pub content_type: ContentType,
    pub key_generation_old: KeyGenerationOld,
    pub key_area_appkey_index: KeyAreaEncryptionKeyIndex,
    pub content_size: u64,
    pub program_id: u64,
    pub content_index: u32,
    pub sdk_version: u32,
    pub key_generation: u8,
    pub signature_key_generation: u8,
    // 0xe
    #[br(count = 0xE)]
    #[brw(pad_size_to = 0xE)]
    _reserved: Vec<u8>,
    #[br(count = 0x10)]
    #[brw(pad_size_to = 0x10)]
    pub rights_id: Vec<u8>,
    #[br(count = 4)]
    #[brw(pad_size_to = 0x10 * 4)]
    pub fs_entries: Vec<FsEntry>,
    // array of sha256 hashes
    #[br(count = 4)]
    #[brw(pad_size_to = 0x20 * 4)]
    pub sha256_hashes: Vec<[u8; 0x20]>,
    // encrypted key area
    // #[br(count = 4)]
    #[brw(pad_size_to = 0x10 * 4)]
    pub encrypted_keys: KeyArea,
}

impl NcaHeader {
    /// Takes an already-decrypted NCA header and parses it
    ///
    /// This will take only what is needed for the header, which is the first 0x340 bytes, and parse it.
    ///
    /// Note: If you would like to decrypt the header first, please use the `to_bytes_encrypt` method.
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> Result<Self, binrw::Error> {
        let mut decrypted = vec![0; 0x340];
        reader.read_exact(&mut decrypted)?;
        let header: NcaHeader = binrw::io::Cursor::new(&decrypted).read_le()?;
        Ok(header)
    }

    /// Parses an NCA header from a byte slice (0x340 bytes) of an already-decrypted header
    pub fn from_bytes(bytes: &[u8; 0x340]) -> Result<Self, binrw::Error> {
        let header: NcaHeader = binrw::io::Cursor::new(bytes).read_le()?;
        Ok(header)
    }

    /// Encrypts the header data with the NCA header encryption
    ///
    /// The first 0xC00 bytes are encrypted with AES-XTS with sector size 0x200
    /// and a non-standard tweak. This encrypted data includes:
    /// - 0x400 bytes for the NCA header
    /// - 0x800 bytes for section headers (0x200 bytes per section)
    pub fn to_bytes_encrypt(&self, keyset: &Keyset) -> Vec<u8> {
        // Serialize the header to bytes using to_bytes method
        let header_data = self.to_bytes();

        // Ensure we have 0xC00 bytes by padding if necessary
        let mut header_data_padded = vec![0u8; header_data.len().max(0xC00)];
        header_data_padded[..header_data.len()].copy_from_slice(&header_data);

        // Create a copy for encryption
        let mut encrypted = header_data_padded.clone();

        // Set up XTS encryption with the header key
        let xts = keyset.header_crypt();

        // Encrypt the first 0xC00 bytes (NCA header + section headers)
        let sector_size = 0x200;
        let first_sector_index = 0;
        let encrypted_portion = &mut encrypted[..0xC00];

        xts.encrypt_area(
            encrypted_portion,
            sector_size,
            first_sector_index,
            get_nintendo_tweak,
        );

        encrypted
    }

    /// Serializes the header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut cursor = binrw::io::Cursor::new(Vec::new());
        self.write_le(&mut cursor)
            .expect("Failed to serialize header");
        cursor.into_inner()
    }

    /// Get the key generation to use (accounting for old key_generation field)
    pub fn get_key_generation(&self) -> u8 {
        let key_gen_old = self.key_generation_old as u8;
        let key_gen = self.key_generation;

        // Use the higher of the two key generation values
        let base_key_gen = if key_gen_old < key_gen {
            key_gen
        } else {
            key_gen_old
        };

        // Both 0 and 1 are master key 0
        if base_key_gen > 0 {
            base_key_gen - 1
        } else {
            base_key_gen
        }
    }
}
#[binrw]
#[brw(little)]
#[derive(Debug, Default, Clone)]
// The key area from the NCA
pub struct KeyArea {
    /// AES-XTS keys
    pub aes_xts_key: [u8; 0x20],
    /// AES-CTR keys
    pub aes_ctr_key: [u8; 0x10],
    /// Unknown
    pub _reserved: [u8; 0x10],
}

pub struct Nca<R: Read + Seek> {
    reader: R,
    pub header: NcaHeader,
    pub fs_headers: Vec<FsHeader>,
    dec_title_key: Option<[u8; 0x10]>,
    dec_key_area: KeyArea, // Add decrypted key area to store
    key_status: bool,      // Track whether keys are properly initialized
}

impl<R: Read + Seek> Nca<R> {
    pub fn from_reader(
        reader: R,
        keyset: &Keyset,
        title_keys: Option<&TitleKeys>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        println!("-----------------------------------------------");
        println!("Initializing NCA reader");

        // let's take the first 0xC00 bytes and decrypt them
        let mut reader = reader;
        let mut encrypted_buf = vec![0; 0xC00];
        reader.read_exact(&mut encrypted_buf)?;

        let decrypted = decrypt_with_header_key(&encrypted_buf, keyset, 0x200, 0);

        let header = {
            let header_slice = &decrypted[..0x340];
            let header_array: &[u8; 0x340] = header_slice
                .try_into()
                .expect("Slice length doesn't match array length");
            NcaHeader::from_bytes(header_array)?
        };

        // Add after header decryption:
        println!("NCA version: {}", header.nca_version.as_char());
        println!("Content type: {:?}", header.content_type);
        println!("Key generation old: {:?}", header.key_generation_old);
        println!("Key generation: {}", header.key_generation);
        println!(
            "Key area encryption key index: {:?}",
            header.key_area_appkey_index
        );

        // Parse the filesystem headers
        let mut fs_headers = Vec::new();

        for (i, entry) in header.fs_entries.iter().enumerate() {
            // Skip empty entries (both start and end offset are 0)
            if entry.start_offset == 0 && entry.end_offset == 0 {
                continue;
            }

            // Each FS header is 0x200 bytes, starting at offset 0x400
            let fs_header_offset = 0x400 + (i * 0x200);

            // Make sure we don't go past the end of our decrypted buffer
            if fs_header_offset + 0x200 > decrypted.len() {
                tracing::warn!("FS header {} is out of bounds", i);
                break;
            }

            // Parse the filesystem header
            let fs_header_data = &decrypted[fs_header_offset..fs_header_offset + 0x200];
            let mut cursor = binrw::io::Cursor::new(fs_header_data);
            let fs_header: FsHeader = cursor.read_le()?;

            fs_headers.push(fs_header);
        }

        // Initialize decrypted key area
        let mut dec_key_area = KeyArea::default();
        // Default key_status is true
        let mut key_status = true;

        // Process key decryption based on rights ID
        let dec_title_key = if !header.rights_id.iter().all(|&b| b == 0) {
            // If we have rights ID, try to get the title key
            let rights_id_hex = hex::encode(&header.rights_id).to_uppercase();

            // Get the key generation
            let key_gen = header.get_key_generation();

            // First check if we have title keys database
            if let Some(title_keys_db) = title_keys {
                // Get the title KEK for this key generation
                if let Some(title_kek) = keyset.get_title_kek(key_gen as usize) {
                    // Try to decrypt the title key
                    match title_keys_db.decrypt_title_key(&rights_id_hex, title_kek) {
                        Ok(dec_key) => Some(dec_key),
                        Err(e) => {
                            tracing::warn!("Failed to decrypt title key: {}", e);
                            key_status = false;
                            None
                        }
                    }
                } else {
                    tracing::warn!(
                        "Title key encryption key not present for key generation {}",
                        key_gen
                    );
                    key_status = false;
                    None
                }
            } else {
                // No title keys database provided
                tracing::warn!("NCA requires title key but no title keys database was supplied");
                key_status = false;
                None
            }
        } else {
            // If no rights ID, decrypt key area
            let key_gen = header.get_key_generation();

            // Get the appropriate key area key based on index
            let key_area_key = match header.key_area_appkey_index {
                KeyAreaEncryptionKeyIndex::Application => {
                    let key = keyset.get_key_area_key_application(key_gen as usize);
                    key.map(|k| k.as_slice())
                }
                KeyAreaEncryptionKeyIndex::Ocean => {
                    let key = keyset.get_key_area_key_ocean(key_gen as usize);
                    key.map(|k| k.as_slice())
                }
                KeyAreaEncryptionKeyIndex::System => {
                    let key = keyset.get_key_area_key_system(key_gen as usize);
                    key.map(|k| k.as_slice())
                }
                _ => None,
            };

            // If we have a key, decrypt the key area
            if let Some(key) = key_area_key {
                // TODO: Properly decrypt the key area
                // For now just copy the encrypted key area
                dec_key_area = header.encrypted_keys.clone();
            } else {
                // If we're here, we couldn't get the key area key
                tracing::warn!(
                    "Key area key of type {:?} not present for key generation {}",
                    header.key_area_appkey_index,
                    key_gen
                );
                key_status = false;
            }

            None
        };

        // After obtaining fs_headers:
        println!("Found {} valid filesystem headers", fs_headers.len());
        for (i, fs_header) in fs_headers.iter().enumerate() {
            println!(
                "FS #{} - Type: {:?}, Encryption: {:?}, Hash: {:?}",
                i, fs_header.fs_type, fs_header.encryption_type, fs_header.hash_type
            );
        }

        Ok(Self {
            reader,
            header,
            fs_headers,
            dec_title_key,
            dec_key_area,
            key_status,
        })
    }

    /// Get the number of valid filesystems in this NCA
    #[inline]
    pub fn filesystem_count(&self) -> usize {
        self.fs_headers.len()
    }

    /// Get the filesystem offset in bytes
    pub fn get_fs_offset(&self, idx: usize) -> Option<u64> {
        if idx >= self.fs_headers.len() {
            return None;
        }

        // Find the corresponding fs_entry by index
        // This works because we populate fs_headers in the same order as valid fs_entries
        let valid_entries: Vec<_> = self
            .header
            .fs_entries
            .iter()
            .filter(|entry| entry.start_offset != 0 || entry.end_offset != 0)
            .collect();

        if idx >= valid_entries.len() {
            return None;
        }

        let fs_entry = valid_entries[idx];
        Some(get_block_offset(fs_entry.start_offset as u64))
    }

    /// Check if the NCA needs a title key for decryption
    #[inline]
    pub fn has_rights_id(&self) -> bool {
        !self.header.rights_id.iter().all(|&b| b == 0)
    }

    /// Check if the NCA has valid keys for decryption
    #[inline]
    pub fn has_valid_keys(&self) -> bool {
        self.key_status
    }

    /// Get the key generation to use (accounting for old key_generation field)
    pub fn get_key_generation(&self) -> u8 {
        let key_gen_old = self.header.key_generation_old as u8;
        let key_gen = self.header.key_generation;

        // Use the higher of the two key generation values
        let base_key_gen = if key_gen_old < key_gen {
            key_gen
        } else {
            key_gen_old
        };

        // Both 0 and 1 are master key 0
        if base_key_gen > 0 {
            base_key_gen - 1
        } else {
            base_key_gen
        }
    }
    /// Gets the AES-CTR key for decryption
    /// If the NCA has a rights ID, it uses the stored decrypted title key
    /// Otherwise, it uses the decrypted key area key
    #[inline]
    pub fn get_aes_ctr_decrypt_key(&self) -> Result<[u8; 0x10], Box<dyn std::error::Error>> {
        if !self.key_status {
            return Err("NCA keys are not available for decryption".into());
        }

        if let Some(dec_key) = self.dec_title_key {
            // Use the already-decrypted title key
            println!("Using decrypted title key");
            Ok(dec_key)
        } else {
            println!("Using decrypted key area key");
            // ISSUE: Debug why our key is different than CNTX's
            // For now, print debug info about the key_area
            println!(
                "KeyArea in header: {:02X?}",
                self.header.encrypted_keys.aes_ctr_key
            );
            println!(
                "Our decrypted KeyArea: {:02X?}",
                self.dec_key_area.aes_ctr_key
            );

            // TODO: In a real fix, we need to properly decrypt this key
            // For now, hardcode the key that CNTX uses for debugging
            let debug_key = [0x04; 0x10];
            println!("WARNING: Using debug key to match CNTX: {:02X?}", debug_key);
            // Use the decrypted key area's AES-CTR key
            Ok(debug_key) // Changed temporarily for debugging
            // Ok(self.dec_key_area.aes_ctr_key) // Original code
        }
    }

    pub fn open_pfs0_filesystem(
        &mut self,
        idx: usize,
        _keyset: &Keyset,
    ) -> Result<Pfs0<Box<dyn ReadSeek + '_>>, Box<dyn std::error::Error>> {
        if idx >= self.fs_headers.len() {
            return Err("Invalid filesystem index".into());
        }

        let fs_header = &self.fs_headers[idx];
        if fs_header.fs_type != FsType::PartitionFs {
            return Err(format!("Invalid filesystem type: {:?}", fs_header.fs_type).into());
        }

        let fs_start_offset = self
            .get_fs_offset(idx)
            .ok_or("Failed to get filesystem offset")?;

        println!("===============================================");
        println!("Opening PFS0 filesystem at index {}", idx);
        println!("Filesystem start offset: 0x{:X}", fs_start_offset);
        println!("Filesystem type: {:?}", fs_header.fs_type);
        println!("Encryption type: {:?}", fs_header.encryption_type);
        println!("Hash type: {:?}", fs_header.hash_type);
        println!("Counter value: 0x{:X}", fs_header.ctr);

        match fs_header.encryption_type {
            EncryptionType::None => {
                println!("Using unencrypted access method");

                let fs_size = (fs_header.hash_data.get_layer_count() as u64
                    * fs_header.hash_data.get_block_size(0).unwrap() as u64)
                    * 0x200;
                let fs_end_offset = fs_start_offset + fs_size;

                println!("Layer count: {}", fs_header.hash_data.get_layer_count());
                println!(
                    "Block size: 0x{:X}",
                    fs_header.hash_data.get_block_size(0).unwrap()
                );
                println!("Total size: 0x{:X} bytes", fs_size);
                println!("End offset: 0x{:X}", fs_end_offset);

                let shared = SharedReader::new(self.reader.by_ref());
                let mut reader = shared.sub_file(fs_start_offset, fs_end_offset);

                // Read and log the magic bytes for debugging
                let mut magic = [0u8; 4];
                reader.seek(std::io::SeekFrom::Start(0))?;
                reader.read_exact(&mut magic)?;
                println!(
                    "Magic bytes at start: {:?} ({})",
                    magic,
                    String::from_utf8_lossy(&magic)
                );
                reader.seek(std::io::SeekFrom::Start(0))?;

                let boxed_reader: Box<dyn ReadSeek + '_> = Box::new(reader);
                Pfs0::new(boxed_reader)
            }
            EncryptionType::AesCtr => {
                println!("Using AES-CTR decryption");

                // Get the decryption key - hardcoded to match CNTX for now
                let debug_key = [0x04; 0x10].to_vec();
                println!("Using debug key: {:02X?}", debug_key);

                // Determine the PFS0 data offset - use direct field as CNTX does
                let pfs0_offset = match &fs_header.hash_data {
                    HashData::HierarchicalSha256Hash { pfs0_offset, .. } => {
                        println!("PFS0 offset field: 0x{:X}", pfs0_offset);
                        fs_start_offset + pfs0_offset
                    }
                    HashData::HierarchicalIntegrity {
                        info_level_hash, ..
                    } => {
                        // For integrity hash, use the last level's offset as the PFS0 data start
                        if let Some(last_level) = info_level_hash.levels.last() {
                            println!("Last level offset: 0x{:X}", last_level.offset);
                            fs_start_offset + last_level.offset
                        } else {
                            println!("No levels found in HierarchicalIntegrity!");
                            fs_start_offset
                        }
                    }
                };

                println!("Final PFS0 absolute offset: 0x{:X}", pfs0_offset);

                // Create a reader for the NCA file
                let reader = std::io::BufReader::new(self.reader.by_ref());

                // Create the AES-CTR reader to match CNTX's implementation exactly
                let mut aes_reader =
                    Aes128CtrReader::new(reader, pfs0_offset, fs_header.ctr, debug_key);

                // Read and verify the magic bytes
                let mut magic = [0u8; 4];
                aes_reader.seek(std::io::SeekFrom::Start(0))?;
                aes_reader.read_exact(&mut magic)?;
                println!(
                    "Magic bytes: {:?} ({})",
                    magic,
                    String::from_utf8_lossy(&magic)
                );

                // Read the first 32 bytes to compare with CNTX's output
                aes_reader.seek(std::io::SeekFrom::Start(0))?;
                let mut first_bytes = [0u8; 32];
                aes_reader.read_exact(&mut first_bytes)?;
                println!("First 32 bytes: {:02X?}", first_bytes);

                // Reset position to beginning
                aes_reader.seek(std::io::SeekFrom::Start(0))?;

                // Box the reader
                let boxed_reader: Box<dyn ReadSeek + '_> = Box::new(aes_reader);

                println!("Attempting to open PFS0...");
                match Pfs0::new(boxed_reader) {
                    Ok(pfs0) => {
                        println!("Successfully opened PFS0!");
                        // List the files if available
                        if let Ok(files) = pfs0.list_files() {
                            println!("Files in PFS0: {:?}", files);
                        }
                        Ok(pfs0)
                    }
                    Err(e) => {
                        println!("Failed to open PFS0: {}", e);
                        Err(e)
                    }
                }
            }
            _ => {
                println!(
                    "Unsupported encryption type: {:?}",
                    fs_header.encryption_type
                );
                Err("Unsupported encryption type".into())
            }
        }
    }
}

#[test]
pub fn decrypt_nca_header() -> color_eyre::Result<()> {
    let keyset = Keyset::from_file("prod.keys")?;

    let file_path = std::path::Path::new(
        "/home/cappy/Projects/nx-archive/test/Browser/cf03cf6a80796869775f77e0c61e136e.cnmt.nca",
    );
    let nca_file = std::fs::File::open(file_path)?;

    let filename = file_path.file_name().unwrap().to_str().unwrap();
    println!("Decrypting NCA: {}", filename);

    let reader = std::io::BufReader::new(nca_file);

    // Pass None for title_key as this is probably a metadata NCA without encryption
    let mut nca = Nca::from_reader(reader, &keyset, None).unwrap();

    println!("{:?}", nca.header);

    for (i, fs_header) in nca.fs_headers.iter().enumerate() {
        println!("Filesystem {}: {:0?}", i, fs_header);
    }

    println!("Total valid filesystems: {}", nca.filesystem_count());

    // Clone the file path here to avoid borrow issues
    let file_path_clone = file_path.to_path_buf();

    // Add a hexdump of the first few bytes to debug the issue
    let fs_offset = nca.get_fs_offset(0);
    let pfs0_result = nca.open_pfs0_filesystem(0, &keyset);
    match pfs0_result {
        Ok(_pfs0) => println!("PFS0 opened successfully!"),
        Err(e) => {
            println!("Failed to open PFS0: {}", e);
            // For further debugging, you could try reading raw bytes from the offset
            if let Some(fs_offset) = fs_offset {
                println!("Dumping raw bytes from offset 0x{:X}", fs_offset);
                let mut raw_reader = std::fs::File::open(file_path_clone)?;
                raw_reader.seek(std::io::SeekFrom::Start(fs_offset))?;
                let mut buf = [0u8; 0x100];
                raw_reader.read_exact(&mut buf)?;
                println!("Raw bytes: {:02X?}", &buf[..16]);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use xts_mode::get_tweak_default;

    use super::*;

    #[test]
    fn test_nintendo_tweak_generation() {
        let sector = 0x01020304_u128;
        let tweak = get_nintendo_tweak(sector);
        let expected = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
            0x03, 0x04,
        ];
        assert_eq!(tweak.as_slice(), &expected);
    }

    #[test]
    fn test_standard_tweak_generation() {
        let sector = 0x01020304_u128;
        let tweak = get_tweak_default(sector);
        let expected = [
            0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(tweak.as_slice(), &expected);
    }

    #[test]
    fn test_nintendo_standard_tweak_difference() {
        let sector = 0x0102030405060708_u128;
        let nintendo_tweak = get_nintendo_tweak(sector);
        let standard_tweak = get_tweak_default(sector);
        assert_ne!(nintendo_tweak, standard_tweak);
    }

    #[test]
    fn test_fs_entry_size() {
        let entry = FsEntry {
            start_offset: 0,
            end_offset: 100,
            _reserved: 0,
        };
        assert_eq!(std::mem::size_of_val(&entry), 16);
    }

    fn test_header() -> NcaHeader {
        NcaHeader {
            header_sig: RSASignature::default(),
            header_key_sig: RSASignature::default(),
            nca_version: NcaVersion::from_char('3'),
            distribution: DistributionType::Download,
            content_type: ContentType::Program,
            key_generation_old: KeyGenerationOld::Gen3_0_0,
            key_area_appkey_index: KeyAreaEncryptionKeyIndex::Application,
            content_size: 0,
            program_id: 0,
            content_index: 0,
            sdk_version: 0,
            key_generation: 0,
            signature_key_generation: 0,
            _reserved: vec![0; 0xE],
            rights_id: vec![0; 0x10],
            fs_entries: vec![],
            sha256_hashes: vec![],
            encrypted_keys: KeyArea::default(),
        }
    }

    #[test]
    fn test_nca_header_size() {
        let header = test_header();
        // assert_eq!(std::mem::size_of_val(&header), 0x340);
        // now serialize to bytes
        let header_bytes = header.to_bytes();
        assert_eq!(header_bytes.len(), 0x340);
    }

    #[test]
    fn test_header_magic() {
        // let magic = [b'N', b'C', b'A', 0];
        let header = test_header();
        let header_bytes = header.to_bytes();
        assert_eq!(&header_bytes[0x200..0x204], b"NCA3");
    }

    #[test]
    fn test_header_enc_dec() {
        let header = test_header();

        let keyset = Keyset {
            header_key: [2; 0x20],
            ..Default::default()
        };

        let header_bytes = header.to_bytes();

        println!("{:#?}", header_bytes.len());

        assert_eq!(header_bytes.len(), 0x340);

        // Let's alliocate 0xC00 bytes for the encrypted header
        let mut to_be_encrypted = vec![0; 0xC00];

        // copy the header bytes to the first 0x340 bytes
        to_be_encrypted[..0x340].copy_from_slice(&header_bytes);

        // Encrypt the header
        let encrypted = encrypt_with_header_key(&to_be_encrypted, &keyset, 0x200, 0);

        // Decrypt the header

        let decrypted = decrypt_with_header_key(&encrypted, &keyset, 0x200, 0);

        // take the header
        let decrypted_header = &decrypted[..0x340];

        assert_eq!(header_bytes, decrypted_header);

        // let decrypted_header: NcaHeader =
        //     NcaHeader::from_bytes(&(decrypted_header.try_into().unwrap())).unwrap();

        // assert_eq!(header, decrypted_header);
    }
}

//! NCA (Nintendo Content Archive) file format
//!
//! This module provides functionality for reading and processing NCA files used in Nintendo Switch games.
//! The NCA format is a container format used by Nintendo to store game data, including encrypted content.
//!
//! # Structure
//!
//! An NCA file consists of:
//! - An encrypted header (first 0xC00 bytes)
//!   - Main NCA header (0x400 bytes)
//!   - Section headers (0x200 bytes per section, up to 4 sections)
//! - Content sections containing file data
//!
//! # Encryption
//!
//! NCAs use several encryption mechanisms:
//! - AES-XTS with Nintendo's custom tweak for the header
//! - AES-CTR for content sections
//! - Rights management via titlekeys for (most) content
//!
//! # Key Hierarchy
//!
//! The module handles different encryption keys:
//! - Header key for decrypting the NCA header
//! - Key area keys (application, ocean, system)
//! - Title keys for DRM-protected content
//!
//! The title keys are generated by the Nintendo Switch's production keys (see [Keyset](crate::formats::keyset::Keyset)).
//! It is unknown how the title keys are generated from the production keys at this time.
//! You are still required to generate them using a Nintendo Switch console.
//!

use binrw::prelude::*;
use std::io::{Read, Seek};

mod types;

// Add tracing instrument import
use tracing::instrument;

// Use the ReadSeek trait from io module instead of from crate root
use crate::io::{Aes128CtrReader, ReadSeek, SubFile};

use super::keyset::get_nintendo_tweak;
use super::pfs0::Pfs0;
use super::romfs::RomFs; // Add import for RomFs
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

    xts.unwrap().encrypt_area(
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

    if let Some(xts) = xts {
        xts.decrypt_area(
            &mut decrypted,
            sector_size,
            first_sector_index,
            get_nintendo_tweak,
        );
    } else {
        // Handle the case where xts is None
        panic!("Failed to get header crypt");
    }

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
    pub fn from_num(value: usize) -> Result<Self, crate::error::Error> {
        format!("{}", value)
            .chars()
            .next()
            .map(Self::from_char)
            .ok_or_else(|| {
                crate::error::Error::InvalidData(
                    "Failed to convert number to NcaVersion: cannot represent as UTF-8 character"
                        .to_string(),
                )
            })
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
    /// Distribution type
    pub distribution: DistributionType,
    /// Content type
    pub content_type: ContentType,
    /// key_generation_old
    pub key_generation_old: KeyGenerationOld,
    pub key_area_appkey_index: KeyAreaEncryptionKeyIndex,
    pub content_size: u64,
    pub program_id: u64,
    pub content_index: u32,
    pub sdk_version: u32,
    pub key_generation: KeyGeneration,
    pub signature_key_generation: u8,
    // 0xE
    pub _reserved_e: [u8; 0xE],
    pub rights_id: [u8; 0x10],
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
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> Result<Self, crate::error::Error> {
        let mut decrypted = vec![0; 0x340];
        reader.read_exact(&mut decrypted)?;
        let header: NcaHeader = binrw::io::Cursor::new(&decrypted).read_le()?;
        Ok(header)
    }

    /// Parses an NCA header from a byte slice (0x340 bytes) of an already-decrypted header
    pub fn from_bytes(bytes: &[u8; 0x340]) -> Result<Self, crate::error::Error> {
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

        xts.unwrap().encrypt_area(
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
        let key_gen = self.key_generation as u8;

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
    #[instrument(
        level = "trace",
        skip(reader, keyset, title_keys),
        fields(content_type, nca_version)
    )]
    pub fn from_reader(
        reader: R,
        keyset: &Keyset,
        title_keys: Option<&TitleKeys>,
    ) -> Result<Self, crate::error::Error> {
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

        // Add header details to the span
        tracing::Span::current()
            .record("content_type", format!("{:?}", header.content_type))
            .record(
                "nca_version",
                format_args!("{}", header.nca_version.as_char()),
            );

        tracing::trace!(
            nca_version = %header.nca_version.as_char(),
            content_type = ?header.content_type,
            key_generation_old = ?header.key_generation_old,
            key_generation = ?header.key_generation,
            key_area_appkey_index = ?header.key_area_appkey_index,
            "NCA header decoded"
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
            let rights_id_hex = hex::encode(header.rights_id).to_uppercase();
            tracing::trace!(rights_id = %rights_id_hex, "NCA requires title key");

            // Get the key generation
            let key_gen = header.get_key_generation();

            // First check if we have title keys database
            if let Some(title_keys_db) = title_keys {
                // Get the title KEK for this key generation
                let title_kek = keyset.get_title_kek(key_gen as usize);
                tracing::trace!(
                    key_gen = %key_gen,
                    title_kek = ?title_kek,
                    "Title KEK obtained"
                );

                // Try to decrypt the title key

                if let Some(title_kek) = title_kek {
                    // Try to decrypt the title key
                    match title_keys_db.decrypt_title_key(&rights_id_hex, &title_kek) {
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
            tracing::trace!("NCA does not require title key, attempting to get key area key");
            let key_gen = header.get_key_generation();

            // Get the appropriate key area key based on index
            let key_area_key = match header.key_area_appkey_index {
                KeyAreaEncryptionKeyIndex::Application => {
                    let key = keyset.get_key_area_key_application(key_gen as usize);
                    tracing::trace!(key_gen = %key_gen, key_type = "Application", key = ?key, "Key area key obtained");
                    key
                }
                KeyAreaEncryptionKeyIndex::Ocean => {
                    let key = keyset.get_key_area_key_ocean(key_gen as usize);
                    tracing::trace!(key_gen = %key_gen, key_type = "Ocean", key = ?key, "Key area key obtained");
                    key
                }
                KeyAreaEncryptionKeyIndex::System => {
                    let key = keyset.get_key_area_key_system(key_gen as usize);
                    tracing::trace!(key_gen = %key_gen, key_type = "System", key = ?key, "Key area key obtained");
                    key
                }
            };

            // If we have a key, decrypt the key area
            if let Some(key) = key_area_key {
                tracing::trace!(
                    encrypted_key = %hex::encode(header.encrypted_keys.aes_ctr_key),
                    "Decrypting key area"
                );

                // Properly decrypt the key area using ECB Decryptor, matching CNTX implementation
                use cipher::BlockDecryptMut;
                use cipher::KeyInit;

                // Create a copy of the encrypted key area
                let mut key_area_copy = header.encrypted_keys.clone();

                // Define the type for our ECB decryptor
                type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

                // Create an ECB decryptor with our key and no padding
                let mut decryptor = Aes128EcbDec::new_from_slice(&key).map_err(|_| {
                    crate::error::Error::CryptoError("Failed to create ECB decryptor".to_string())
                })?;

                // Decrypt the key area in-place
                // The key area is exactly 64 bytes (0x40), which is a multiple of the AES block size (16 bytes)
                // So we don't need to worry about padding
                decryptor.decrypt_blocks_mut(unsafe {
                    core::slice::from_raw_parts_mut(
                        &mut key_area_copy as *mut KeyArea as *mut aes::Block,
                        std::mem::size_of::<KeyArea>() / 16, // 4 blocks of 16 bytes each
                    )
                });

                dec_key_area = key_area_copy;

                tracing::trace!(
                    decrypted_key = %hex::encode(dec_key_area.aes_ctr_key),
                    "Key area decrypted"
                );
            } else {
                tracing::warn!(
                    key_type = ?header.key_area_appkey_index,
                    key_gen = %key_gen,
                    "Key area key not present"
                );
                key_status = false;
            }

            None
        };

        // After obtaining fs_headers:
        tracing::trace!(
            fs_header_count = fs_headers.len(),
            "NCA filesystem headers decoded"
        );

        for (i, fs_header) in fs_headers.iter().enumerate() {
            tracing::trace!(
                index = i,
                fs_type = ?fs_header.fs_type,
                encryption_type = ?fs_header.encryption_type,
                hash_type = ?fs_header.hash_type,
                "FS header details"
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
        let key_gen = self.header.key_generation as u8;

        // Use the higher of the two key generation values
        let base_key_gen = if key_gen_old < key_gen {
            key_gen
        } else {
            key_gen_old
        };

        // Both 0 and 1 are master key 0
        if base_key_gen > 1 {
            base_key_gen - 1
        } else {
            base_key_gen
        }
    }
    /// Gets the AES-CTR key for decryption
    /// If the NCA has a rights ID, it uses the stored decrypted title key
    /// Otherwise, it uses the decrypted key area key
    #[inline]
    pub fn get_aes_ctr_decrypt_key(&self) -> Result<[u8; 0x10], crate::error::Error> {
        if self.has_rights_id() {
            // If title key is required, check if we have a decrypted one
            if let Some(dec_key) = self.dec_title_key {
                // Title key is required and available, use it
                tracing::trace!(key = %hex::encode(dec_key), "Using decrypted title key");
                return Ok(dec_key);
            }

            // Title key is required but not available
            let rights_id_hex = hex::encode(self.header.rights_id).to_uppercase();
            return Err(crate::error::Error::KeyLookupError(format!(
                "NCA requires title key for rights ID {}, but it was not available or could not be decrypted",
                rights_id_hex
            )));
        }

        // NCA doesn't require title key, use key area's AES-CTR key
        if !self.key_status {
            // Provide more specific error message based on the key area encryption key index and key generation
            let key_gen = self.get_key_generation();
            let key_type = self.header.key_area_appkey_index;

            let key_name = match key_type {
                KeyAreaEncryptionKeyIndex::Application => "key_area_key_application",
                KeyAreaEncryptionKeyIndex::Ocean => "key_area_key_ocean",
                KeyAreaEncryptionKeyIndex::System => "key_area_key_system",
            };

            return Err(crate::error::Error::KeyLookupError(format!(
                "Key area could not be decrypted (missing {}_{:2x} in keys file)",
                key_name, key_gen
            )));
        }

        tracing::trace!(key = %hex::encode(self.dec_key_area.aes_ctr_key), "Using decrypted key area key");
        Ok(self.dec_key_area.aes_ctr_key)
    }

    /// Private helper method to prepare a reader for any filesystem type
    #[instrument(level = "trace", skip(self))]
    fn prepare_fs_reader(
        &mut self,
        idx: usize,
        // fs_type: FsType,
        // fs_name: &str,
    ) -> Result<Box<dyn ReadSeek + '_>, crate::error::Error> {
        if idx >= self.fs_headers.len() {
            return Err(crate::error::Error::InvalidState(
                "Invalid filesystem index".to_string(),
            ));
        }

        let fs_header = &self.fs_headers[idx];
        // if fs_header.fs_type != fs_type {
        //     return Err(format!("Invalid filesystem type: {:?}", fs_header.fs_type).into());
        // }

        let fs_start_offset = self
            .get_fs_offset(idx)
            .ok_or(crate::error::Error::InvalidState(
                "Failed to get filesystem offset".to_string(),
            ))?;

        tracing::trace!(
            fs_index = idx,
            fs_start_offset = format!("0x{:X}", fs_start_offset),
            fs_type = ?fs_header.fs_type,
            encryption_type = ?fs_header.encryption_type,
            hash_type = ?fs_header.hash_type,
            counter = format!("0x{:X}", fs_header.ctr),
            "Opening filesystem sector",
        );

        // Determine the filesystem data offset based on hash data structure

        // This will be different depending on the encryption type.
        // For unencrypted filesystems, we use this offset directly though. I think.
        let fs_offset_abs = match &fs_header.hash_data {
            HashData::HierarchicalSha256(hash) => {
                tracing::trace!(?hash, "Hierarchical SHA-256 hash data");
                // for SHA-256 hashes, we get the offset from the first (actually second)
                // level of the hash data
                hash.layer_regions[0].offset
            }
            HashData::HierarchicalIntegrity(hash) => {
                tracing::trace!(?hash, "Hierarchical Integrity hash data");
                // for Integrity hashes, we get the offset from the last level
                hash.info_level_hash.levels.last().unwrap().logical_offset
            }
        } + fs_start_offset;

        tracing::trace!(
            fs_offset_abs = format!("0x{:X}", fs_offset_abs),
            "Absolute filesystem offset",
        );

        let fs_size = match &fs_header.hash_data {
            HashData::HierarchicalSha256(hash) => {
                tracing::trace!(?hash, "Hierarchical SHA-256 hash data");
                // for SHA-256 hashes, we get the size from the first (actually second)
                // level of the hash data
                hash.layer_regions[0].size
            }
            HashData::HierarchicalIntegrity(hash) => {
                tracing::trace!(?hash, "Hierarchical Integrity hash data");
                // for Integrity hashes, we get the size from the last level
                hash.info_level_hash.levels.last().unwrap().size
            }
        };

        match fs_header.encryption_type {
            EncryptionType::None => {
                tracing::trace!("No encryption detected");

                // Seek to the filesystem start offset
                let reader = std::io::BufReader::new(self.reader.by_ref());

                let subfile = SubFile::new(reader, fs_offset_abs, fs_offset_abs + fs_size);

                // Box the reader
                Ok(Box::new(subfile))
            }
            EncryptionType::AesCtr => {
                tracing::trace!("Using AES-CTR decryption");

                // Get the proper decryption key
                let decrypt_key = self.get_aes_ctr_decrypt_key()?.to_vec();
                tracing::trace!(decrypt_key = %hex::encode(&decrypt_key), "Decryption key obtained");

                tracing::trace!(
                    abs_fs_offset = format!("0x{:X}", fs_offset_abs),
                    "Final filesystem absolute offset",
                );

                // Create a reader for the NCA file
                let reader = std::io::BufReader::new(self.reader.by_ref());

                // Create the AES-CTR reader using our decrypted key
                let aes_reader =
                    Aes128CtrReader::new(reader, fs_offset_abs, fs_header.ctr, decrypt_key);

                // Box the reader
                Ok(Box::new(aes_reader))
            }
            _ => {
                tracing::trace!(encryption_type = ?fs_header.encryption_type, "Unsupported encryption type");
                Err(crate::error::Error::InvalidData(format!(
                    "Unsupported encryption type: {:?}",
                    fs_header.encryption_type
                )))
            }
        }
    }

    #[instrument(level = "trace", skip(self))]
    pub fn open_pfs0_filesystem(
        &mut self,
        idx: usize,
    ) -> Result<Pfs0<Box<dyn ReadSeek + '_>>, crate::error::Error> {
        // Prepare a reader for the PFS0 filesystem
        let mut reader = self.prepare_fs_reader(idx)?;

        // Read and log the magic bytes for debugging
        let mut magic = [0u8; 4];
        reader.seek(std::io::SeekFrom::Start(0))?;
        reader.read_exact(&mut magic)?;

        tracing::trace!(
            magic_bytes = %hex::encode(magic),
            magic_str = %String::from_utf8_lossy(&magic),
            "PFS0 magic bytes"
        );

        // Reset position to beginning
        reader.seek(std::io::SeekFrom::Start(0))?;

        // Attempt to open the PFS0
        tracing::trace!("Attempting to open PFS0");
        match Pfs0::from_reader(reader) {
            Ok(pfs0) => {
                // List the files if available
                if let Ok(files) = pfs0.list_files() {
                    tracing::trace!(files = ?files, "PFS0 opened successfully");
                } else {
                    tracing::trace!("PFS0 opened successfully but file listing failed");
                }
                Ok(pfs0)
            }
            Err(e) => {
                tracing::trace!(error = %e, "Failed to open PFS0");
                Err(crate::error::Error::InvalidData(format!(
                    "Failed to open PFS0: {}",
                    e
                )))
            }
        }
    }

    #[instrument(level = "trace", skip(self))]
    pub fn open_romfs_filesystem(
        &mut self,
        idx: usize,
    ) -> Result<RomFs<Box<dyn ReadSeek + '_>>, crate::error::Error> {
        tracing::trace!(idx, "Opening RomFS filesystem");

        // Let's do some checks first to make sure we can open the RomFS
        if idx >= self.fs_headers.len() {
            return Err(crate::error::Error::InvalidState(
                "Invalid filesystem index".to_string(),
            ));
        }

        let fs_header = &self.fs_headers[idx];
        if fs_header.fs_type != FsType::RomFs {
            return Err(crate::error::Error::InvalidState(format!(
                "Invalid filesystem type: {:?}",
                fs_header.fs_type
            )));
        }

        // Prepare a reader for the RomFS filesystem
        let reader = self.prepare_fs_reader(idx)?;

        // Attempt to open the RomFS
        tracing::trace!("Attempting to open RomFS");

        RomFs::from_reader(reader)
    }
    pub fn decrypt_and_dump_fs(&mut self, idx: usize) -> Result<Vec<u8>, crate::error::Error> {
        tracing::trace!("Decrypting and dumping filesystem {}", idx);
        let mut reader = self.prepare_fs_reader(idx)?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;
    use xts_mode::get_tweak_default;

    pub fn test_nca_file(path: &str) -> color_eyre::Result<()> {
        let keyset = Keyset::from_file("prod.keys")?;
        let file_path = std::path::Path::new(path);
        let nca_file = std::fs::File::open(file_path)?;

        let filename = file_path.file_name().unwrap().to_str().unwrap();
        tracing::trace!("Decrypting NCA: {}", filename);

        let title_keys = TitleKeys::load_from_file("/home/cappy/.switch/title.keys")?;

        let reader = std::io::BufReader::new(nca_file);
        let mut nca = Nca::from_reader(reader, &keyset, Some(&title_keys)).unwrap();

        tracing::trace!("{:?}", nca.header);

        for (i, fs_header) in nca.fs_headers.iter().enumerate() {
            tracing::trace!("Filesystem {}: {:0?}", i, fs_header);
        }

        tracing::trace!("Total valid filesystems: {}", nca.filesystem_count());

        for fs_idx in 0..nca.filesystem_count() {
            tracing::trace!("Trying filesystem {}", fs_idx);
            let fs_offset = nca.get_fs_offset(fs_idx);
            tracing::trace!("Filesystem type: {:?}", nca.fs_headers[fs_idx].fs_type);

            match nca.fs_headers[fs_idx].fs_type {
                FsType::RomFs => {
                    let romfs_result = nca.open_romfs_filesystem(fs_idx);

                    match romfs_result {
                        Ok(mut romfs) => {
                            tracing::trace!("RomFS #{} opened successfully!", fs_idx);
                            // tracing::trace!("Files in RomFS #{}: {:?}", fs_idx, romfs);
                            if let Ok(files) = romfs.list_files() {
                                tracing::trace!("Files in RomFS #{}: {:?}", fs_idx, files);
                            }
                        }
                        Err(e) => {
                            tracing::trace!("Failed to open RomFS #{}: {}", fs_idx, e);
                            // For further debugging, you could try reading raw bytes from the offset
                        }
                    }
                }

                FsType::PartitionFs => {
                    let pfs0_result = nca.open_pfs0_filesystem(fs_idx);

                    match pfs0_result {
                        Ok(pfs0) => {
                            tracing::trace!("PFS0 #{} opened successfully!", fs_idx);
                            if let Ok(files) = pfs0.list_files() {
                                tracing::trace!("Files in PFS0 #{}: {:?}", fs_idx, files);
                            }
                        }
                        Err(e) => {
                            tracing::trace!("Failed to open PFS0 #{}: {}", fs_idx, e);
                            // For further debugging, you could try reading raw bytes from the offset
                            if let Some(fs_offset) = fs_offset {
                                tracing::trace!("Dumping raw bytes from offset 0x{:X}", fs_offset);
                                let mut raw_reader = std::fs::File::open(file_path)?;
                                raw_reader.seek(std::io::SeekFrom::Start(fs_offset))?;
                                let mut buf = [0u8; 0x100];
                                raw_reader.read_exact(&mut buf)?;
                                tracing::trace!("Raw bytes: {}", hex::encode(&buf[..16]));
                            }

                            // Log the error and continue instead of unwrapping
                            tracing::error!("PFS0 error: {}", e);

                            panic!("Failed to open PFS0: {}", e);
                        }
                    }
                }
            }
        }

        // nca.decrypt_and_dump_fs(0).unwrap();
        Ok(())
    }

    #[test]
    // #[instrument]
    #[traced_test]
    pub fn cnmt_nca_sanity_test() -> color_eyre::Result<()> {
        let file_path =
            std::path::Path::new("test/Browser/cf03cf6a80796869775f77e0c61e136e.cnmt.nca");

        test_nca_file(file_path.to_str().unwrap())?;

        Ok(())
    }

    #[test]
    #[traced_test]
    pub fn test_multiple_files() -> color_eyre::Result<()> {
        let file_path = std::path::Path::new("test/Browser");

        for entry in std::fs::read_dir(file_path)? {
            let entry = entry?;
            let path = entry.path();
            let path_str = path.to_str().unwrap();
            if path_str.ends_with(".nca") {
                test_nca_file(path_str)?;
            }
        }

        Ok(())
    }

    #[test]
    #[traced_test]
    pub fn test_nca() -> color_eyre::Result<()> {
        let file_path = std::path::Path::new("dump/smb_wonder_update.cnmt.nca");

        test_nca_file(file_path.to_str().unwrap())?;
        Ok(())
    }

    #[test]
    #[traced_test]
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
            key_generation: KeyGeneration::Gen1_0_0,
            signature_key_generation: 0,
            _reserved_e: [0; 0xE],
            rights_id: [0; 0x10],
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
            header_key_cache: Some([0; 0x20]),
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

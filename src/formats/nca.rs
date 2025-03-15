//! Nintendo Content Archive (NCA) format parser with AES-XTS decryption

use super::Keyset;
use aes::{
    Aes128,
    cipher::{BlockDecryptMut, KeyInit},
};
use binrw::{Endian, io::Cursor, meta::ReadEndian, prelude::*};
use std::io::{Read, Seek, SeekFrom};
use xts_mode::{Xts128, get_tweak_default};

// Region helper structure
#[derive(BinRead, Debug)]
pub struct Region {
    pub offset: u64,
    pub size: u64,
}

// ========== ENUM DEFINITIONS ========== //

#[repr(u8)]
#[derive(Debug, Clone, Copy, BinRead)]
pub enum DistributionType {
    #[brw(magic = 0x00u8)]
    Download = 0x00,
    #[brw(magic = 0x01u8)]
    GameCard = 0x01,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, BinRead)]
pub enum ContentType {
    #[brw(magic = 0x00u8)]
    Program = 0x00,
    #[brw(magic = 0x01u8)]
    Meta = 0x01,
    #[brw(magic = 0x02u8)]
    Control = 0x02,
    #[brw(magic = 0x03u8)]
    Manual = 0x03,
    #[brw(magic = 0x04u8)]
    Data = 0x04,
    #[brw(magic = 0x05u8)]
    PublicData = 0x05,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, BinRead)]
pub enum HashType {
    #[brw(magic = 0x00u8)]
    Auto = 0x00,
    #[brw(magic = 0x01u8)]
    None = 0x01,
    #[brw(magic = 0x02u8)]
    HierarchicalSha256Hash = 0x02,
    #[brw(magic = 0x03u8)]
    HierarchicalIntegrityHash = 0x03,
    #[brw(magic = 0x04u8)]
    AutoSha3 = 0x04,
    #[brw(magic = 0x05u8)]
    HierarchicalSha3256Hash = 0x05,
    #[brw(magic = 0x06u8)]
    HierarchicalIntegritySha3Hash = 0x06,
}
#[repr(u8)]
#[derive(Debug, Clone, Copy, BinRead)]
pub enum EncryptionType {
    #[brw(magic = 0x00u8)]
    Auto = 0x00,
    #[brw(magic = 0x01u8)]
    None = 0x01,
    #[brw(magic = 0x02u8)]
    AesXts = 0x02,
    #[brw(magic = 0x03u8)]
    AesCtr = 0x03,
    #[brw(magic = 0x04u8)]
    AesCtrEx = 0x04,
    #[brw(magic = 0x05u8)]
    AesCtrSkipLayerHash = 0x05,
    #[brw(magic = 0x06u8)]
    AesCtrExSkipLayerHash = 0x06,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, BinRead)]
pub enum MetaDataHashType {
    #[brw(magic = 0x00u8)]
    None = 0x00,
    #[brw(magic = 0x01u8)]
    HierarchicalIntegrity = 0x01,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, BinRead)]
pub enum FsType {
    #[brw(magic = 0x00u8)]
    RomFs = 0x00,
    #[brw(magic = 0x01u8)]
    PartitionFs = 0x01,
}

// ========== HEADER STRUCTURES ========== //

#[derive(BinRead, Debug)]
pub struct FsEntry {
    pub start_offset: u32,
    pub end_offset: u32,
    #[br(pad_before = 0x8)]
    _reserved: u64,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct NcaHeader {
    #[br(count = 0x100)]
    _signature_fixed: Vec<u8>,
    #[br(count = 0x100)]
    _signature_npdm: Vec<u8>,
    #[br(pad_before = 0x200 - 0x200, magic = b"NCA3")]
    pub distribution_type: DistributionType,
    pub content_type: ContentType,
    pub key_generation_old: u8,
    pub key_area_encryption_key_index: u8,
    pub content_size: u64,
    pub program_id: u64,
    pub content_index: u32,
    pub sdk_addon_version: u32,
    pub key_generation: u8,
    pub signature_key_generation: u8,
    #[br(count = 0xE)]
    _reserved_header: Vec<u8>,
    #[br(count = 0x10)]
    pub rights_id: Vec<u8>,
    #[br(count = 4)]
    pub fs_entries: Vec<FsEntry>,
    #[br(count = 32 * 4)]
    _section_hashes: Vec<u8>,
    #[br(count = 16 * 4)]
    pub encrypted_key_area: Vec<u8>,
}

// ========== FILE SYSTEM HEADERS ========== //

#[derive(BinRead, Debug)]
pub struct BucketTreeHeader {
    magic: [u8; 4],
    version: u32,
    entry_count: u32,
    _reserved: u32,
}

#[derive(Debug)]
pub enum HashData {
    HierarchicalSha256 {
        master_hash: [u8; 32],
        block_size: u32,
        layer_count: u32,
        layer_regions: [Region; 2],
    },
    IntegrityMeta {
        magic: [u8; 4],
        version: u32,
        master_hash_size: u32,
        levels: [HierarchicalIntegrityLevel; 3],
        master_hash: [u8; 32],
    },
    // Other variants omitted for brevity
}

#[derive(BinRead, Debug)]
pub struct HierarchicalIntegrityLevel {
    logical_offset: u64,
    hash_data_size: u64,
    block_size: u32,
    _reserved: u32,
}

pub struct FsHeader {
    pub version: u16,
    pub fs_type: FsType,
    pub hash_type: HashType,
    pub encryption_type: EncryptionType,
    pub meta_data_hash_type: MetaDataHashType,
    pub hash_data: HashData,
    // Other fields omitted for brevity
}

// Custom parsing implementation for FsHeader
impl BinRead for FsHeader {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: binrw::Endian,
        _: Self::Args<'_>,
    ) -> BinResult<Self> {
        let version = u16::read_options(reader, options, ())?;
        let fs_type = FsType::read_options(reader, options, ())?;
        let hash_type = HashType::read_options(reader, options, ())?;
        let encryption_type = EncryptionType::read_options(reader, options, ())?;
        let meta_data_hash_type = MetaDataHashType::read_options(reader, options, ())?;
        let _reserved = <[u8; 2]>::read_options(reader, options, ())?;

        let hash_data = match hash_type {
            HashType::HierarchicalSha256Hash => {
                let master_hash = <[u8; 32]>::read_options(reader, options, ())?;
                let block_size = u32::read_options(reader, options, ())?;
                let layer_count = u32::read_options(reader, options, ())?;
                let mut layer_regions =
                    std::array::from_fn::<_, 2, _>(|_| Region { offset: 0, size: 0 });
                for region in &mut layer_regions {
                    *region = Region::read_options(reader, options, ())?;
                }
                HashData::HierarchicalSha256 {
                    master_hash,
                    block_size,
                    layer_count,
                    layer_regions,
                }
            }
            // Other hash types handled similarly
            _ => {
                return Err(binrw::Error::Custom {
                    pos: reader.stream_position()?,
                    err: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Unsupported hash type: {:?}", hash_type),
                    )),
                });
            }
        };

        Ok(Self {
            version,
            fs_type,
            hash_type,
            encryption_type,
            meta_data_hash_type,
            hash_data,
        })
    }
}

impl ReadEndian for FsHeader {
    const ENDIAN: binrw::meta::EndianKind = binrw::meta::EndianKind::Endian(Endian::Little);
}

// ========== MAIN NCA PARSER ========== //

pub struct Nca<R: Read + Seek> {
    reader: R,
    pub header: NcaHeader,
    section_headers: Vec<FsHeader>,
    decrypted_keys: Vec<[u8; 16]>,
    keyset: Keyset,
}

impl<R: Read + Seek> Nca<R> {
    pub fn new(mut reader: R, keyset: Keyset) -> Result<Self, Box<dyn std::error::Error>> {
        // Read and decrypt header
        let mut encrypted_header = vec![0u8; 0xC00];
        reader.read_exact(&mut encrypted_header)?;
        let decrypted_header = Self::decrypt_header(&encrypted_header, &keyset.header_key)?;

        // Parse main header
        let mut cursor = Cursor::new(&decrypted_header[..0x400]);
        let header = NcaHeader::read(&mut cursor)?;

        // Parse section headers
        let mut section_headers = Vec::new();
        for i in 0..4 {
            let start = 0x400 + i * 0x200;
            let end = start + 0x200;
            let mut cursor = Cursor::new(&decrypted_header[start..end]);
            section_headers.push(FsHeader::read(&mut cursor)?);
        }

        // Decrypt key area
        let decrypted_keys = Self::decrypt_key_area(&header, &keyset)?;

        Ok(Self {
            reader,
            header,
            section_headers,
            decrypted_keys,
            keyset,
        })
    }

    fn decrypt_header(
        data: &[u8],
        header_key: &[u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (data_key, tweak_key) = header_key.split_at(16);
        let cipher: Xts128<Aes128> = Xts128::new(
            Aes128::new_from_slice(data_key).unwrap(),
            Aes128::new_from_slice(tweak_key).unwrap(),
        );
        let mut decrypted = data.to_vec();

        for (sector_idx, sector) in decrypted.chunks_mut(0x200).enumerate() {
            let tweak = get_tweak_default(sector_idx as u128);
            cipher.decrypt_sector(sector, tweak);
        }

        Ok(decrypted)
    }

    fn decrypt_key_area(
        header: &NcaHeader,
        keyset: &Keyset,
    ) -> Result<Vec<[u8; 16]>, Box<dyn std::error::Error>> {
        let key_area = match header.key_area_encryption_key_index {
            0 => &keyset.key_area_keys_application,
            1 => &keyset.key_area_keys_ocean,
            2 => &keyset.key_area_keys_system,
            _ => return Err("Invalid key area index".into()),
        };

        let master_key = key_area
            .get(header.key_generation as usize)
            .ok_or("Key generation not found")?;

        header
            .encrypted_key_area
            .chunks(16)
            .map(|chunk| {
                let mut block = [0u8; 16];
                block.copy_from_slice(chunk);
                let mut cipher = Aes128::new_from_slice(master_key).unwrap();
                cipher.decrypt_block_mut((&mut block).into());
                Ok(block)
            })
            .collect()
    }

    pub fn extract_section(
        &mut self,
        section_id: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let entry = self
            .header
            .fs_entries
            .get(section_id)
            .ok_or("Invalid section ID")?;
        let header = self
            .section_headers
            .get(section_id)
            .ok_or("Invalid section ID")?;
        let key = self
            .decrypted_keys
            .get(section_id)
            .ok_or("No key for section")?;

        let start = u64::from(entry.start_offset) * 0x200;
        let size = (u64::from(entry.end_offset) - u64::from(entry.start_offset)) * 0x200;

        self.reader.seek(SeekFrom::Start(start))?;
        let mut data = vec![0u8; size as usize];
        self.reader.read_exact(&mut data)?;

        match header.encryption_type {
            EncryptionType::AesXts => self.decrypt_xts(&mut data, key),
            EncryptionType::AesCtr => self.decrypt_ctr(&mut data, key),
            _ => Ok(data),
        }
    }

    fn decrypt_xts(
        &self,
        data: &mut [u8],
        key: &[u8; 16],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (data_key, tweak_key) = self.keyset.header_key.split_at(16);
        let cipher = Xts128::new(
            Aes128::new_from_slice(data_key).unwrap(),
            Aes128::new_from_slice(tweak_key).unwrap(),
        );
        let mut decrypted = data.to_vec();

        for (sector_idx, sector) in decrypted.chunks_mut(0x200).enumerate() {
            let tweak = get_tweak_default((sector_idx as u128).into());
            cipher.decrypt_sector(sector, tweak);
        }

        Ok(decrypted)
    }

    fn decrypt_ctr(
            &self,
            data: &mut [u8],
            key: &[u8; 16],
        ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            use aes::cipher::BlockEncryptMut;

            // Create a copy of the data to decrypt
            let mut decrypted = data.to_vec();

            // Initialize AES cipher with the provided key
            let mut cipher = Aes128::new_from_slice(key).map_err(|e| Box::<dyn std::error::Error>::from(format!("AES key error: {}", e)))?;

            // Create counter block (typically would use section-specific counter)
            let mut counter = [0u8; 16];

            // Create a buffer for the keystream
            let mut keystream = [0u8; 16];

            // Process each block
            for (i, chunk) in decrypted.chunks_mut(16).enumerate() {
                // Update counter for this block
                // In real implementation, this would use a proper CTR mode counter
                // format with nonce + counter
                for j in 0..8 {
                    counter[8 + j] = ((i as u64) >> (j * 8)) as u8;
                }

                // Encrypt the counter to get the keystream
                keystream.copy_from_slice(&counter);
                cipher.encrypt_block_mut((&mut keystream).into());

                // XOR the keystream with the data
                for (data_byte, keystream_byte) in chunk.iter_mut().zip(keystream.iter()) {
                    *data_byte ^= keystream_byte;
                }
            }

            Ok(decrypted)
        }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Cursor, Read};
    use std::path::Path;

    fn load_test_keyset() -> Result<Keyset, Box<dyn std::error::Error>> {
        let keyset_path = Path::new("/home/cappy/.switch/prod.keys");
        let mut keyset_file = File::open(keyset_path)?;
        let mut keyset_data = Vec::new();
        keyset_file.read_to_end(&mut keyset_data)?;

        // Parse the keyset from the file
        let cursor = Cursor::new(keyset_data);
        // Use cursor directly without casting, ensuring it implements Read + Seek
        let keyset = Keyset::from_reader(cursor)?;
        Ok(keyset)
    }

    #[test]
    fn test_read_nca_from_file() {
        // Read an actual NCA file
        let nca_path = Path::new("tests/data/sample.nca");
        let file = File::open(nca_path).expect("Failed to open test NCA file");

        // Load the keyset from a file
        let keyset = load_test_keyset().expect("Failed to load test keyset");

        // Create an NCA instance from the file
        let nca = Nca::new(file, keyset).expect("Failed to create NCA from file");

        // Basic validation
        // assert_eq!(nca.header.content_type, ContentType::Program);
        assert!(nca.header.content_size > 0);
    }

    #[test]
    fn test_decrypt_header() {
        // This is a simplified test with mock data
        let mock_header = vec![0u8; 0xC00]; // Mock encrypted header
        let mock_key = [0u8; 32]; // Mock header key

        let result = Nca::<Cursor<Vec<u8>>>::decrypt_header(&mock_header, &mock_key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0xC00);
    }

    #[test]
    fn test_decrypt_key_area() {
        // Load the keyset from a file
        let keyset = load_test_keyset().expect("Failed to load test keyset");

        // Create a mock header with some test data
        let mut header = NcaHeader {
            _signature_fixed: vec![0u8; 0x100],
            _signature_npdm: vec![0u8; 0x100],
            distribution_type: DistributionType::Download,
            content_type: ContentType::Program,
            key_generation_old: 0,
            key_area_encryption_key_index: 0, // Application key
            content_size: 1024,
            program_id: 0,
            content_index: 0,
            sdk_addon_version: 0,
            key_generation: 0,
            signature_key_generation: 0,
            _reserved_header: vec![0u8; 0xE],
            rights_id: vec![0u8; 0x10],
            fs_entries: vec![],
            _section_hashes: vec![0u8; 32 * 4],
            encrypted_key_area: vec![0u8; 16 * 4],
        };

        let result = Nca::<Cursor<Vec<u8>>>::decrypt_key_area(&header, &keyset);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 4);
    }

    #[test]
    fn test_extract_section_from_file() {
        // Read an actual NCA file
        let nca_path = Path::new("test/Browser/cf03cf6a80796869775f77e0c61e136e.cnmt.nca");
        let file = File::open(nca_path).expect("Failed to open test NCA file");

        // Load the keyset from a file
        let keyset = load_test_keyset().expect("Failed to load test keyset");

        // Create an NCA instance from the file
        let mut nca = Nca::new(file, keyset).expect("Failed to create NCA from file");

        // Try to extract the first section
        let section_data = nca.extract_section(0).expect("Failed to extract section 0");

        // Basic validation
        assert!(!section_data.is_empty());
    }

    #[test]
    fn test_fstypes_enum() {
        assert_eq!(FsType::RomFs as u8, 0x00);
        assert_eq!(FsType::PartitionFs as u8, 0x01);
    }

    #[test]
    fn test_encryption_types_enum() {
        assert_eq!(EncryptionType::None as u8, 0x01);
        assert_eq!(EncryptionType::AesXts as u8, 0x02);
        assert_eq!(EncryptionType::AesCtr as u8, 0x03);
    }
}
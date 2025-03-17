use binrw::prelude::*;

#[binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct RSASignature {
    // #[brw(count = 8)]
    pub signature: [[u8; 0x20]; 8],
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The source of the content the NCA is for, either downloaded from
/// the CDN or from a game card (cartridge).
pub enum DistributionType {
    /// The content was downloaded from a CDN, such as the eShop.
    Download = 0x00,
    /// The content is from a game card (cartridge).
    GameCard = 0x01,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The type of content stored in the NCA.
pub enum ContentType {
    /// Program content (executable code).
    Program = 0x00,
    /// Meta content (information about the title).
    Meta = 0x01,
    /// Control content (icon, screenshots, etc.).
    Control = 0x02,
    /// Manual content (digital manual/documentation).
    Manual = 0x03,
    /// Data content (general game data).
    Data = 0x04,
    /// Public data content.
    PublicData = 0x05,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The key generation used for the NCA.
pub enum KeyGeneration {
    /// 1.0.0 key generation
    Gen1_0_0 = 0x00,
    /// Unknown key generation (presumably planned for Horizon 2.0.0 but never used)
    Unused = 0x01,
    /// 3.0.0 key generation
    Gen3_0_0 = 0x02,
    /// 4.0.0 key generation
    Gen4_0_0 = 0x03,
    /// 5.0.0 key generation
    Gen5_0_0 = 0x04,
    /// 6.0.0 key generation
    Gen6_0_0 = 0x05,
    /// 6.2.0 key generation
    Gen6_2_0 = 0x06,
    /// 7.0.0 key generation
    Gen7_0_0 = 0x07,
    /// 8.1.0 key generation
    Gen8_1_0 = 0x08,
    /// 9.0.0 key generation
    Gen9_0_0 = 0x09,
    /// 9.1.0 key generation
    Gen9_1_0 = 0x0A,
    /// 12.1.0 key generation
    Gen12_1_0 = 0x0B,
    /// 13.0.0 key generation
    Gen13_0_0 = 0x0C,
    /// 14.0.0 key generation
    Gen14_0_0 = 0x0D,
}

/// Alias for backward compatibility
pub type KeyGenerationOld = KeyGeneration;

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The encryption key index used for the key area in the NCA header.
pub enum KeyAreaEncryptionKeyIndex {
    /// Application key area encryption key.
    Application = 0x00,
    /// Ocean key area encryption key.
    Ocean = 0x01,
    /// System key area encryption key.
    System = 0x02,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Filesystem type
pub enum FsType {
    /// RomFS filesystem
    RomFs = 0x00,
    /// Partition filesystem
    PartitionFs = 0x01,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Hash type used for filesystem verification
pub enum HashType {
    #[default]
    /// Automatically select hash type
    Auto = 0x00,
    /// No hash verification
    None = 0x01,
    /// Hierarchical SHA256 hash
    HierarchicalSha256Hash = 0x02,
    /// Hierarchical integrity hash
    HierarchicalIntegrityHash = 0x03,
    /// [14.0.0+] Automatically select SHA3 hash
    AutoSha3 = 0x04,
    /// [14.0.0+] Hierarchical SHA3-256 hash
    HierarchicalSha3256Hash = 0x05,
    /// [14.0.0+] Hierarchical integrity SHA3 hash
    HierarchicalIntegritySha3Hash = 0x06,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Encryption type for NCA content
pub enum EncryptionType {
    /// Automatically select encryption type
    Auto = 0x00,
    /// No encryption
    None = 0x01,
    /// AES-XTS encryption
    AesXts = 0x02,
    /// AES-CTR encryption
    AesCtr = 0x03,
    /// AES-CTR extended encryption
    AesCtrEx = 0x04,
    /// [14.0.0+] AES-CTR encryption with skipped layer hash
    AesCtrSkipLayerHash = 0x05,
    /// [14.0.0+] AES-CTR extended encryption with skipped layer hash
    AesCtrExSkipLayerHash = 0x06,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// [14.0.0+] Hash type for metadata
pub enum MetaDataHashType {
    /// No metadata hash
    None = 0x00,
    /// Hierarchical integrity hash for metadata
    HierarchicalIntegrity = 0x01,
}

#[binrw]
#[brw(little)]
#[derive(Debug, PartialEq, Eq)]
pub enum HashData {
    // We don't want to actually pre-assert this since binrw
    // looks for the magic byte at the start of the struct, and we know
    // that IVFC is the only variant that starts with that magic byte.
    // #[br(pre_assert(hash_type == HashType::HierarchicalSha256Hash))]
    HierarchicalSha256Hash {
        #[brw(pad_size_to = 0x20)]
        master_hash: [u8; 0x20],
        #[brw(pad_size_to = 0x4)]
        hash_block_size: u32,
        #[brw(pad_size_to = 0x4)]
        layer_count: u32,
        // Add hash table offset and pfs0 offset fields to match CNTX
        #[brw(pad_size_to = 0x8)]
        hash_table_offset: u64,
        #[brw(pad_size_to = 0x8)]
        hash_table_size: u64,
        #[brw(pad_size_to = 0x8)]
        pfs0_offset: u64,
        #[brw(pad_size_to = 0x8)]
        pfs0_size: u64,
        // Remaining layer regions and reserved fields
        #[brw(pad_size_to = 0x20)]
        #[br(count = 0x20)]
        _reserved1: Vec<u8>,
        #[brw(pad_size_to = 0x20)]
        #[br(count = 0x20)]
        _reserved2: Vec<u8>,
        #[brw(pad_size_to = 0x20)]
        #[br(count = 0x20)]
        _reserved3: Vec<u8>,
        #[brw(pad_size_to = 0x10)]
        #[br(count = 0x10)]
        _reserved4: Vec<u8>,
    },
    // #[br(pre_assert(hash_type == HashType::HierarchicalIntegrityHash))]
    #[br(magic = b"IVFC")]
    HierarchicalIntegrity {
        version: u32,
        #[brw(pad_size_to = 0x4)]
        master_hash_size: u32,
        #[brw(pad_size_to = 0xB4)]
        info_level_hash: InfoLevelHash,
        #[brw(pad_size_to = 0x20)]
        master_hash: [u8; 0x20],
        #[brw(pad_size_to = 0x18)]
        #[br(count = 0x18)]
        _reserved: Vec<u8>,
    },
}

impl HashData {
    /// Get the number of layers in the hash data
    pub fn get_layer_count(&self) -> u32 {
        match self {
            HashData::HierarchicalSha256Hash { layer_count, .. } => *layer_count,
            HashData::HierarchicalIntegrity {
                info_level_hash, ..
            } => info_level_hash.max_layers,
        }
    }

    /// Get the block size for a specific layer
    /// For HierarchicalSha256Hash, layer index is ignored since all layers use the same block size
    /// For HierarchicalIntegrity, returns the block size for the specified layer
    /// Returns None if the layer index is out of bounds
    pub fn get_block_size(&self, layer_index: usize) -> Option<u32> {
        match self {
            HashData::HierarchicalSha256Hash {
                hash_block_size, ..
            } => Some(*hash_block_size),
            HashData::HierarchicalIntegrity {
                info_level_hash, ..
            } => {
                if layer_index < info_level_hash.levels.len() {
                    // The block size is stored as log2, so we need to calculate 2^block_size_log2
                    let block_size_log2 = info_level_hash.levels[layer_index].block_size_log2;
                    Some(1 << block_size_log2)
                } else {
                    None
                }
            }
        }
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, PartialEq, Eq)]
pub struct InfoLevelHash {
    pub max_layers: u32,
    #[brw(pad_size_to = 0x90)]
    #[br(count = max_layers)]
    pub levels: Vec<HierarchicalIntegrityLevelInfo>,
    #[brw(pad_size_to = 0x20)]
    pub signature_salt: [u8; 0x20],
}

#[binrw]
#[brw(little)]
#[derive(Debug, PartialEq, Eq)]
pub struct HierarchicalIntegrityLevelInfo {
    pub offset: u64,
    pub size: u64,
    pub block_size_log2: u32,
    #[brw(pad_size_to = 0x4)]
    pub _reserved: [u8; 0x4],
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
// The FsHeader for each section is at offset + 0x400 + (sectionid * 0x200),
// where sectionid corresponds to the index used with the entry/hash tables.
/// NCA filesystem header
pub struct FsHeader {
    /// The filesystem version for the NCA.
    ///
    /// In most cases, this should always be a 2.
    pub version: u16,
    /// The type of filesystem used in this section.
    pub fs_type: FsType,
    /// The hash type used for filesystem verification.
    pub hash_type: HashType,
    /// The encryption type used for the filesystem.
    pub encryption_type: EncryptionType,
    /// Metadata hash type, only used in 14.0.0+ NCAs.
    pub metadata_hash_type: MetaDataHashType,
    _reserved: [u8; 0x2],
    #[brw(pad_size_to = 0xF8)]
    pub hash_data: HashData,
    #[br(count = 0x40)]
    #[brw(pad_size_to = 0x40)]
    pub patch_info: Vec<u8>,
    // now we're at 0x140

    // cntx combines these 2 fields into a single u64
    // so I don't know if I should do the same
    pub ctr: u64,
    #[brw(pad_size_to = 0x30)]
    #[br(count = 0x30)]
    pub sparse_info: Vec<u8>,
    #[brw(pad_size_to = 0x28)]
    #[br(count = 0x28)]
    pub compression_info: Vec<u8>,
    #[brw(pad_size_to = 0x30)]
    #[br(count = 0x30)]
    pub metadata_hashdata_info: Vec<u8>,
    #[brw(pad_size_to = 0x30)]
    #[br(count = 0x30)]
    _reserved2: Vec<u8>,
}

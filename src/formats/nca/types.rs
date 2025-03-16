use binrw::prelude::*;

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug)]
/// The key generation used for the NCA.
pub enum KeyGenerationOld {
    /// 1.0.0 key generation
    Gen1_0_0 = 0x00,
    /// Unknown key generation (presumably planned for Horizon 2.0.0 but never used)
    Unused = 0x01,
    /// 3.0.0 key generation
    Gen3_0_0 = 0x02,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug)]
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
#[derive(Debug)]
/// Filesystem type
pub enum FsType {
    /// RomFS filesystem
    RomFs = 0x00,
    /// Partition filesystem
    PartitionFs = 0x01,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug)]
/// Hash type used for filesystem verification
pub enum HashType {
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
#[derive(Debug)]
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
#[derive(Debug)]
/// [14.0.0+] Hash type for metadata
pub enum MetaDataHashType {
    /// No metadata hash
    None = 0x00,
    /// Hierarchical integrity hash for metadata
    HierarchicalIntegrity = 0x01,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub enum HashData {
    HierarchicalSha256Hash {
        #[brw(pad_size_to = 0x20)]
        /// The master hash
        master_hash: [u8; 0x20],
        #[brw(pad_size_to = 0x4)]
        hash_block_size: u32,
        #[brw(pad_size_to = 0x4)]
        layer_count: u32,
        #[brw(pad_size_to = 0x50)]
        #[br(count = 0x50)]
        layer_regions: Vec<u8>,
        #[brw(pad_size_to = 0x80)]
        #[br(count = 0x80)]
        _reserved: Vec<u8>,
    },


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
    pub generation: u32,
    pub secure_value: u32,
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

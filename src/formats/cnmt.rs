use binrw::prelude::*;
use std::io::{Read, Seek};

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The type of meta content according to the ncmsvc documentation
pub enum ContentMetaType {
    /// Invalid meta content type
    Invalid = 0x00,
    /// System program (System Modules or System Applets)
    SystemProgram = 0x01,
    /// System data archives
    SystemData = 0x02,
    /// System update content
    SystemUpdate = 0x03,
    /// Boot image package (Firmware package A or C)
    BootImagePackage = 0x04,
    /// Boot image package safe (Firmware package B or D)
    BootImagePackageSafe = 0x05,
    /// Application content
    Application = 0x80,
    /// Patch content
    Patch = 0x81,
    /// AddOn content
    AddOn = 0x82,
    /// Delta content
    Delta = 0x83,
    /// [15.0.0+] Data patch content
    DataPatch = 0x84,
}

#[binrw]
#[brw(little, repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// [17.0.0+] The platform for content meta
///
/// Possibly used for specifying backwards/forwards compatibility
/// with the Nintendo Switch 2
pub enum ContentMetaPlatform {
    /// Nintendo Switch platform
    NX = 0,
}

#[binrw]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// The type of content according to the wiki documentation
pub enum ContentType {
    /// Meta content
    Meta = 0x0,
    /// Program content
    Program = 0x1,
    /// Data content
    Data = 0x2,
    /// Control content
    Control = 0x3,
    /// HTML document content
    HtmlDocument = 0x4,
    /// Legal information content
    LegalInformation = 0x5,
    /// Delta fragment content
    DeltaFragment = 0x6,
    /// Any other unrecognized content type
    // #[default]
    Other(u8),
}

impl From<u8> for ContentType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Meta,
            1 => Self::Program,
            2 => Self::Data,
            3 => Self::Control,
            4 => Self::HtmlDocument,
            5 => Self::LegalInformation,
            6 => Self::DeltaFragment,
            other => Self::Other(other),
        }
    }
}

impl From<ContentType> for u8 {
    fn from(value: ContentType) -> Self {
        match value {
            ContentType::Meta => 0,
            ContentType::Program => 1,
            ContentType::Data => 2,
            ContentType::Control => 3,
            ContentType::HtmlDocument => 4,
            ContentType::LegalInformation => 5,
            ContentType::DeltaFragment => 6,
            ContentType::Other(val) => val,
        }
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct CnmtHeader {
    /// Title ID
    pub title_id: u64,
    /// Title version
    pub title_version: u32,
    /// Content meta type
    pub meta_type: ContentMetaType,
    /// [17.0.0+] Content meta platform, [1.0.0-16.1.0] Reserved
    pub platform: ContentMetaPlatform,
    /// Extended header size
    pub extended_header_size: u16,
    /// Number of content entries
    pub content_count: u16,
    /// Number of meta entries
    pub content_meta_count: u16,
    /// Reserved field
    #[br(pad_before = 1)]
    /// Content meta attributes
    pub attributes: u8,
    /// Storage ID
    pub storage_id: u8,
    /// Content install type
    pub content_install_type: u8,
    /// Reserved field
    #[br(pad_before = 2)]
    /// Required download system version
    pub required_dl_system_version: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct ApplicationExtendedHeader {
    /// Patch ID
    pub patch_id: u64,
    /// Minimum system version required
    pub minimum_system_version: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct PatchExtendedHeader {
    /// Application ID
    pub application_id: u64,
    /// Minimum system version required
    pub minimum_system_version: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct AddonExtendedHeader {
    /// Application ID
    pub application_id: u64,
    /// Minimum application version required
    pub minimum_application_version: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct DeltaExtendedHeader {
    /// Application ID
    pub application_id: u64,
    /// Minimum system version required
    pub minimum_system_version: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct SystemUpdateExtendedHeader {
    /// System update meta version
    pub system_update_meta_version: u64,
}

#[derive(Debug, Clone)]
pub enum ExtendedHeader {
    Application(ApplicationExtendedHeader),
    Patch(PatchExtendedHeader),
    Addon(AddonExtendedHeader),
    Delta(DeltaExtendedHeader),
    SystemUpdate(SystemUpdateExtendedHeader),
    Unknown(Vec<u8>),
}

/// Firmware version information
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FirmwareVersion {
    /// Pre-15.0.0 firmware
    Pre15_0_0,
    /// 15.0.0+ firmware
    V15_0_0Plus,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
/// Content info structure containing details about content files
pub struct ContentInfo {
    /// Content ID (usually a hash or identifier)
    pub content_id: [u8; 16],

    /// Size of the content in bytes (6 bytes in pre-15.0.0)
    #[br(map = |bytes: [u8; 6]| {
        let mut size_bytes = [0u8; 8];
        size_bytes[0..6].copy_from_slice(&bytes);
        u64::from_le_bytes(size_bytes)
    })]
    #[bw(map = |size: &u64| {
        let size_bytes = size.to_le_bytes();
        let mut result = [0u8; 6];
        result.copy_from_slice(&size_bytes[0..6]);
        result
    })]
    pub size: u64,

    /// Content type
    #[br(map = |val: u8| ContentType::from(val))]
    #[bw(map = |content_type: &ContentType| u8::from(*content_type))]
    pub content_type: ContentType,

    /// Reserved field
    #[br(temp)]
    #[bw(calc = 0u8)]
    _reserved: u8,

    /// ID offset
    pub id_offset: u8,
}

/// Alternative implementation for 15.0.0+ firmware
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct ContentInfoV15 {
    /// Content ID (usually a hash or identifier)
    pub content_id: [u8; 16],

    /// Size of the content in bytes (5 bytes in 15.0.0+)
    #[br(map = |bytes: [u8; 5]| {
        let mut size_bytes = [0u8; 8];
        size_bytes[0..5].copy_from_slice(&bytes);
        u64::from_le_bytes(size_bytes)
    })]
    #[bw(map = |size: &u64| {
        let size_bytes = size.to_le_bytes();
        let mut result = [0u8; 5];
        result.copy_from_slice(&size_bytes[0..5]);
        result
    })]
    pub size: u64,

    /// Content attributes
    pub attributes: u8,

    /// Content type
    #[br(map = |val: u8| ContentType::from(val))]
    #[bw(map = |content_type: &ContentType| u8::from(*content_type))]
    pub content_type: ContentType,

    /// ID offset
    pub id_offset: u8,
}

impl From<ContentInfo> for ContentInfoV15 {
    fn from(info: ContentInfo) -> Self {
        Self {
            content_id: info.content_id,
            size: info.size,
            attributes: 0xFF, // Default value for unknown attributes
            content_type: info.content_type,
            id_offset: info.id_offset,
        }
    }
}

impl From<ContentInfoV15> for ContentInfo {
    fn from(info: ContentInfoV15) -> Self {
        Self {
            content_id: info.content_id,
            size: info.size,

            content_type: info.content_type,
            id_offset: info.id_offset,
        }
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
/// Content entry with hash and info
pub struct ContentEntry {
    /// SHA-256 hash of the content
    pub hash: [u8; 0x20], // 0x20 bytes SHA-256 hash
    /// Content info fields (without the hash)
    pub info: ContentInfo,
}

/// Alternative implementation for 15.0.0+ firmware
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct ContentEntryV15 {
    /// SHA-256 hash of the content
    pub hash: [u8; 32],
    /// Content info fields (without the hash)
    pub info: ContentInfoV15,
}

impl From<ContentEntry> for ContentEntryV15 {
    fn from(entry: ContentEntry) -> Self {
        Self {
            hash: entry.hash,
            info: entry.info.into(),
        }
    }
}

impl From<ContentEntryV15> for ContentEntry {
    fn from(entry: ContentEntryV15) -> Self {
        Self {
            hash: entry.hash,
            info: entry.info.into(),
        }
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
#[non_exhaustive]
/// Content meta entry for dependent content
pub struct ContentMetaEntry {
    /// Title ID
    pub title_id: u64,
    /// Version
    pub version: u32,
    /// Meta type
    pub meta_type: u8,
    /// Attributes
    pub attributes: u8,
    /// Reserved field
    #[br(pad_after = 2)]
    pub _reserved: (),
}

#[derive(Debug, Clone)]
/// Main CNMT structure containing all parsed data
pub struct Cnmt {
    /// CNMT header
    pub header: CnmtHeader,
    /// Extended header based on meta_type
    pub extended_header: ExtendedHeader,
    /// Content entries
    pub content_entries: Vec<ContentEntry>,
    /// Meta entries
    pub meta_entries: Vec<ContentMetaEntry>,
}

impl Cnmt {
    /// Parse a CNMT file from a reader
    pub fn from_reader<R: Read + Seek>(mut reader: &mut R) -> BinResult<Self> {
        // Read the header
        let header: CnmtHeader = reader.read_le()?;

        // Determine firmware version based on meta_type
        // For real implementation you would want a more robust way to detect firmware version
        let firmware_version = if header.meta_type == ContentMetaType::DataPatch {
            FirmwareVersion::V15_0_0Plus
        } else {
            FirmwareVersion::Pre15_0_0
        };

        // Read extended header based on meta type
        let extended_header = match header.meta_type {
            ContentMetaType::Application => {
                let ext: ApplicationExtendedHeader = reader.read_le()?;
                ExtendedHeader::Application(ext)
            }
            ContentMetaType::Patch => {
                let ext: PatchExtendedHeader = reader.read_le()?;
                ExtendedHeader::Patch(ext)
            }
            ContentMetaType::AddOn => {
                let ext: AddonExtendedHeader = reader.read_le()?;
                ExtendedHeader::Addon(ext)
            }
            ContentMetaType::Delta => {
                let ext: DeltaExtendedHeader = reader.read_le()?;
                ExtendedHeader::Delta(ext)
            }
            ContentMetaType::SystemUpdate => {
                let ext: SystemUpdateExtendedHeader = reader.read_le()?;
                ExtendedHeader::SystemUpdate(ext)
            }
            _ => {
                let mut buffer = vec![0u8; header.extended_header_size as usize];
                reader.read_exact(&mut buffer)?;
                ExtendedHeader::Unknown(buffer)
            }
        };

        // Read content entries based on firmware version
        let mut content_entries = Vec::with_capacity(header.content_count as usize);

        match firmware_version {
            FirmwareVersion::Pre15_0_0 => {
                for _ in 0..header.content_count {
                    let entry: ContentEntry = reader.read_le()?;
                    content_entries.push(entry);
                }
            }
            FirmwareVersion::V15_0_0Plus => {
                for _ in 0..header.content_count {
                    let v15_entry: ContentEntryV15 = reader.read_le()?;
                    content_entries.push(v15_entry.into());
                }
            }
        }

        // Read meta entries
        let mut meta_entries = Vec::with_capacity(header.content_meta_count as usize);
        for _ in 0..header.content_meta_count {
            let entry: ContentMetaEntry = reader.read_le()?;
            meta_entries.push(entry);
        }

        Ok(Cnmt {
            header,
            extended_header,
            content_entries,
            meta_entries,
        })
    }

    // Helper methods
    pub fn get_content_entry_by_type(&self, content_type: ContentType) -> Option<&ContentEntry> {
        self.content_entries
            .iter()
            .find(|entry| entry.info.content_type == content_type)
    }

    pub fn get_main_content_id(&self) -> Option<[u8; 16]> {
        self.get_content_entry_by_type(ContentType::Program)
            .map(|entry| entry.info.content_id)
    }

    pub fn get_extended_header_info(&self) -> String {
        match &self.extended_header {
            ExtendedHeader::Application(app) => {
                format!(
                    "Application - Patch ID: {:016X}, Min System Version: {}",
                    app.patch_id, app.minimum_system_version
                )
            }
            ExtendedHeader::Patch(patch) => {
                format!(
                    "Patch - Application ID: {:016X}, Min System Version: {}",
                    patch.application_id, patch.minimum_system_version
                )
            }
            ExtendedHeader::Addon(addon) => {
                format!(
                    "AddOn - Application ID: {:016X}, Min App Version: {}",
                    addon.application_id, addon.minimum_application_version
                )
            }
            ExtendedHeader::Delta(delta) => {
                format!(
                    "Delta - Application ID: {:016X}, Min System Version: {}",
                    delta.application_id, delta.minimum_system_version
                )
            }
            ExtendedHeader::SystemUpdate(sys) => {
                format!(
                    "System Update - Meta Version: {}",
                    sys.system_update_meta_version
                )
            }
            ExtendedHeader::Unknown(_) => "Unknown Extended Header".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::BufReader;
    use std::io::Cursor;
    use std::path::Path;

    #[test]
    fn test_parse_cnmt_header() {
        let test_data = [
            // Header data
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // title_id (u64)
            0x12, 0x34, 0x56, 0x78, // title_version (u32)
            0x80, // meta_type (u8) - APPLICATION (updated to 0x80)
            0x00, // platform (u8)
            0x10, 0x00, // extended_header_size (u16)
            0x02, 0x00, // content_count (u16)
            0x01, 0x00, // content_meta_count (u16)
            0x00, // reserved (u8)
            0x01, // attributes (u8)
            0x02, // storage_id (u8)
            0x03, // content_install_type (u8)
            0x00, 0x00, // reserved (u16)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, // required_dl_system_version (u64)
        ];

        let mut cursor = Cursor::new(test_data);
        let header: CnmtHeader = cursor.read_le().unwrap();

        assert_eq!(header.title_id, 0xEFCDAB8967452301);
        assert_eq!(header.title_version, 0x78563412);
        assert_eq!(header.meta_type, ContentMetaType::Application);
        assert_eq!(header.platform, ContentMetaPlatform::NX);
        assert_eq!(header.extended_header_size, 0x10);
        assert_eq!(header.content_count, 0x02);
        assert_eq!(header.content_meta_count, 0x01);
        assert_eq!(header.attributes, 0x01);
        assert_eq!(header.storage_id, 0x02);
        assert_eq!(header.content_install_type, 0x03);
        assert_eq!(header.required_dl_system_version, 0x8877665544332211);
    }

    #[test]
    fn test_content_entry() {
        let test_data = [
            // Hash (32 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, // Content ID (16 bytes)
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
            0x2F, 0x30, // Size (6 bytes)
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, // Content type (1 byte)
            0x01, // Content type = Program (value 1)
            0x0,  // Reserved (1 byte)
            0x42, 0x00, // ID offset (2 bytes - LE format 0x0042)
        ];

        let mut cursor = Cursor::new(test_data);
        let entry: ContentEntry = cursor.read_le().unwrap();

        // Test hash
        let expected_hash = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        assert_eq!(entry.hash, expected_hash);

        // Test content ID
        let expected_content_id = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
            0x2F, 0x30,
        ];
        assert_eq!(entry.info.content_id, expected_content_id);

        // Test size (6 bytes)
        let mut expected_size_bytes = [0u8; 8];
        expected_size_bytes[0..6].copy_from_slice(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        let expected_size = u64::from_le_bytes(expected_size_bytes);
        assert_eq!(entry.info.size, expected_size);

        // Test content type and id offset
        assert_eq!(entry.info.content_type, ContentType::Program); // Program is 0x1
        assert_eq!(entry.info.id_offset, 0x42);
    }

    #[test]
    fn test_content_entry_v15() {
        let test_data = [
            // Hash (32 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, // Content ID (16 bytes)
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
            0x2F, 0x30, // Size (5 bytes for 15.0.0+)
            0x31, 0x32, 0x33, 0x34, 0x35, // Content attributes (1 byte)
            0xFF, // Content type (1 byte)
            0x01, // Content type = Program (value 1)
            0x42, // ID offset (1 byte)
        ];

        let mut cursor = Cursor::new(test_data);
        let entry: ContentEntryV15 = cursor.read_le().unwrap();

        // Test hash
        let expected_hash = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        assert_eq!(entry.hash, expected_hash);

        // Test content ID
        let expected_content_id = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
            0x2F, 0x30,
        ];
        assert_eq!(entry.info.content_id, expected_content_id);

        // Test size (5 bytes)
        let mut expected_size_bytes = [0u8; 8];
        expected_size_bytes[0..5].copy_from_slice(&[0x31, 0x32, 0x33, 0x34, 0x35]);
        let expected_size = u64::from_le_bytes(expected_size_bytes);
        assert_eq!(entry.info.size, expected_size);

        // Test attributes, content type and id offset
        assert_eq!(entry.info.attributes, 0xFF);
        assert_eq!(entry.info.content_type, ContentType::Program);
        assert_eq!(entry.info.id_offset, 0x42);
    }

    #[test]
    fn test_application_cnmt() {
        let path = Path::new("dump/app.cnmt");

        // Skip test if file doesn't exist (to avoid CI failure)
        if (!path.exists()) {
            println!("Skipping test_application_cnmt: test file not found");
            return;
        }

        let file = File::open(path).expect("Failed to open test file");
        let mut reader = BufReader::new(file);
        let cnmt = Cnmt::from_reader(&mut reader).expect("Failed to parse CNMT");

        // Test header fields
        println!("Title ID: {:016X}", cnmt.header.title_id);
        println!("Title Version: {}", cnmt.header.title_version);
        println!("Meta Type: {:?}", cnmt.header.meta_type);
        println!("Extended Header Size: {}", cnmt.header.extended_header_size);
        println!("Content Count: {}", cnmt.header.content_count);
        println!("Content Meta Count: {}", cnmt.header.content_meta_count);
        println!("Attributes: {}", cnmt.header.attributes);
        println!("Storage ID: {}", cnmt.header.storage_id);
        println!("Content Install Type: {}", cnmt.header.content_install_type);

        // Print content types for debugging
        for (i, entry) in cnmt.content_entries.iter().enumerate() {
            println!("Content {}: Type={:?}", i, entry.info.content_type);
        }

        assert_eq!(cnmt.header.title_id, 0x0100c4c320c0ffee);

        // ...existing code...
    }

    #[test]
    fn test_extended_header_info() {
        let app_header = ApplicationExtendedHeader {
            patch_id: 0x0100000000000123,
            minimum_system_version: 0x0000000000000123,
        };

        let extended_header = ExtendedHeader::Application(app_header);
        let cnmt = Cnmt {
            header: CnmtHeader {
                title_id: 0,
                title_version: 0,
                meta_type: ContentMetaType::Application,
                platform: ContentMetaPlatform::NX,
                extended_header_size: 0,
                content_count: 0,
                content_meta_count: 0,
                attributes: 0,
                storage_id: 0,
                content_install_type: 0,
                required_dl_system_version: 0,
            },
            extended_header,
            content_entries: Vec::new(),
            meta_entries: Vec::new(),
        };

        let info = cnmt.get_extended_header_info();
        assert!(info.contains("0100000000000123"));
        assert!(info.contains("Application"));
    }
}

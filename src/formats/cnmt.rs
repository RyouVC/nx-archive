use binrw::prelude::*;
use std::io::{Read, Seek};

// CNMT Meta Types
pub const CNMT_TYPE_SYSTEM_UPDATE: u8 = 0x0;
pub const CNMT_TYPE_APPLICATION: u8 = 0x1;
pub const CNMT_TYPE_PATCH: u8 = 0x2;
pub const CNMT_TYPE_ADDON: u8 = 0x3;
pub const CNMT_TYPE_DELTA: u8 = 0x4;
pub const CNMT_TYPE_DATA_PATCH: u8 = 0x5; // [15.0.0+]

// Content Types
pub const CONTENT_TYPE_META: u8 = 0x0;
pub const CONTENT_TYPE_PROGRAM: u8 = 0x1;
pub const CONTENT_TYPE_DATA: u8 = 0x2;
pub const CONTENT_TYPE_CONTROL: u8 = 0x3;
pub const CONTENT_TYPE_HTML_DOCUMENT: u8 = 0x4;
pub const CONTENT_TYPE_LEGAL_INFORMATION: u8 = 0x5;
pub const CONTENT_TYPE_DELTA_FRAGMENT: u8 = 0x6;

/// Content Meta header structure
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct CnmtHeader {
    /// Title ID
    pub title_id: u64,
    /// Title version
    pub title_version: u32,
    /// Content meta type
    pub meta_type: u8,
    /// Reserved field
    #[br(pad_before = 1)]
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

/// Extended header for Application type
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct ApplicationExtendedHeader {
    /// Patch ID
    pub patch_id: u64,
    /// Minimum system version required
    pub minimum_system_version: u64,
}

/// Extended header for Patch type
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct PatchExtendedHeader {
    /// Application ID
    pub application_id: u64,
    /// Minimum system version required
    pub minimum_system_version: u64,
}

/// Extended header for AddOn type
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct AddonExtendedHeader {
    /// Application ID
    pub application_id: u64,
    /// Minimum application version required
    pub minimum_application_version: u64,
}

/// Extended header for Delta type
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct DeltaExtendedHeader {
    /// Application ID
    pub application_id: u64,
    /// Minimum system version required
    pub minimum_system_version: u64,
}

/// Extended header for System Update type
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct SystemUpdateExtendedHeader {
    /// System update meta version
    pub system_update_meta_version: u64,
}

/// Extended header variants based on content meta type
#[derive(Debug, Clone)]
pub enum ExtendedHeader {
    Application(ApplicationExtendedHeader),
    Patch(PatchExtendedHeader),
    Addon(AddonExtendedHeader),
    Delta(DeltaExtendedHeader),
    SystemUpdate(SystemUpdateExtendedHeader),
    Unknown(Vec<u8>),
}

/// Content info structure containing details about content files
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct ContentInfo {
    /// Content ID (usually a hash or identifier)
    pub content_id: [u8; 16],
    /// Size of the content in bytes (stored as a 48-bit value)
    pub size_attr: [u8; 6],
    /// Content type
    pub content_type: u8,
    /// ID offset
    #[br(pad_before = 1)]
    pub id_offset: u16,
}

/// Content entry with hash and info
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct ContentEntry {
    /// SHA-256 hash of the content
    pub hash: [u8; 32],
    /// Content info fields (without the hash)
    pub info: ContentInfo,
}

/// Content meta entry for dependent content
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
#[non_exhaustive]
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

/// Main CNMT structure containing all parsed data
#[derive(Debug, Clone)]
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
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> BinResult<Self> {
        // Read the header
        let header: CnmtHeader = reader.read_le()?;

        // Read extended header based on meta type
        let extended_header = match header.meta_type {
            CNMT_TYPE_APPLICATION => {
                let ext: ApplicationExtendedHeader = reader.read_le()?;
                ExtendedHeader::Application(ext)
            }
            CNMT_TYPE_PATCH => {
                let ext: PatchExtendedHeader = reader.read_le()?;
                ExtendedHeader::Patch(ext)
            }
            CNMT_TYPE_ADDON => {
                let ext: AddonExtendedHeader = reader.read_le()?;
                ExtendedHeader::Addon(ext)
            }
            CNMT_TYPE_DELTA => {
                let ext: DeltaExtendedHeader = reader.read_le()?;
                ExtendedHeader::Delta(ext)
            }
            CNMT_TYPE_SYSTEM_UPDATE => {
                let ext: SystemUpdateExtendedHeader = reader.read_le()?;
                ExtendedHeader::SystemUpdate(ext)
            }
            _ => {
                let mut buffer = vec![0u8; header.extended_header_size as usize];
                reader.read_exact(&mut buffer)?;
                ExtendedHeader::Unknown(buffer)
            }
        };

        // Read content entries
        let mut content_entries = Vec::with_capacity(header.content_count as usize);
        for _ in 0..header.content_count {
            let entry: ContentEntry = reader.read_le()?;
            content_entries.push(entry);
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

    /// Get content entry by its type
    pub fn get_content_entry_by_type(&self, content_type: u8) -> Option<&ContentEntry> {
        self.content_entries
            .iter()
            .find(|entry| entry.info.content_type == content_type)
    }

    /// Get the content ID of the main program
    pub fn get_main_content_id(&self) -> Option<[u8; 16]> {
        self.get_content_entry_by_type(CONTENT_TYPE_PROGRAM)
            .map(|entry| entry.info.content_id)
    }

    /// Get human-readable extended header information
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
            0x01, // meta_type (u8) - APPLICATION
            0x00, // reserved (u8)
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
        assert_eq!(header.meta_type, 0x01);
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
            0x01, // Reserved (1 byte)
            0x00, // ID offset (2 bytes)
            0x42, 0x00,
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
        // let mut expected_size_bytes = [0u8; 8];
        // expected_size_bytes[0..6].copy_from_slice(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        // let expected_size = u64::from_le_bytes(expected_size_bytes);
        // assert_eq!(entry.info.size, expected_size);

        // Test content type and id offset
        assert_eq!(entry.info.content_type, 0x01);
        assert_eq!(entry.info.id_offset, 0x0042);
    }

    #[test]
    fn test_application_cnmt() {
        let path = Path::new("test/Browser-cnmt/Application_0100c4c320c0ffee.cnmt");

        // Skip test if file doesn't exist (to avoid CI failure)
        if !path.exists() {
            println!("Skipping test_application_cnmt: test file not found");
            return;
        }

        let file = File::open(path).expect("Failed to open test file");
        let mut reader = BufReader::new(file);
        let cnmt = Cnmt::from_reader(&mut reader).expect("Failed to parse CNMT");

        // Test header fields
        println!("Title ID: {:016X}", cnmt.header.title_id);
        println!("Title Version: {}", cnmt.header.title_version);
        println!("Meta Type: {}", cnmt.header.meta_type);
        println!("Extended Header Size: {}", cnmt.header.extended_header_size);
        println!("Content Count: {}", cnmt.header.content_count);
        println!("Content Meta Count: {}", cnmt.header.content_meta_count);
        println!("Attributes: {}", cnmt.header.attributes);
        println!("Storage ID: {}", cnmt.header.storage_id);
        println!("Content Install Type: {}", cnmt.header.content_install_type);
        assert_eq!(cnmt.header.title_id, 0x0100c4c320c0ffee);
        // assert_eq!(cnmt.header.meta_type, CNMT_TYPE_APPLICATION);
        // assert_eq!(cnmt.header.extended_header_size, 16);

        for entry in cnmt.content_entries.iter() {
            // assert!(entry.info.size > 0, "Content size should be greater than 0");
            println!("Content ID: {:02X?}", entry.info.content_id);
            // println!("Content Size: {}", entry.info.size);
            println!("Content Type: {}", entry.info.content_type);
            println!("ID Offset: {}", entry.info.id_offset);
        }

        // Test extended header is Application type
        // if let ExtendedHeader::Application(app) = &cnmt.extended_header {
        //     assert!(app.patch_id > 0);
        // } else {
        //     panic!("Expected Application extended header");
        // }

        // println!("CNMT: {:?}", cnmt);
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
                meta_type: CNMT_TYPE_APPLICATION,
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

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
    Meta = 0x00,
    /// Program content
    Program = 0x01,
    /// Data content
    Data = 0x02,
    /// Control content
    Control = 0x03,
    /// HTML document content
    HtmlDocument = 0x04,
    /// Legal information content
    LegalInformation = 0x05,
    /// Delta fragment content
    DeltaFragment = 0x06,
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

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
/// Content entry with hash and info
pub struct PackagedContentInfo {
    pub hash: [u8; 0x20],
    pub content_id: [u8; 0x10],
    pub size_attr: [u8; 0x6],
    pub content_type: u8,
    pub id_offset: u16,
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
    /// Extended header data (optional, varies by content type)
    pub extended_header_bytes: Vec<u8>,
    /// Content entries
    pub content_entries: Vec<PackagedContentInfo>,
    /// Meta entries
    pub meta_entries: Vec<ContentMetaEntry>,
}

impl Cnmt {
    /// Parse a CNMT file from a reader
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> binrw::BinResult<Self> {
        // Read header
        let header = CnmtHeader::read_le(reader)?;

        // Handle extended header if present
        let mut extended_header_bytes = Vec::new();
        if header.extended_header_size > 0 {
            extended_header_bytes.resize(header.extended_header_size as usize, 0);
            reader.read_exact(&mut extended_header_bytes)?;
        }

        // Read content entries (exact number specified in header)
        let mut content_entries = Vec::with_capacity(header.content_count as usize);
        for _ in 0..header.content_count {
            content_entries.push(PackagedContentInfo::read_le(reader)?);
        }

        // Read meta entries (exact number specified in header)
        let mut meta_entries = Vec::with_capacity(header.content_meta_count as usize);
        for _ in 0..header.content_meta_count {
            meta_entries.push(ContentMetaEntry::read_le(reader)?);
        }

        Ok(Self {
            header,
            extended_header_bytes,
            content_entries,
            meta_entries,
        })
    }

    /// Get the title ID as a hex string
    pub fn title_id(&self) -> String {
        format!("{:016X}", self.header.title_id)
    }

    /// Get the title version
    pub fn version(&self) -> u32 {
        self.header.title_version
    }

    /// Get the content meta type
    pub fn content_meta_type(&self) -> ContentMetaType {
        self.header.meta_type
    }

    /// Get the content entries
    pub fn content_entries(&self) -> &[PackagedContentInfo] {
        &self.content_entries
    }

    /// Get the meta entries
    pub fn meta_entries(&self) -> &[ContentMetaEntry] {
        &self.meta_entries
    }

    /// Calculate the size of a content entry
    pub fn calculate_content_size(&self, index: usize) -> Option<u64> {
        if index >= self.content_entries.len() {
            return None;
        }

        let entry = &self.content_entries[index];
        let size = u64::from(entry.size_attr[0])
            | (u64::from(entry.size_attr[1]) << 8)
            | (u64::from(entry.size_attr[2]) << 16)
            | (u64::from(entry.size_attr[3]) << 24)
            | (u64::from(entry.size_attr[4]) << 32)
            | (u64::from(entry.size_attr[5]) << 40);

        Some(size)
    }

    /// Pretty print the CNMT information
    pub fn print_info(&self) {
        println!("Title ID: {}", self.title_id());
        println!("Version: {}", self.version());
        println!("Type: {:?}", self.content_meta_type());
        println!("\nContent Entries:");

        for (i, entry) in self.content_entries().iter().enumerate() {
            println!("  Entry {}:", i + 1);
            println!("    Content ID: {}", hex::encode(&entry.content_id));
            println!("    Hash: {}", hex::encode(&entry.hash));
            println!("    Type: {:?}", ContentType::from(entry.content_type));

            if let Some(size) = self.calculate_content_size(i) {
                println!("    Size: {} bytes", size);
            } else {
                println!("    Size: Unknown");
            }
        }

        if !self.meta_entries.is_empty() {
            println!("\nMeta Entries:");
            for (i, entry) in self.meta_entries.iter().enumerate() {
                println!("  Entry {}:", i + 1);
                println!("    Title ID: {:016X}", entry.title_id);
                println!("    Version: {}", entry.version);
                println!("    Type: {}", entry.meta_type);
                println!("    Attributes: {}", entry.attributes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FILE_BROWSER_CNMT: &[u8] =
        include_bytes!("../../test/Browser-cnmt/Application_0100c4c320c0ffee.cnmt");

    #[test]
    fn test_parse_browser_cnmt() {
        let mut reader = std::io::Cursor::new(TEST_FILE_BROWSER_CNMT);
        let cnmt = Cnmt::from_reader(&mut reader).unwrap();

        assert_eq!(cnmt.title_id(), "0100C4C320C0FFEE");
        assert!(matches!(
            cnmt.content_meta_type(),
            ContentMetaType::Application
        ));

        println!("{:?}", cnmt);
        cnmt.print_info();

        // Verify content entries
        assert!(!cnmt.content_entries().is_empty());

        // Check the expected size of first content
        if let Some(size) = cnmt.calculate_content_size(0) {
            assert!(size > 0, "Content size should be non-zero");
        }
    }
}

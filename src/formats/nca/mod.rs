use binrw::prelude::*;
use std::io::{Read, Seek};
use std::path::Path;
mod types;

use super::Keyset;
use super::keyset::get_nintendo_tweak;
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

#[binrw]
#[brw(little)]
#[derive(Debug)]
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
    #[br(count = 0x100)]
    #[bw(pad_size_to = 0x100)]
    pub header_sig: Vec<u8>,
    #[br(count = 0x100)]
    #[bw(pad_size_to = 0x100)]
    pub header_key_sig: Vec<u8>,
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
    #[br(count = 4)]
    #[brw(pad_size_to = 0x10 * 4)]
    pub encrypted_keys: Vec<[u8; 0x10]>,
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
}

#[test]
pub fn decrypt_nca_header() -> color_eyre::Result<()> {
    let keyset = Keyset::from_file("prod.keys")?;

    let file_path = Path::new("test/Browser/2b9b99ea58139c320c82055c337135df.nca");
    let nca = std::fs::File::open(file_path)?;

    let filename = file_path.file_name().unwrap().to_str().unwrap();
    println!("Decrypting NCA: {}", filename);

    let mut reader = std::io::BufReader::new(nca);

    // Let's try and decrypt the header first.
    let mut buf = vec![0; 0xC00];
    reader.read_exact(&mut buf)?;

    let decrypted = decrypt_with_header_key(&buf, &keyset, 0x200, 0);

    // take the 0x340 bytes for the header
    let header_bytes = &decrypted[..0x340];
    let remaining = &decrypted[0x340..];

    // dump remaining bytes into a file
    let mut remaining_file = std::fs::File::create(format!("test_tmp/{filename}_remaining.bin"))?;

    // dump remaining
    std::io::Write::write_all(&mut remaining_file, remaining)?;

    let header = NcaHeader::from_bytes(&header_bytes.try_into().unwrap())?;

    println!("{:?}", header);
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

    #[test]
    fn test_nca_header_size() {
        let header = NcaHeader {
            header_sig: vec![],
            header_key_sig: vec![],
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
            _reserved: vec![],
            rights_id: vec![],
            fs_entries: vec![],
            sha256_hashes: vec![],
            encrypted_keys: vec![],
        };
        // assert_eq!(std::mem::size_of_val(&header), 0x340);
        // now serialize to bytes
        let header_bytes = header.to_bytes();
        assert_eq!(header_bytes.len(), 0x340);
    }

    #[test]
    fn test_header_magic() {
        // let magic = [b'N', b'C', b'A', 0];
        let header = NcaHeader {
            header_sig: vec![0; 0x100],
            header_key_sig: vec![0; 0x100],
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
            encrypted_keys: vec![],
        };
        let header_bytes = header.to_bytes();
        assert_eq!(&header_bytes[0x200..0x204], b"NCA3");
    }

    #[test]
    fn test_header_enc_dec() {
        let header = NcaHeader {
            header_sig: vec![0; 0x100],
            header_key_sig: vec![0; 0x100],
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
            encrypted_keys: vec![],
        };

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

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit, typenum};
use aes::{Aes128, Aes256};
use binrw::prelude::*;
use std::io::{Read, Seek};
use xts_mode::Xts128;

use super::Keyset;
use super::keyset::get_nintendo_tweak;

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

/// Standard XTS tweak for comparison
pub fn get_standard_tweak(sector: u128) -> GenericArray<u8, typenum::U16> {
    // Create a zero-initialized array
    let mut tweak = [0u8; 16];
    let bytes = sector.to_le_bytes();
    // let default_tweak = get_tweak_default(sector);
    // tweak.copy_from_slice(&default_tweak);

    // For standard tweak, place bytes at the end
    let mut count = 0;
    for i in 0..bytes.len() {
        if bytes[i] != 0 {
            count = i + 1;
        }
    }

    for i in 0..count {
        tweak[16 - count + i] = bytes[i];
    }

    *GenericArray::from_slice(&tweak)
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
    pub nca_version: u8,
    pub distribution: u8,
    pub content_type: u8,
    pub key_generation_old: u8,
    pub key_area_appkey_index: u8,
    pub content_size: u64,
    pub program_id: u64,
    pub content_index: u32,
    pub sdk_version: u32,
    pub key_generation: u8,
    pub signature_key_generation: u8,
    // 0xe
    #[br(count = 0xE)]
    #[brw(pad_size_to = 0xE)]
    pub _reserved: Vec<u8>,
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
    pub fn decrypt<R: Read + Seek>(
        reader: &mut R,
        keyset: &Keyset,
    ) -> Result<Vec<u8>, binrw::Error> {
        // Read the entire 0xC00 header (NCA header + section headers)
        let mut encrypted = vec![0; 0xC00];
        reader.seek(std::io::SeekFrom::Start(0))?;
        reader.read_exact(&mut encrypted)?;

        let mut decrypted = encrypted.clone();

        // Set up XTS decryption with the header key
        // let key = &keyset.header_key;
        // let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..0x10]));
        // let cipher_2 = Aes128::new(GenericArray::from_slice(&key[0x10..]));
        // let xts = Xts128::new(cipher_1, cipher_2);

        let xts = keyset.header_crypt();
        // Decrypt all sectors (0x200 bytes each)
        let sector_size = 0x200;
        let first_sector_index = 0;
        xts.decrypt_area(&mut decrypted, sector_size, first_sector_index, |sector| {
            get_nintendo_tweak(sector)
        });

        Ok(decrypted)
    }

    /// Takes an already-decrypted NCA header and parses it
    pub fn from_reader_decrypted<R: Read + Seek>(reader: &mut R) -> Result<Self, binrw::Error> {
        let mut decrypted = vec![0; 0xC00];
        reader.read_exact(&mut decrypted)?;
        let header: NcaHeader = binrw::io::Cursor::new(&decrypted).read_le()?;
        Ok(header)
    }

    /// Takes a still-encrypted NCA header and decrypts it before parsing
    pub fn from_reader<R: Read + Seek>(
        reader: &mut R,
        keyset: &Keyset,
    ) -> Result<Self, binrw::Error> {
        let decrypted = Self::decrypt(reader, keyset)?;
        let header: NcaHeader = binrw::io::Cursor::new(&decrypted).read_le()?;
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

// #[test]
// pub fn decrypt_nca_header() -> color_eyre::Result<()> {
//     use aes::Aes128;
//     use aes::cipher::typenum::U16;
//     let keyset = Keyset::from_file("prod.keys")?;

//     let mut nca = std::fs::File::open("test/Browser/cf03cf6a80796869775f77e0c61e136e.cnmt.nca")?;

//     let mut reader = std::io::BufReader::new(nca);

//     let key = keyset.header_key;

//     // take 0xC00
//     let mut header = vec![0; 0xC00];
//     reader.read_exact(&mut header)?;

//     // The first 0xC00 bytes are encrypted with AES-XTS with sector size 0x200 with a non-standard "tweak"
//     let mut decrypted = vec![0; 0xC00];
//     let mut encrypted = vec![0; 0xC00];
//     encrypted.copy_from_slice(&header);
//     decrypted.copy_from_slice(&header);

//     let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..0x10]));
//     let cipher_2 = Aes128::new(GenericArray::from_slice(&key[0x10..]));

//     let xts: Xts128<Aes128> = Xts128::new(cipher_1, cipher_2);

//     let sector_size = 0x200;
//     let first_sector_index = 0;
//     xts.decrypt_area(&mut decrypted, sector_size, first_sector_index, |sector| {
//         get_nintendo_tweak(sector).into()
//     });

//     // dump to file for debugging
//     std::fs::write("decrypted_header.bin", &decrypted)?;

//     let header: NcaHeader = binrw::io::Cursor::new(&decrypted).read_be()?;

//     println!("{:#?}", header);

//     // Check if the magic starts with b"NCA"
//     // assert_eq!(&header.magic[0..3], b"NCA");

//     Ok(())
// }

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
    fn test_header_magic() {
        // let magic = [b'N', b'C', b'A', 0];
        let header = NcaHeader {
            header_sig: vec![0; 0x100],
            header_key_sig: vec![0; 0x100],
            nca_version: b'3',
            distribution: 0,
            content_type: 0,
            key_generation_old: 0,
            key_area_appkey_index: 0,
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
        assert_eq!(header.nca_version, b'3');
        println!("{:#?}", header.nca_version);
    }

    #[test]
    fn test_header_enc_dec() {
        let header = NcaHeader {
            header_sig: vec![0; 0x100],
            header_key_sig: vec![0; 0x100],
            nca_version: b'3',
            distribution: 0,
            content_type: 0,
            key_generation_old: 0,
            key_area_appkey_index: 0,
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

        let keyset = Keyset {
            header_key: [9; 32],
            ..Default::default()
        };

        let encrypted = header.to_bytes_encrypt(&keyset);

        assert_ne!(encrypted, header_bytes);

        // Check if the first 0xC00 bytes are encrypted
        assert_ne!(encrypted[..0xC00], header.to_bytes());

        let mut cursor = std::io::Cursor::new(encrypted.clone());
        let decrypted = NcaHeader::from_reader(&mut cursor, &keyset).unwrap();
        assert_eq!(
            decrypted.nca_version, header.nca_version,
            "Decrypted version should match the original"
        );

        let decrypted_bytes = decrypted.to_bytes();

        assert_eq!(decrypted_bytes.len(), header_bytes.len());

        // Now let's try a different header key and see if it fails
        let keyset_2 = Keyset {
            header_key: [0; 32],
            ..Default::default()
        };

        let mut cursor = std::io::Cursor::new(encrypted);

        // let result = NcaHeader::from_reader(&mut cursor, &keyset_2);
        // Try to decrypt with the wrong key and print the error
        let result = NcaHeader::from_reader(&mut cursor, &keyset_2);
        println!("Decryption with bad key result: {:?}", result);
        assert!(
            result.is_err(),
            "Decryption should fail with an incorrect keyset"
        );
    }
}

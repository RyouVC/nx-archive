//! The Nintendo Hashed filesystem (HFS0) is a filesystem used by the Nintendo Switch to store data in a hashed format.
//! This filesystem is used in the Nintendo Switch's game cards (the little bitter carts that you insert physically into the console).
//!
//! This module doesn't allow you to eat the game itself, but lets you dump data
//! from the game card.
//!
//! You still require the XCI module to read the game card image format, which in turn contains this filesystem.
//! For the game card image format, see [xci](crate::formats::xci).

use binrw::prelude::*;
use std::io::{Read, Seek, SeekFrom};

use crate::{FileEntryExt, io::SubFile};

/// Nintendo Switch HFS0 (Hashed File System 0) header structure
///
/// This header is located at the beginning of an HFS0 archive file and contains:
/// - A magic identifier "HFS0" (validated by binrw)
///
/// The "SHA-256 File System" or "HFS0" starts at offset 0x10000 in the Gamecard.
/// The first 0x200 bytes act as a global header and
/// represent the root partition which points to the other partitions
/// ("normal", "logo", "update" and "secure").
#[derive(Debug)]
#[binrw]
#[brw(little, magic = b"HFS0")]
pub struct Hfs0Header {
    // magic field is handled by binrw using the magic attribute
    pub file_count: u32,
    pub string_table_size: u32,
    pub _reserved: u32,
    #[br(count = file_count)]
    pub file_entries: Vec<Hfs0Entry>,
    /// String table - 00-padded to align the start of raw filedata with a sector/media unit boundary
    #[br(pad_size_to = string_table_size)]
    #[br(count = string_table_size)]
    pub string_table: Vec<u8>,
    // the rest is raw file data, which is not parsed by this struct
    // due to memory constraints

    // We will seek and read as needed
}

#[derive(Debug)]
#[binrw]
#[brw(little)]
pub struct Hfs0Entry {
    /// Offset of the file in data
    pub offset: u64,
    /// File size
    pub size: u64,
    /// Offset of filename in string table
    pub filename_offset: u32,
    /// Size of hashed region of file
    /// (for HFS0s, this is the size of the pre-filedata portion,
    /// for NCAs this is usually 0x200)
    pub hashed_region_size: u32,
    /// Reserved field
    pub _reserved: u64,
    /// SHA-256 hash of the first (size of hashed region) bytes of filedata
    pub sha256: [u8; 0x20],
}

#[derive(Debug)]
pub struct Hfs0File {
    pub name: String,
    pub size: u64,
    /// Offset of the start of the file in the HFS0
    ///
    /// In our case, this offset is absolute to the start of the HFS0 file.
    pub offset: u64,
    pub hash: [u8; 0x20],
}

#[derive(Debug)]
pub struct Hfs0<R: Read + Seek> {
    pub header: Hfs0Header,
    pub reader: R,
}

impl<R: Read + Seek> Hfs0<R> {
    pub fn new(mut reader: R) -> BinResult<Self> {
        let header = Hfs0Header::read(&mut reader)?;

        Ok(Self { header, reader })
    }

    /// Reads the file data into a vector of bytes
    ///
    /// Previously known as `list_files`, which is ironically a misnomer
    pub fn read_to_vec(&mut self, file: &Hfs0File) -> Result<Vec<u8>, std::io::Error> {
        self.reader.seek(SeekFrom::Start(file.offset))?;
        let mut data = vec![0; file.size as usize];
        self.reader.read_exact(&mut data)?;
        Ok(data)
    }

    pub fn read_to_buf(&mut self, file: &Hfs0File, buf: &mut [u8]) -> Result<(), std::io::Error> {
        self.reader.seek(SeekFrom::Start(file.offset))?;
        self.reader.read_exact(buf)?;
        Ok(())
    }

    pub fn subfile(&mut self, file: &Hfs0File) -> SubFile<R>
    where
        R: Clone,
    {
        SubFile::new(self.reader.clone(), file.offset, file.offset + file.size)
    }

    pub fn get_files(&self) -> Vec<Hfs0File> {
        self.header
            .file_entries
            .iter()
            .map(|entry| {
                let filename_bytes = &self.header.string_table[entry.filename_offset as usize..];
                let end = filename_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(filename_bytes.len());
                let name = std::str::from_utf8(&filename_bytes[..end])
                    .unwrap()
                    .to_string();

                // Use the name we just extracted to call get_file()
                // Since we know the file exists, unwrap is safe here
                self.get_file(&name).unwrap()
            })
            .collect()
    }

    pub fn get_file(&self, name: &str) -> Option<Hfs0File> {
        // Calculate the header size: 16 bytes for the HFS0 header fields + file entries + string table
        let header_size = 16
            + (self.header.file_entries.len() * std::mem::size_of::<Hfs0Entry>())
            + self.header.string_table_size as usize;

        self.header.file_entries.iter().find_map(|entry| {
            let filename_bytes = &self.header.string_table[entry.filename_offset as usize..];
            let end = filename_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(filename_bytes.len());
            let entry_name = std::str::from_utf8(&filename_bytes[..end])
                .unwrap()
                .to_string();

            if entry_name == name {
                Some(Hfs0File {
                    name: entry_name,
                    size: entry.size,
                    // Add header size to the offset to get the absolute file position
                    offset: entry.offset + header_size as u64,
                    hash: entry.sha256,
                })
            } else {
                None
            }
        })
    }
}

impl<R: Read + Seek> FileEntryExt<R> for Hfs0File {
    fn file_reader(&self, reader: R) -> Result<SubFile<R>, crate::error::Error> {
        Ok(SubFile::new(reader, self.offset, self.offset + self.size))
    }

    fn file_size(&self) -> u64 {
        self.size
    }

    fn read_bytes(&self, reader: R, size: usize) -> Result<Vec<u8>, crate::error::Error> {
        let mut buf = vec![0; size];
        let mut reader = reader;
        reader.seek(SeekFrom::Start(self.offset))?;
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
    fn file_name(&self) -> String {
        self.name.clone()
    }
}

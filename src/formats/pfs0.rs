//! # Nintendo PFS0 (PartitionFS0) format
//!
//! The Partition File System (PFS0) format is a simple archive format used by Nintendo Switch for packaging files.
//!
//! They are also known as NSP (Nintendo Submission Package) files, which are simply PFS0 images packed
//! for distribution.
//!
//! These files are used to store nested game archives, such as NCA files, which contain the actual game data.
//!
//! They also usually install cryptographic tickets and metadata files, which are used to identify and
//! enforce DRM restrictions on the game.
//!

use std::io::{Read, Seek, SeekFrom};

use binrw::prelude::*;

use crate::io::SubFile;

// Type alias for NSP (Nintendo Submission Package), which are simply just
// PFS0 images
pub type Nsp<R> = Pfs0<R>;
pub type NspHeader = Pfs0Header;
pub type NspEntry = Pfs0Entry;

#[derive(BinRead, Debug)]
#[brw(little, magic = b"PFS0")]
/// Nintendo Switch PFS0 (PartitionFS0) header structure
///
/// This header is located at the beginning of a PFS0 archive file and contains:
/// - A magic identifier "PFS0" (validated by binrw)
/// - Information about the file entries and string table
///
/// # Format Layout
/// - 0x00: Magic "PFS0" (4 bytes)
/// - 0x04: Number of files (4 bytes)
/// - 0x08: String table size (4 bytes)
/// - 0x0C: Reserved (4 bytes, usually zeros)
pub struct Pfs0Header {
    // magic field is handled by binrw using the magic attribute
    /// Number of files contained in this PFS0 archive
    pub num_files: u32,
    /// Size of the string table in bytes
    pub str_table_offset: u32,
    /// Reserved field, typically set to zeros
    pub reserved: [u8; 4],
}

impl Pfs0Header {
    /// Magic identifier for PFS0 files
    pub const MAGIC: [u8; 4] = *b"PFS0";
}

#[derive(BinRead, Debug)]
#[brw(little)]
/// The PFS0 file entry structure describes a single file within the archive
///
/// # Format Layout
/// - 0x00: Data offset (8 bytes)
/// - 0x08: Data size (8 bytes)
/// - 0x10: String table offset (4 bytes)
/// - 0x14: Reserved (4 bytes)
///
/// # Notes
/// - `data_offset` is relative to the start of file data section, not the start of the PFS0 file
/// - The file data section begins after the header, all file entries, and the string table
/// - String table offset points to a null-terminated filename in the string table
/// - The reserved field is typically set to zeros
pub struct Pfs0Entry {
    /// Offset to file data, relative to the start of file data section
    pub data_offset: u64,
    /// Size of the file data in bytes
    pub data_size: u64,
    /// Offset into the string table for the null-terminated filename
    pub string_table_offset: u32,
    /// Reserved field, usually zeroes
    pub reserved: [u8; 4],
}

impl Pfs0Entry {
    /// Extract the filename from the string table
    ///
    /// # Arguments
    /// * `string_table` - The full string table from the PFS0 archive
    ///
    /// # Returns
    /// * `Result<String, std::str::Utf8Error>` - The filename as a String if successful
    ///
    /// # Notes
    /// - Filenames are stored as null-terminated UTF-8 strings in the string table
    /// - If no null terminator is found, it will use the entire remainder of the string table
    pub fn get_name(&self, string_table: &[u8]) -> Result<String, std::str::Utf8Error> {
        let name_start = self.string_table_offset as usize;
        let name_end = string_table[name_start..]
            .iter()
            .position(|&x| x == 0)
            .map(|p| name_start + p)
            .unwrap_or(string_table.len());

        let name = std::str::from_utf8(&string_table[name_start..name_end])?.to_string();
        Ok(name)
    }
}

#[derive(Debug)]
/// Represents a file within the PFS0 archive with both metadata and name
pub struct Pfs0File {
    /// Filename extracted from the string table
    pub name: String,
    /// File entry metadata including size and offset information
    pub entry: Pfs0Entry,
}

/// Main structure for working with Nintendo Switch PFS0 archives
///
/// PFS0 is a simple archive format used by Nintendo Switch for packaging files.
/// The format consists of:
/// 1. Header (0x10 bytes)
/// 2. File entries (0x18 bytes each)
/// 3. String table (variable size)
/// 4. File data (aligned and sequentially stored)
pub struct Pfs0<R: Read + Seek> {
    /// The underlying reader for the PFS0 archive
    pub reader: R,
    /// Parsed header information
    pub header: Pfs0Header,
    /// List of files contained in the archive with their metadata
    pub files: Vec<Pfs0File>,
}

impl<R: Read + Seek> Pfs0<R> {
    /// Create a new PFS0 parser from a reader
    ///
    /// # Arguments
    /// * `reader` - Any source that implements Read + Seek
    ///
    /// # Returns
    /// * `Result<Self, Box<dyn std::error::Error>>` - A parsed PFS0 structure or an error
    ///
    /// # Notes
    /// - The magic "PFS0" is automatically validated by binrw
    /// - This function reads the header, all file entries, and the string table
    pub fn new(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        let header: Pfs0Header = reader.read_le()?;
        // Magic validation is handled by binrw via the magic attribute
        println!("PFS0 Header: {:?}", header);

        // Read all file entries
        let entries = (0..header.num_files)
            .map(|_| reader.read_le::<Pfs0Entry>())
            .collect::<Result<Vec<_>, _>>()?;

        // Read the entire string table
        let mut string_table = vec![0u8; header.str_table_offset as usize];
        reader.read_exact(&mut string_table)?;

        // Create file entries with resolved names
        let mut files = Vec::with_capacity(entries.len());
        for entry in entries.into_iter() {
            let name = entry.get_name(&string_table).unwrap();
            files.push(Pfs0File { name, entry });
        }

        Ok(Self {
            reader,
            header,
            files,
        })
    }

    /// Extract a file from the PFS0 archive by its path/name
    ///
    /// # Arguments
    /// * `vpath` - The filename to extract
    ///
    /// # Returns
    /// * `Result<Vec<u8>, crate::error::Error>` - The file contents or an error
    ///
    /// # Notes
    /// - Files are extracted in chunks to avoid excessive memory usage
    /// - The file offset calculation accounts for the PFS0 header, entries, and string table
    pub fn read_file(&mut self, vpath: &str) -> Result<Vec<u8>, crate::error::Error> {
        let file =
            self.files
                .iter()
                .find(|f| f.name == vpath)
                .ok_or(crate::error::Error::NotFound(format!(
                    "File not found: {}",
                    vpath
                )))?;
        let file_data_offset = file.entry.data_offset;
        let size = file.entry.data_size as usize;

        // Calculate actual file offset in the container
        // This is: header (0x10) + all entries (0x18 * num_files) + string table size
        let files_start_offset =
            0x10 + (0x18 * self.header.num_files as u64) + (self.header.str_table_offset as u64);
        let offset = files_start_offset + file_data_offset;

        tracing::trace!(
            ?vpath,
            offset = format!("{:012X}", offset),
            actual_offset = format!("{:012X}", offset + size as u64),
            "Dumping included file"
        );

        self.reader.seek(SeekFrom::Start(offset))?;

        // Read the file data in chunks to avoid excessive memory usage
        let mut data = Vec::with_capacity(size);
        let mut ofs = 0;
        let chunk_size = 0x800000; // 8MB chunks

        while ofs < size {
            let sz = if size - ofs < chunk_size {
                size - ofs
            } else {
                chunk_size
            };

            let mut buffer = vec![0u8; sz];
            self.reader.read_exact(&mut buffer)?;
            data.extend_from_slice(&buffer);
            ofs += sz;
        }

        println!("Dumped!");
        Ok(data)
    }

    pub fn return_reader_file(&mut self, vpath: &str) -> Result<SubFile<R>, crate::error::Error>
    where
        R: Clone,
    {
        let file =
            self.files
                .iter()
                .find(|f| f.name == vpath)
                .ok_or(crate::error::Error::NotFound(format!(
                    "File not found: {}",
                    vpath
                )))?;
        let file_data_offset = file.entry.data_offset;
        let size = file.entry.data_size;

        // Calculate actual file offset in the container
        // This is: header (0x10) + all entries (0x18 * num_files) + string table size
        let files_start_offset =
            0x10 + (0x18 * self.header.num_files as u64) + (self.header.str_table_offset as u64);
        let offset = files_start_offset + file_data_offset;

        tracing::trace!(
            ?vpath,
            offset = format!("{:012X}", offset),
            actual_offset = format!("{:012X}", offset + size as u64),
            "Dumping included file"
        );

        // Clone the reader to provide an owned value to SubFile::new
        let reader_clone = self.reader.clone();

        Ok(SubFile::new(reader_clone, offset, offset + size))
    }

    pub fn list_files(&self) -> Result<Vec<String>, crate::error::Error> {
        let files = self.files.iter().map(|f| f.name.clone()).collect();
        Ok(files)
    }


    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tracing_test::traced_test;
    #[test]
    #[traced_test]
    fn test_pfs0_reader() {
        let file = include_bytes!("../../test/Browser.nsp");
        let cursor = std::io::Cursor::new(&file[..]);
        let mut pfs0 = Pfs0::new(cursor).unwrap();

        println!("{:?}", pfs0.files);

        let vpath = "2b9b99ea58139c320c82055c337135df.nca";
        // Use a string literal for include_bytes!
        let fixture_data =
            include_bytes!("../../test/Browser/2b9b99ea58139c320c82055c337135df.nca");
        let data = pfs0.read_file(vpath).unwrap();
        println!("Data length: {}", data.len());
        // write to file
        std::fs::write("test_tmp/output.nca", &data).expect("Failed to write file");
        assert_eq!(data.len(), fixture_data.len());
        assert_eq!(data, fixture_data);
    }
}

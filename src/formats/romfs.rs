use binrw::{BinRead, BinReaderExt, BinResult};
use std::collections::HashMap;
use std::io::{Read, Result as IoResult, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// use crate::error::Error;
use crate::io::SharedReader;

/// Custom error type for RomFS operations
#[derive(Debug, thiserror::Error)]
pub enum RomFsError {
    #[error("Invalid RomFS header: {0}")]
    InvalidHeader(String),

    #[error("Failed to read RomFS: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse data: {0}")]
    ParseError(#[from] binrw::Error),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Directory not found: {0}")]
    DirNotFound(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Other error: {0}")]
    Other(String),
}

// impl From<RomFsError> for Box<dyn std::error::Error> {
//     fn from(err: RomFsError) -> Self {
//         Box::new(err)
//     }
// }

/// RomFS header structure
#[derive(Debug, Clone, BinRead)]
#[br(little)]
pub struct RomFsHeader {
    pub header_size: u32,
    pub dir_hash_table_offset: u64,
    pub dir_hash_table_size: u32,
    pub dir_table_offset: u64,
    pub dir_table_size: u32,
    pub file_hash_table_offset: u64,
    pub file_hash_table_size: u32,
    pub file_table_offset: u64,
    pub file_table_size: u32,
    pub file_data_offset: u64,
}

/// Directory entry structure
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub parent_offset: u32,
    pub sibling_offset: u32,
    pub child_dir_offset: u32,
    pub child_file_offset: u32,
    pub hash_sibling_offset: u32,
    pub name_size: u32,
    pub name: String,
}

/// File entry structure
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub parent_offset: u32,
    pub sibling_offset: u32,
    pub data_offset: u64,
    pub data_size: u64,
    pub hash_sibling_offset: u32,
    pub name_size: u32,
    pub name: String,
}

/// A RomFS directory iterator
pub struct RomFsDirectoryIterator<R: Read + Seek> {
    romfs: Arc<Mutex<RomFs<R>>>,
    dir_offsets: Vec<u32>,
    file_offsets: Vec<u32>,
    current_dir_index: usize,
    current_file_index: usize,
}

impl<R: Read + Seek> RomFsDirectoryIterator<R> {
    /// Returns the next directory name or None if there are no more directories
    pub fn next_dir(&mut self) -> Option<Result<String, Box<dyn std::error::Error>>> {
        if self.current_dir_index >= self.dir_offsets.len() {
            return None;
        }

        let mut romfs = self.romfs.lock().unwrap();
        let result = match romfs.read_dir_entry(self.dir_offsets[self.current_dir_index]) {
            Ok(dir) => Ok(dir.name),
            Err(e) => Err(e),
        };

        self.current_dir_index += 1;
        Some(result)
    }

    /// Returns the next file name and size or None if there are no more files
    pub fn next_file(&mut self) -> Option<Result<(String, u64), Box<dyn std::error::Error>>> {
        if self.current_file_index >= self.file_offsets.len() {
            return None;
        }

        let mut romfs = self.romfs.lock().unwrap();
        let result = match romfs.read_file_entry(self.file_offsets[self.current_file_index]) {
            Ok(file) => Ok((file.name, file.data_size)),
            Err(e) => Err(e),
        };

        self.current_file_index += 1;
        Some(result)
    }

    /// Reset the directory iterator to the beginning
    pub fn rewind(&mut self) {
        self.current_dir_index = 0;
        self.current_file_index = 0;
    }

    /// Returns the number of directories in this iterator
    pub fn dir_count(&self) -> usize {
        self.dir_offsets.len()
    }

    /// Returns the number of files in this iterator
    pub fn file_count(&self) -> usize {
        self.file_offsets.len()
    }
}

#[derive(Debug)]
/// RomFS representation
pub struct RomFs<R: Read + Seek> {
    reader: R,
    header: RomFsHeader,
    dir_hash_table: Vec<u32>,
    file_hash_table: Vec<u32>,
    cache_dir_entries: HashMap<u32, DirectoryEntry>,
    cache_file_entries: HashMap<u32, FileEntry>,
}

impl<R: Read + Seek> RomFs<R> {
    /// Magic value for invalid entry offsets
    pub const INVALID_ENTRY: u32 = u32::MAX;
    /// Offset of the root directory
    pub const ROOT_DIR_OFFSET: u32 = 0;
    /// Maximum reasonable header size (to prevent excessive allocations)
    const MAX_REASONABLE_HEADER_SIZE: u32 = 0x10000000; // 256MB
    /// Maximum reasonable table size (to prevent excessive allocations)
    const MAX_REASONABLE_TABLE_SIZE: u32 = 0x10000000; // 256MB

    /// Create a new RomFS reader from a reader
    pub fn new(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        // Read and dump the first 64 bytes for debugging
        let mut preview = [0u8; 64];
        let reader_clone = &mut reader;
        reader_clone.seek(SeekFrom::Start(0))?;
        let bytes_read = reader_clone.read(&mut preview)?;
        tracing::trace!(
            preview_hex = %hex::encode(&preview[..bytes_read]),
            "First {} bytes of RomFS data", bytes_read
        );

        // Reset position for actual parsing
        reader.seek(SeekFrom::Start(0))?;

        // Read the header
        let header: RomFsHeader = match reader.read_le() {
            Ok(h) => h,
            Err(e) => {
                return Err(RomFsError::InvalidHeader(format!(
                    "Failed to parse RomFS header: {}",
                    e
                ))
                .into());
            }
        };

        tracing::trace!(
            header_size = header.header_size,
            dir_hash_table_offset = header.dir_hash_table_offset,
            dir_hash_table_size = header.dir_hash_table_size,
            dir_table_offset = header.dir_table_offset,
            dir_table_size = header.dir_table_size,
            file_hash_table_offset = header.file_hash_table_offset,
            file_hash_table_size = header.file_hash_table_size,
            file_table_offset = header.file_table_offset,
            file_table_size = header.file_table_size,
            file_data_offset = header.file_data_offset,
            "RomFS header parsed"
        );

        // Validate header values to avoid security issues with large allocations
        if header.header_size == 0 || header.header_size > Self::MAX_REASONABLE_HEADER_SIZE {
            return Err(RomFsError::InvalidHeader(format!(
                "Invalid header size: {}",
                header.header_size
            ))
            .into());
        }

        if header.dir_hash_table_size > Self::MAX_REASONABLE_TABLE_SIZE {
            return Err(RomFsError::InvalidHeader(format!(
                "Dir hash table too large: {}",
                header.dir_hash_table_size
            ))
            .into());
        }

        if header.file_hash_table_size > Self::MAX_REASONABLE_TABLE_SIZE {
            return Err(RomFsError::InvalidHeader(format!(
                "File hash table too large: {}",
                header.file_hash_table_size
            ))
            .into());
        }

        // Validate hash table offsets are within reasonable bounds
        if header.dir_hash_table_offset == 0 {
            return Err(
                RomFsError::InvalidHeader("Directory hash table offset is 0".into()).into(),
            );
        }

        if header.file_hash_table_offset == 0 {
            return Err(RomFsError::InvalidHeader("File hash table offset is 0".into()).into());
        }

        // Read the directory hash table
        reader.seek(SeekFrom::Start(header.dir_hash_table_offset))?;
        let dir_hash_count = header.dir_hash_table_size as usize / std::mem::size_of::<u32>();

        tracing::trace!(
            dir_hash_count = dir_hash_count,
            "Reading directory hash table"
        );

        let mut dir_hash_table = vec![0u32; dir_hash_count];
        for entry in dir_hash_table.iter_mut() {
            match reader.read_le() {
                Ok(hash) => *entry = hash,
                Err(e) => return Err(RomFsError::ParseError(e).into()),
            }
        }

        // Read the file hash table
        reader.seek(SeekFrom::Start(header.file_hash_table_offset))?;
        let file_hash_count = header.file_hash_table_size as usize / std::mem::size_of::<u32>();

        tracing::trace!(file_hash_count = file_hash_count, "Reading file hash table");

        let mut file_hash_table = vec![0u32; file_hash_count];
        for entry in file_hash_table.iter_mut() {
            match reader.read_le() {
                Ok(hash) => *entry = hash,
                Err(e) => return Err(RomFsError::ParseError(e).into()),
            }
        }

        Ok(Self {
            reader,
            header,
            dir_hash_table,
            file_hash_table,
            cache_dir_entries: HashMap::new(),
            cache_file_entries: HashMap::new(),
        })
    }

    /// Compute a hash for a given parent offset and name
    fn compute_hash(&self, parent: u32, name: &[u8], table_size: usize) -> u32 {
        let mut hash = parent ^ 123456789;
        for &b in name {
            hash = hash.rotate_right(5);
            hash ^= b as u32;
        }
        hash % (table_size as u32)
    }

    pub fn list_files(&mut self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut files = Vec::new();

        for offset in 0..self.file_hash_table.len() {
            if let Ok(file) = self.read_file_entry(offset as u32) {
                files.push(file.name)
            }
        }

        Ok(files)
    }

    /// Read a directory entry from the directory table
    fn read_dir_entry(
        &mut self,
        offset: u32,
    ) -> Result<DirectoryEntry, Box<dyn std::error::Error>> {
        // Check the cache first
        if let Some(entry) = self.cache_dir_entries.get(&offset) {
            return Ok(entry.clone());
        }

        // If not in cache, read from file
        let mut reader = &mut self.reader;
        reader.seek(SeekFrom::Start(
            self.header.dir_table_offset + offset as u64,
        ))?;

        let parent_offset: u32 = reader.read_le()?;
        let sibling_offset: u32 = reader.read_le()?;
        let child_dir_offset: u32 = reader.read_le()?;
        let child_file_offset: u32 = reader.read_le()?;
        let hash_sibling_offset: u32 = reader.read_le()?;
        let name_size: u32 = reader.read_le()?;

        let mut name_bytes = vec![0u8; name_size as usize];
        reader.read_exact(&mut name_bytes)?;

        let name = String::from_utf8(name_bytes)?;

        Ok(DirectoryEntry {
            parent_offset,
            sibling_offset,
            child_dir_offset,
            child_file_offset,
            hash_sibling_offset,
            name_size,
            name,
        })
    }

    /// Read a file entry from the file table
    fn read_file_entry(&mut self, offset: u32) -> Result<FileEntry, Box<dyn std::error::Error>> {
        // Check the cache first
        if let Some(entry) = self.cache_file_entries.get(&offset) {
            return Ok(entry.clone());
        }

        // If not in cache, read from file
        let mut reader = &mut self.reader;
        reader.seek(SeekFrom::Start(
            self.header.file_table_offset + offset as u64,
        ))?;

        let parent_offset: u32 = reader.read_le()?;
        let sibling_offset: u32 = reader.read_le()?;
        let data_offset: u64 = reader.read_le()?;
        let data_size: u64 = reader.read_le()?;
        let hash_sibling_offset: u32 = reader.read_le()?;
        let name_size: u32 = reader.read_le()?;

        let mut name_bytes = vec![0u8; name_size as usize];
        reader.read_exact(&mut name_bytes)?;

        let name = String::from_utf8(name_bytes)?;

        Ok(FileEntry {
            parent_offset,
            sibling_offset,
            data_offset,
            data_size,
            hash_sibling_offset,
            name_size,
            name,
        })
    }

    /// Find a directory by its path
    pub fn find_dir(&mut self, path: &str) -> Result<u32, Box<dyn std::error::Error>> {
        let path_parts: Vec<_> = path.split('/').filter(|p| !p.is_empty()).collect();

        let mut current_dir = Self::ROOT_DIR_OFFSET;
        for part in path_parts {
            match self.find_dir_in_parent(current_dir, part) {
                Ok(dir) => current_dir = dir,
                Err(e) => {
                    return Err(RomFsError::DirNotFound(format!(
                        "Could not find directory '{}': {}",
                        part, e
                    ))
                    .into());
                }
            }
        }

        Ok(current_dir)
    }

    /// Find a directory within a parent directory by name
    fn find_dir_in_parent(
        &mut self,
        parent_offset: u32,
        name: &str,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let hash = self.compute_hash(parent_offset, name.as_bytes(), self.dir_hash_table.len());

        let mut current_offset = self.dir_hash_table[hash as usize];
        while current_offset != Self::INVALID_ENTRY {
            let entry = self.read_dir_entry(current_offset)?;
            if entry.parent_offset == parent_offset && entry.name == name {
                return Ok(current_offset);
            }
            current_offset = entry.hash_sibling_offset;
        }

        Err("Directory not found".into())
    }

    /// Find a file by its path
    pub fn find_file(&mut self, path: &str) -> Result<FileEntry, Box<dyn std::error::Error>> {
        let mut path_buf = PathBuf::from(path);
        let file_name = path_buf
            .file_name()
            .ok_or_else(|| RomFsError::InvalidPath(format!("Invalid path: {}", path)))?
            .to_string_lossy()
            .to_string();

        path_buf.pop();
        let parent_path = path_buf.to_string_lossy().to_string();

        match self.find_dir(&parent_path) {
            Ok(parent_offset) => self.find_file_in_dir(parent_offset, &file_name),
            Err(e) => Err(RomFsError::FileNotFound(format!(
                "Could not find parent directory for file '{}': {}",
                path, e
            ))
            .into()),
        }
    }

    /// Find a file within a parent directory by name
    fn find_file_in_dir(
        &mut self,
        parent_offset: u32,
        name: &str,
    ) -> Result<FileEntry, Box<dyn std::error::Error>> {
        let hash = self.compute_hash(parent_offset, name.as_bytes(), self.file_hash_table.len());

        let mut current_offset = self.file_hash_table[hash as usize];
        while current_offset != Self::INVALID_ENTRY {
            let entry = self.read_file_entry(current_offset)?;
            if entry.parent_offset == parent_offset && entry.name == name {
                return Ok(entry);
            }
            current_offset = entry.hash_sibling_offset;
        }

        Err("File not found".into())
    }

    /// Check if a file exists by path
    pub fn file_exists(&mut self, path: &str) -> bool {
        self.find_file(path).is_ok()
    }

    /// Check if a directory exists by path
    pub fn dir_exists(&mut self, path: &str) -> bool {
        self.find_dir(path).is_ok()
    }

    /// Get the size of a file by path
    pub fn get_file_size(&mut self, path: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let file = self.find_file(path)?;
        Ok(file.data_size)
    }

    /// Extract a file from the RomFS
    pub fn extract_file(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let file = self.find_file(path)?;

        tracing::info!("Extracting file: {} (size: {})", path, file.data_size);

        let offset = self.header.file_data_offset + file.data_offset;
        let size = file.data_size as usize;

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
            match self.reader.read_exact(&mut buffer) {
                Ok(_) => data.extend_from_slice(&buffer),
                Err(e) => return Err(RomFsError::IoError(e).into()),
            }
            ofs += sz;
        }

        tracing::info!("Extraction complete!");
        Ok(data)
    }

    /// Open a directory iterator for browsing directories and files
    pub fn open_dir(
        &mut self,
        path: &str,
    ) -> Result<RomFsDirectoryIterator<R>, Box<dyn std::error::Error>>
    where
        Self: Clone,
        R: Clone,
    {
        let dir_offset = self.find_dir(path)?;
        let dir_entry = self.read_dir_entry(dir_offset)?;

        let mut dir_offsets = Vec::new();
        let mut current_child = dir_entry.child_dir_offset;

        while current_child != Self::INVALID_ENTRY {
            dir_offsets.push(current_child);
            let child_entry = self.read_dir_entry(current_child)?;
            current_child = child_entry.sibling_offset;
        }

        let mut file_offsets = Vec::new();
        let mut current_file = dir_entry.child_file_offset;

        while current_file != Self::INVALID_ENTRY {
            file_offsets.push(current_file);
            let file_entry = self.read_file_entry(current_file)?;
            current_file = file_entry.sibling_offset;
        }

        Ok(RomFsDirectoryIterator {
            romfs: Arc::new(Mutex::new(self.clone())),
            dir_offsets,
            file_offsets,
            current_dir_index: 0,
            current_file_index: 0,
        })
    }
}

impl<R: Read + Seek + Clone> Clone for RomFs<R> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            header: self.header.clone(),
            dir_hash_table: self.dir_hash_table.clone(),
            file_hash_table: self.file_hash_table.clone(),
            cache_dir_entries: self.cache_dir_entries.clone(),
            cache_file_entries: self.cache_file_entries.clone(),
        }
    }
}

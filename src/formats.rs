use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Seek, SeekFrom, Write};

pub const UNCOMPRESSABLE_HEADER_SIZE: usize = 0x4000;
pub const NCA_MEDIA_BLOCK_SIZE: u64 = 0x200;

#[derive(Debug, Clone)]
pub struct Section {
    pub offset: u64,
    pub size: u64,
    pub crypto_type: u64,
    pub crypto_key: [u8; 16],
    pub crypto_counter: [u8; 16],
}

impl Section {
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u64::<LittleEndian>(self.offset)?;
        writer.write_u64::<LittleEndian>(self.size)?;
        writer.write_u64::<LittleEndian>(self.crypto_type)?;
        writer.write_all(&[0u8; 8])?; // padding
        writer.write_all(&self.crypto_key)?;
        writer.write_all(&self.crypto_counter)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NczHeader {
    pub sections: Vec<Section>,
}

impl NczHeader {
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(b"NCZSECTN")?;
        writer.write_u64::<LittleEndian>(self.sections.len() as u64)?;
        for section in &self.sections {
            section.write(writer)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BlockHeader {
    pub version: u8,
    pub block_type: u8,
    pub block_size_exponent: u8,
    pub block_sizes: Vec<u32>,
    pub decompressed_size: u64,
}

impl BlockHeader {
    pub fn new(block_size: usize, decompressed_size: u64) -> Self {
        // Make sure block_size is a power of 2
        assert!(
            block_size & (block_size - 1) == 0,
            "Block size must be a power of 2"
        );

        Self {
            version: 2,
            block_type: 1, // Changed from 0 to 1 to match Python implementation
            block_size_exponent: block_size.trailing_zeros() as u8,
            block_sizes: Vec::new(),
            decompressed_size,
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(b"NCZBLOCK")?;
        writer.write_u8(self.version)?;
        writer.write_u8(self.block_type)?;
        writer.write_u8(0)?; // unused
        writer.write_u8(self.block_size_exponent)?;
        writer.write_u32::<LittleEndian>(self.block_sizes.len() as u32)?;
        writer.write_u64::<LittleEndian>(self.decompressed_size)?;

        for size in &self.block_sizes {
            writer.write_u32::<LittleEndian>(*size)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SectionTableEntry {
    pub media_offset: u32,
    pub media_end_offset: u32,
    pub offset: u64,
    pub end_offset: u64,
}

impl SectionTableEntry {
    pub fn new<R: Read>(reader: &mut R) -> Result<Self> {
        let media_offset = reader.read_u32::<LittleEndian>()?;
        let media_end_offset = reader.read_u32::<LittleEndian>()?;

        // Skip unknown values
        let _unknown1 = reader.read_u32::<LittleEndian>()?;
        let _unknown2 = reader.read_u32::<LittleEndian>()?;

        let offset = media_offset as u64 * NCA_MEDIA_BLOCK_SIZE;
        let end_offset = media_end_offset as u64 * NCA_MEDIA_BLOCK_SIZE;

        Ok(Self {
            media_offset,
            media_end_offset,
            offset,
            end_offset,
        })
    }
}

#[derive(Debug)]
pub struct NcaHeader {
    pub magic: [u8; 4],
    pub section_tables: Vec<SectionTableEntry>,
    pub crypto_type: u8,
    pub key_index: u8,
    pub crypto_type2: u8,
    pub rights_id: [u8; 16],
    pub crypto_key: [u8; 16],
}

impl NcaHeader {
    // Read the header from the first 0xC00 bytes of an NCA file
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        reader.seek(SeekFrom::Start(0x200))?;

        // Read magic
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        if &magic != b"NCA3" {
            return Err(anyhow::anyhow!("Invalid NCA magic: {:?}", magic));
        }

        // Read crypto types
        reader.seek(SeekFrom::Start(0x220))?;
        let crypto_type = reader.read_u8()?;
        let key_index = reader.read_u8()?;

        // Skip to rightsId
        reader.seek(SeekFrom::Start(0x230))?;
        let mut rights_id = [0u8; 16];
        reader.read_exact(&mut rights_id)?;

        // Read crypto type 2
        reader.seek(SeekFrom::Start(0x240))?;
        let crypto_type2 = reader.read_u8()?;

        // For simplicity, we use a placeholder for crypto key
        let crypto_key = [0u8; 16];

        // Parse section tables
        reader.seek(SeekFrom::Start(0x240))?;
        let mut section_tables = Vec::with_capacity(4);

        for _ in 0..4 {
            let table_data = SectionTableEntry::new(reader)?;
            if table_data.media_end_offset > table_data.media_offset {
                section_tables.push(table_data);
            }
        }

        Ok(Self {
            magic,
            section_tables,
            crypto_type,
            key_index,
            crypto_type2,
            rights_id,
            crypto_key,
        })
    }

    pub fn get_sections(&self) -> Vec<Section> {
        let mut sections = Vec::new();

        // First sort the sections by offset
        let mut sorted_tables = self.section_tables.clone();
        sorted_tables.sort_by_key(|table| table.offset);

        // Filter out empty sections
        sorted_tables.retain(|table| table.media_end_offset > table.media_offset);

        for table in &sorted_tables {
            if table.offset < table.end_offset {
                // Calculate the counter starting from the sector
                let counter = generate_counter_from_section(table.offset);

                let section = Section {
                    offset: table.offset,
                    size: table.end_offset - table.offset,
                    crypto_type: self.crypto_type as u64,
                    crypto_key: self.crypto_key,
                    crypto_counter: counter,
                };
                sections.push(section);
            }
        }

        // Add fake section if needed - IMPORTANT for NSZ compatibility
        if !sections.is_empty() && sections[0].offset > UNCOMPRESSABLE_HEADER_SIZE as u64 {
            let fake_section = Section {
                offset: UNCOMPRESSABLE_HEADER_SIZE as u64,
                size: sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE as u64,
                crypto_type: 0, // Type 0 means no crypto
                crypto_key: [0u8; 16],
                crypto_counter: [0u8; 16],
            };
            sections.insert(0, fake_section);
        }

        sections
    }
}

// Add padding utility function
pub fn align_to(size: u64, alignment: u64) -> u64 {
    let remainder = size % alignment;
    if remainder == 0 {
        size
    } else {
        size + (alignment - remainder)
    }
}

// Improved counter generation to exactly match Python implementation
fn generate_counter_from_section(offset: u64) -> [u8; 16] {
    let mut counter = [0u8; 16];

    // Divide by sector size (0x10) to get the sector number
    let sector = offset >> 4;

    // Put the low 8 bytes of the sector in the counter in big-endian format
    for i in 0..8 {
        counter[15 - i] = ((sector >> (i * 8)) & 0xFF) as u8;
    }

    counter
}

// Simplified function used for the fake section case
fn generate_counter_from_offset(offset: u64) -> [u8; 16] {
    generate_counter_from_section(offset)
}

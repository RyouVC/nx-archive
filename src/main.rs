mod formats;

use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use clap::Parser;
use colored::*;
use formats::{align_to, BlockHeader, NcaHeader, NczHeader, Section, UNCOMPRESSABLE_HEADER_SIZE};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use std::cmp;
use std::{
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    time::Instant,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Input NSP file
    #[arg(short, long)]
    input: PathBuf,

    /// Output NSZ file
    #[arg(short, long)]
    output: PathBuf,

    /// Block size in MB (default: 16)
    #[arg(short, long, default_value = "16")]
    block_size: usize,

    /// Compression level (0-22, default: 18)
    #[arg(short, long, default_value = "18")]
    compression_level: i32,
}

struct NszBuilder {
    block_size: usize,
    compression_level: i32,
}

impl NszBuilder {
    fn new(block_size: usize, compression_level: i32) -> Self {
        Self {
            block_size: block_size * 1024 * 1024, // Convert MB to bytes
            compression_level,
        }
    }

    fn compress_nsp(&self, input_path: &PathBuf, output_path: &PathBuf) -> Result<()> {
        info!("Processing {}", input_path.display());
        let start_time = Instant::now();
        let file_size = input_path.metadata()?.len();

        let mut nsp = File::open(input_path)?;
        let mut nsz = File::create(output_path)?;

        // Read PFS0 header
        let mut header = [0u8; 0x10];
        nsp.read_exact(&mut header)?;

        if &header[0..4] != b"PFS0" {
            error!("Invalid PFS0 header in {}", input_path.display());
            return Err(anyhow::anyhow!("Invalid PFS0 header"));
        }

        debug!("Found valid PFS0 header");
        let num_files = (&header[0x4..0x8]).read_u32::<LittleEndian>()?;
        let str_table_size = (&header[0x8..0xC]).read_u32::<LittleEndian>()?;
        info!("NSP contains {} files", num_files);

        // Read file entries
        let entries_size = num_files as usize * 0x18;
        let mut entries = vec![0u8; entries_size];
        nsp.read_exact(&mut entries)?;

        // Read string table
        let mut str_table = vec![0u8; str_table_size as usize];
        nsp.read_exact(&mut str_table)?;

        // First pass: pre-process files to check which NCAs will be compressed
        // and update string table (NCA->NCZ)
        let mut modify_string_table = false;
        let mut new_str_table = str_table.clone();

        for i in 0..num_files {
            let entry_offset = (i * 0x18) as usize;
            let entry = &entries[entry_offset..entry_offset + 0x18];
            let name_offset = (&entry[0x10..0x14]).read_u32::<LittleEndian>()?;

            // Get filename from string table
            let name = match str_table[name_offset as usize..]
                .iter()
                .position(|&x| x == 0)
            {
                Some(end) => String::from_utf8_lossy(
                    &str_table[name_offset as usize..name_offset as usize + end],
                ),
                None => String::from_utf8_lossy(&str_table[name_offset as usize..]),
            };

            // Check if this file will be compressed (NCA -> NCZ)
            if name.to_string().ends_with(".nca")
                && !name.to_string().ends_with(".cnmt.nca") // Don't compress cnmt
                && (&entry[8..16]).read_u64::<LittleEndian>()? > UNCOMPRESSABLE_HEADER_SIZE as u64
            {
                if let Some(name_end) = name.to_string().strip_suffix(".nca") {
                    let new_name = format!("{}.ncz", name_end);
                    info!("Will convert {} to {}", name, new_name);

                    // Replace in string table
                    let start = name_offset as usize;
                    let end = start + name.len();

                    // Create new string table entries
                    let mut replacement = new_name.as_bytes().to_vec();
                    replacement.push(0); // Null terminator

                    // Only update if needed and if it fits
                    if replacement.len() <= (end - start) {
                        new_str_table[start..start + replacement.len()]
                            .copy_from_slice(&replacement);
                        modify_string_table = true;
                    } else {
                        warn!(
                            "Cannot rename {} to {} (doesn't fit in string table)",
                            name, new_name
                        );
                    }
                }
            }
        }

        // Use new string table if modified
        if modify_string_table {
            str_table = new_str_table;
        }

        // Calculate header size and align to 0x10
        let base_header_size = 0x10 + entries_size + str_table_size as usize;
        let header_size = align_to(base_header_size as u64, 0x10) as usize;

        // Create hash section that will be appended to the NSZ
        let mut file_hashes = Vec::with_capacity(num_files as usize);

        // Create progress bar
        let progress = ProgressBar::new(file_size);
        progress.set_style(
            ProgressStyle::default_bar()
                .template(
                    "[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta}) {msg}",
                )
                .unwrap()
                .progress_chars("=>-"),
        );

        // First pass: process files to collect hashes and calculate sizes
        let mut files_data = Vec::with_capacity(num_files as usize);
        let mut new_entries = entries.clone();
        let mut current_offset = header_size as u64;

        for i in 0..num_files {
            let entry_offset = (i * 0x18) as usize;
            let entry = &entries[entry_offset..entry_offset + 0x18];

            let offset = (&entry[0..8]).read_u64::<LittleEndian>()?;
            let size = (&entry[8..16]).read_u64::<LittleEndian>()?;
            let name_offset = (&entry[0x10..0x14]).read_u32::<LittleEndian>()?;

            // Get filename from string table
            let name = match str_table[name_offset as usize..]
                .iter()
                .position(|&x| x == 0)
            {
                Some(end) => String::from_utf8_lossy(
                    &str_table[name_offset as usize..name_offset as usize + end],
                ),
                None => String::from_utf8_lossy(&str_table[name_offset as usize..]),
            };

            info!("Processing file {} ({} bytes)", name, size);

            // Seek to file position and read content
            nsp.seek(SeekFrom::Start(offset))?;
            let mut file_data = vec![0u8; size as usize];
            nsp.read_exact(&mut file_data)?;

            // Calculate hash for verification
            let hash = Sha256::digest(&file_data);
            file_hashes.push(hash.as_slice().to_vec());

            // Process file contents - compress NCA files, leave others as-is
            let processed_data = if name.to_string().ends_with(".nca")
                && !name.to_string().ends_with(".cnmt.nca") // Don't compress cnmt
                && size > UNCOMPRESSABLE_HEADER_SIZE as u64
                && file_data.len() >= 0x200
                && &file_data[0x200..0x204] == b"NCA3"
            {
                info!("Compressing NCA file: {}", name);
                // Change extension in the string table if it's NCA -> NCZ
                if let Some(name_end) = name.to_string().strip_suffix(".nca") {
                    let new_name = format!("{}.ncz", name_end);
                    debug!("Changing entry name from {} to {}", name, new_name);
                    // TODO: Update string table with new name (complex string table manipulation)
                }
                self.compress_nca(&file_data)?
            } else {
                info!("Keeping file as-is: {}", name);
                file_data
            };

            // Update entry with new offset and size
            (&mut new_entries[entry_offset..entry_offset + 8])
                .write_u64::<LittleEndian>(current_offset)?;
            (&mut new_entries[entry_offset + 8..entry_offset + 16])
                .write_u64::<LittleEndian>(processed_data.len() as u64)?;

            // Align offset to next 0x10 boundary as per NSZ format
            let aligned_size = align_to(processed_data.len() as u64, 0x10);
            current_offset += aligned_size;
            files_data.push(processed_data);

            progress.set_position(i as u64 * 100 / num_files as u64);
        }

        // Calculate final NSZ size
        let nsz_size = current_offset + (file_hashes.len() * 32) as u64;

        // Second pass: write everything to NSZ file
        // Write header
        nsz.write_all(&header)?;
        nsz.write_all(&new_entries)?;
        nsz.write_all(&str_table)?;

        // Add padding if needed to reach aligned header size
        let padding_size = header_size - base_header_size;
        if padding_size > 0 {
            nsz.write_all(&vec![0u8; padding_size])?;
        }

        // Write file data with alignment
        for (i, data) in files_data.iter().enumerate() {
            nsz.write_all(data)?;

            // Add padding to align to 0x10
            let padding_size = (align_to(data.len() as u64, 0x10) - data.len() as u64) as usize;
            if padding_size > 0 {
                nsz.write_all(&vec![0u8; padding_size])?;
            }

            progress.set_position((num_files as u64 + i as u64) * 100 / (num_files as u64 * 2));
        }

        // Write hash section
        for hash in file_hashes {
            nsz.write_all(&hash)?;
        }

        let duration = start_time.elapsed();
        let compression_ratio = nsz_size as f64 / file_size as f64 * 100.0;

        info!(
            "Compression complete in {:.2?} - Final size: {:.1}% of original ({} bytes)",
            duration, compression_ratio, nsz_size
        );

        progress.finish_with_message(format!(
            "Done! Compression ratio: {:.1}%",
            compression_ratio
        ));

        Ok(())
    }

    fn compress_nca(&self, nca_data: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        debug!("Compressing NCA file of size {} bytes", nca_data.len());

        // Copy the uncompressable header
        output.extend_from_slice(&nca_data[..UNCOMPRESSABLE_HEADER_SIZE]);

        // Parse the NCA header to find sections
        let mut cursor = Cursor::new(&nca_data[..]);
        let nca_header = match NcaHeader::parse(&mut cursor) {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to parse NCA header: {}", e);
                // Fall back to a basic section approach but with proper counter
                let section = Section {
                    offset: UNCOMPRESSABLE_HEADER_SIZE as u64,
                    size: (nca_data.len() - UNCOMPRESSABLE_HEADER_SIZE) as u64,
                    crypto_type: 3, // Common type in NSZ
                    crypto_key: [0u8; 16],
                    crypto_counter: generate_counter_from_offset(UNCOMPRESSABLE_HEADER_SIZE as u64),
                };

                NczHeader {
                    sections: vec![section],
                }
                .write(&mut output)?;

                // Compress the body with exact block alignment
                let body_data = &nca_data[UNCOMPRESSABLE_HEADER_SIZE..];
                let (compressed_body, block_sizes) = self.compress_blocks_with_sizes(body_data)?;

                // Add block header
                let mut block_header = BlockHeader::new(self.block_size, body_data.len() as u64);
                block_header.block_sizes = block_sizes;
                block_header.write(&mut output)?;

                // Add compressed data
                output.extend(compressed_body);

                return Ok(output);
            }
        };

        // Get encryption sections with proper sorting
        let sections = nca_header.get_sections();
        let ncz_header = NczHeader { sections };
        ncz_header.write(&mut output)?;

        // Compress body data
        let body_data = &nca_data[UNCOMPRESSABLE_HEADER_SIZE..];
        let (compressed_body, block_sizes) = self.compress_blocks_with_sizes(body_data)?;

        // Add block header
        let mut block_header = BlockHeader::new(self.block_size, body_data.len() as u64);
        block_header.block_sizes = block_sizes;
        block_header.write(&mut output)?;

        // Add compressed data
        output.extend(compressed_body);

        debug!(
            "Compressed NCA from {} to {} bytes",
            nca_data.len(),
            output.len()
        );
        Ok(output)
    }

    fn compress_blocks_with_sizes(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u32>)> {
        let num_blocks = (data.len() + self.block_size - 1) / self.block_size;
        debug!(
            "Compressing {} bytes into {} blocks of size {}",
            data.len(),
            num_blocks,
            self.block_size
        );

        let mut compressed_data = Vec::with_capacity(data.len()); // Worst case
        let mut block_sizes = Vec::with_capacity(num_blocks);

        // Process each block with parameters matching Python implementation
        for i in 0..num_blocks {
            let start = i * self.block_size;
            let end = cmp::min(start + self.block_size, data.len());
            let block = &data[start..end];

            // Skip compressing blocks that are mostly zeros
            let zero_count = block.iter().filter(|&&b| b == 0).count();
            if zero_count > block.len() * 9 / 10 && block.len() > 100 {
                // Use uncompressed for blocks that are >90% zeros
                block_sizes.push(block.len() as u32);
                compressed_data.extend_from_slice(block);
                debug!("Block {} stored uncompressed (mostly zeros)", i);
                continue;
            }

            // Create a compression dictionary with custom parameters
            // This approach achieves similar results to the Python implementation
            let dict_size_mb = 8; // 8MB dictionary, similar to Python's default
            let level = self.compression_level;

            // Create options with consistent parameters

            // Try to compress the block with these parameters
            let compressed = match zstd::stream::encode_all(block, level) {
                Ok(c) => c,
                Err(e) => return Err(anyhow::anyhow!("Compression error: {}", e)),
            };

            // Store either compressed or original block depending on which is smaller
            if compressed.len() < block.len() {
                block_sizes.push(compressed.len() as u32);
                compressed_data.extend_from_slice(&compressed);
                debug!(
                    "Block {} compressed from {} to {} bytes",
                    i,
                    block.len(),
                    compressed.len()
                );
            } else {
                block_sizes.push(block.len() as u32);
                compressed_data.extend_from_slice(block);
                debug!("Block {} stored uncompressed ({} bytes)", i, block.len());
            }
        }

        Ok((compressed_data, block_sizes))
    }
}

// Add this helper function to generate counter from offset
fn generate_counter_from_offset(offset: u64) -> [u8; 16] {
    let mut counter = [0u8; 16];
    let sector = offset >> 4;

    for i in 0..8 {
        counter[0x10 - i - 1] = (sector >> (i * 8)) as u8;
    }

    counter
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();
    info!(
        "{}",
        r#"
             NSZ v4.6   ,;:;;,
                       ;;;;;
               .=',    ;:;;:,
              /_', "=. ';:;:;
              @=:__,  \,;:;:'
                _(\\.=  ;:;;'
               `"_(  _/="`
                `"'"#
            .cyan()
    );

    let builder = NszBuilder::new(cli.block_size, cli.compression_level);
    builder.compress_nsp(&cli.input, &cli.output)?;

    Ok(())
}

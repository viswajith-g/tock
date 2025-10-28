// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Discovery Table Flash Writer

use crate::binary_discovery_table::{BinariesDiscoveryTable, BinaryEntry, BdtHeader};
use crate::error::BootError;
use crate::flash_hal::FlashHal;

/// Write BDT to flash at 0x8000
pub fn write_bdt_to_flash(
    kernel_entries: &[BinaryEntry],
    kernel_count: usize,
) -> Result<(), BootError> {
    // Build BDT in RAM
    let mut bdt_buffer = [0u8; BinariesDiscoveryTable::SIZE];
    build_bdt_in_buffer(&mut bdt_buffer, kernel_entries, kernel_count)?;
    
    // Erase BDT flash page
    FlashHal::erase_page(BinariesDiscoveryTable::ADDRESS)?;
    
    // Write BDT to flash
    FlashHal::write_buffer(BinariesDiscoveryTable::ADDRESS, &bdt_buffer)?;
    
    Ok(())
}

/// Build BDT in RAM buffer
fn build_bdt_in_buffer(
    buffer: &mut [u8],
    kernel_entries: &[BinaryEntry],
    kernel_count: usize,
) -> Result<(), BootError> {
    buffer.fill(0);
    
    let mut offset = 0;
    
    // Build header
    let header = BdtHeader {
        magic: *b"BDTS",
        kernel_count: kernel_count as u16,
        app_count: 0,
        reserved: [0; 2],
        checksum: 0,
    };
    
    // Write header (without checksum)
    offset += write_header(&mut buffer[offset..], &header);
    
    // Write kernel entries
    for entry in &kernel_entries[..kernel_count] {
        offset += write_entry(&mut buffer[offset..], entry);
    }
    
    // Compute and write checksum
    let checksum = compute_bdt_checksum(buffer);
    buffer[12..16].copy_from_slice(&checksum.to_le_bytes());
    
    Ok(())
}

fn write_header(buffer: &mut [u8], header: &BdtHeader) -> usize {
    buffer[0..4].copy_from_slice(&header.magic);
    buffer[4..6].copy_from_slice(&header.kernel_count.to_le_bytes());
    buffer[6..8].copy_from_slice(&header.app_count.to_le_bytes());
    buffer[8..10].copy_from_slice(&header.reserved);
    16
}

fn write_entry(buffer: &mut [u8], entry: &BinaryEntry) -> usize {
    buffer[0..4].copy_from_slice(&entry.start_address.to_le_bytes());
    buffer[4..8].copy_from_slice(&entry.size.to_le_bytes());
    buffer[8..11].copy_from_slice(&entry.version);
    buffer[11] = entry.binary_type;
    buffer[12..16].copy_from_slice(&entry.reserved);
    16
}

fn compute_bdt_checksum(buffer: &[u8]) -> u32 {
    let mut crc = crc32_init();
    crc = crc32_update(crc, &buffer[0..12]); // Header without checksum
    crc = crc32_update(crc, &buffer[16..]); // Rest of BDT
    crc32_finalize(crc)
}

// CRC32 functions
fn crc32_init() -> u32 {
    0xFFFF_FFFF
}

fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

fn crc32_finalize(crc: u32) -> u32 {
    !crc
}
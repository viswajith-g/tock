// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Discovery Table Flash Writer

use crate::binary_discovery_table::{
    BdtHeader, BinaryEntry, MAX_KERNEL_ENTRIES, BDT_MAGIC, BDT_SIZE, BDT_ADDR,
};
use crate::error::BootError;
use crate::flash_hal::FlashHal;

/// Write BDT to flash at the defined BDT page.
/// - Builds a fresh header
/// - Writes kernel entries (bootloader-owned)
/// - Leaves app section untouched (kernel-owned)
pub fn write_bdt_to_flash(
    kernel_entries: &[BinaryEntry],
    kernel_count: usize,
) -> Result<(), BootError> {
    if kernel_count > MAX_KERNEL_ENTRIES {
        return Err(BootError::InvalidBDT);
    }

    // Build BDT image
    let mut bdt_buffer = [0xFFu8; BDT_SIZE];
    build_bdt_in_buffer(&mut bdt_buffer, kernel_entries, kernel_count)?;

    // Erase the BDT page
    FlashHal::erase_page(BDT_ADDR)?;

    // Program the BDT page
    FlashHal::write_buffer(BDT_ADDR, &bdt_buffer)?;

    Ok(())
}

/// Build the BDT image into a buffer
/// Layout:
///   0x0000 .. 0x000F : Header (16 bytes)
///   0x0010 ..        : Kernel entries (16 bytes each, `kernel_count`)
///   ...              : Remaining bytes left as 0xFF (app section)
fn build_bdt_in_buffer(
    buffer: &mut [u8],
    kernel_entries: &[BinaryEntry],
    kernel_count: usize,
) -> Result<(), BootError> {
    if buffer.len() != BDT_SIZE {
        return Err(BootError::InvalidBDT);
    }
    if kernel_count > MAX_KERNEL_ENTRIES || kernel_entries.len() < kernel_count {
        return Err(BootError::InvalidBDT);
    }

    // Start from an erased state (1)
    buffer.fill(0xFF);

    // Header
    let header = BdtHeader {
        magic: BDT_MAGIC,
        kernel_count: kernel_count as u16,
        app_count: 0,
        reserved: [0u8; 8],
    };
    let mut offset = write_header(buffer, &header);

    // Kernel entries
    for entry in kernel_entries.iter().take(kernel_count) {
        offset += write_entry(&mut buffer[offset..], entry);
    }
    Ok(())
}

#[inline(always)]
fn write_header(buf: &mut [u8], header: &BdtHeader) -> usize {
    // BdtHeader is 16 bytes
    // Layout: magic[4] | kernel_count[2] | app_count[2] | reserved[8]
    buf[0..4].copy_from_slice(&header.magic);
    buf[4..6].copy_from_slice(&header.kernel_count.to_le_bytes());
    buf[6..8].copy_from_slice(&header.app_count.to_le_bytes());
    buf[8..16].copy_from_slice(&header.reserved);
    16
}

#[inline(always)]
fn write_entry(buf: &mut [u8], entry: &BinaryEntry) -> usize {
    // BinaryEntry is 16 bytes.
    // Layout: start[4] | size[4] | version[3] | type[1] | reserved[4]
    buf[0..4].copy_from_slice(&entry.start_address.to_le_bytes());
    buf[4..8].copy_from_slice(&entry.size.to_le_bytes());
    buf[8..11].copy_from_slice(&entry.version);
    buf[11] = entry.binary_type;
    buf[12..16].copy_from_slice(&entry.reserved);
    16
}

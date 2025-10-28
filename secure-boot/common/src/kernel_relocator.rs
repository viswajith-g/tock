// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Kernel relocation engine
//!
//! Performs runtime relocation of kernel binaries to allow kernels
//! to run at addresses different from their link address.

use crate::error::BootError;
use crate::flash_hal::{FlashHal, PAGE_SIZE};
use crate::locate_tlvs::PotentialKernel;
use crate::types::{RelocationInfo, RelocationEntry};
use crate::BootloaderIO;

/// ARM relocation type: R_ARM_ABS32
const R_ARM_ABS32: u8 = 2;

/// Relocate kernel in-place
///
/// This function:
/// 1. Relocates the vector table (hardcoded logic for ~100 entries)
/// 2. Applies relocation from the relocation TLV
/// 3. Modifies kernel in flash using page-based erase/write
pub fn relocate_kernel_in_place<IO: BootloaderIO>(
    kernel: &PotentialKernel,
    reloc_info: &RelocationInfo,
    io: &IO,
) -> Result<(), BootError> {
    let kernel_base = kernel.start_address;
    let link_address = reloc_info.link_address as usize;
    let mut buf = [0u8; 32];

    io.debug("Kernel relocator");

    io.debug("Kernel start address: ");
    io.format(kernel_base, &mut buf);

    io.debug("Link start address: ");
    io.format(link_address, &mut buf);
    
    // If already at link address, no relocation needed
    if kernel_base == link_address {
        io.debug("already at link address");
        return Ok(());
    }
    
    let offset = (kernel_base as i32) - (link_address as i32);
    io.debug("relocation offset:");
    io.format(offset as usize, &mut buf);
    
    // // Step 1: Relocate vector table (first ~100 entries)
    // relocate_vector_table(kernel_base, offset, io)?;
    
    // Step 2: Apply relocation from TLV
    apply_tlv_relocations(kernel_base, offset, reloc_info, io)?;
    
    Ok(())
}

/// Relocate the vector table
///
/// The vector table contains:
/// - Entry 0: Stack pointer (SRAM address - don't relocate)
/// - Entries 1-99: Function pointers (flash addresses - relocate)
fn relocate_vector_table<IO: BootloaderIO>(
    kernel_base: usize,
    offset: i32,
    io: &IO,
) -> Result<(), BootError> {
    // Read the first page containing vector table
    io.debug("relocating vector table");

    let mut page_buffer = [0u8; PAGE_SIZE];
    read_page(kernel_base, &mut page_buffer)?;

    io.debug("read page");
    
    let mut modified = false;
    
    // Process vector table entries (skip entry 0 - stack pointer)
    for i in 1..100 {
        let entry_offset = i * 4;
        if entry_offset + 4 > PAGE_SIZE {
            io.debug("Vector table past first page");
            break;  // Vector table extends beyond first page (unlikely)
        }
        
        let addr_bytes = &page_buffer[entry_offset..entry_offset + 4];
        let addr = u32::from_le_bytes([
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
        ]);
        
        // If this is a flash address, relocate it
        if is_flash_address(addr) {
            // io.debug("this is a flash address");
            let new_addr = (addr as i32 + offset) as u32;
            page_buffer[entry_offset..entry_offset + 4]
                .copy_from_slice(&new_addr.to_le_bytes());
            modified = true;
        }
    }
    
    // Write back if modified
    if modified {
        // io.debug("modified value, writing to flash");
        write_page(kernel_base, &page_buffer)?;
    }
    
    Ok(())
}

/// Apply relocation from TLV
fn apply_tlv_relocations<IO: BootloaderIO>(
    kernel_base: usize,
    offset: i32,
    reloc_info: &RelocationInfo,
    io: &IO,
) -> Result<(), BootError> {
    // Process relocation in batches by page

    io.debug("applying TLV relocations");

    let mut current_page = usize::MAX;
    let mut page_buffer = [0u8; PAGE_SIZE];
    let mut page_modified = false;
    let mut page_base = 0;

    let mut buf = [0u8; 32];

    io.debug("total number of relocation entries:");
    io.format(reloc_info.num_entries as usize, &mut buf);
    
    for i in 0..reloc_info.num_entries {
        // Read relocation entry
        let entry_addr = reloc_info.entries_start + (i as usize * RelocationEntry::SIZE);
        let entry = read_relocation_entry(entry_addr)?;

        // io.debug("relocation entry address:");
        // io.format(entry_addr, &mut buf);
        
        // Only handle R_ARM_ABS32
        if entry.rel_type != R_ARM_ABS32 {
            io.debug("invalid entry type");
            continue;
        }
        
        // Calculate actual address to patch
        let patch_addr = kernel_base + entry.offset as usize;
        let page_num = patch_addr / PAGE_SIZE;

        // io.debug("patch address:");
        // io.format(patch_addr, &mut buf);
        
        // If we've moved to a new page, write the old one
        if page_num != current_page {
            if page_modified {
                io.debug("moved to new page, writing old page");
                write_page(page_base, &page_buffer)?;
            }
            
            // Load new page
            io.debug("loading new page");
            current_page = page_num;
            page_base = page_num * PAGE_SIZE;
            read_page(page_base, &mut page_buffer)?;
            page_modified = false;
        }
        
        // Apply relocation in buffer
        let offset_in_page = patch_addr % PAGE_SIZE;
        
        // Check if value matches expected original value (idempotency check)
        let current_value = u32::from_le_bytes([
            page_buffer[offset_in_page],
            page_buffer[offset_in_page + 1],
            page_buffer[offset_in_page + 2],
            page_buffer[offset_in_page + 3],
        ]);
        
        if current_value == entry.original_value {
            io.debug("need to relocate");
            // Not yet relocated, apply relocation
            let new_value = (entry.original_value as i32 + offset) as u32;
            page_buffer[offset_in_page..offset_in_page + 4]
                .copy_from_slice(&new_value.to_le_bytes());
            page_modified = true;
            io.debug("relocated");
        }
        // else: already relocated, skip
    }
    
    // Write final page if modified
    if page_modified {
        io.debug("final page modification");
        write_page(page_base, &page_buffer)?;
    }
    
    Ok(())
}

/// Read a relocation entry from flash
fn read_relocation_entry(addr: usize) -> Result<RelocationEntry, BootError> {
    let bytes = unsafe {
        core::slice::from_raw_parts(addr as *const u8, RelocationEntry::SIZE)
    };
    
    Ok(RelocationEntry {
        offset: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        original_value: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        rel_type: bytes[8],
        reserved: [bytes[9], bytes[10], bytes[11]],
    })
}

/// Check if an address is in flash range
fn is_flash_address(addr: u32) -> bool {
    addr < 0x0010_0000  // nRF52840 has 1MB flash
}

/// Read a page from flash into buffer
fn read_page(addr: usize, buffer: &mut [u8; PAGE_SIZE]) -> Result<(), BootError> {
    let page_addr = (addr / PAGE_SIZE) * PAGE_SIZE;
    let flash = unsafe {
        core::slice::from_raw_parts(page_addr as *const u8, PAGE_SIZE)
    };
    buffer.copy_from_slice(flash);
    Ok(())
}

/// Write a page to flash (erase then write)
fn write_page(addr: usize, buffer: &[u8; PAGE_SIZE]) -> Result<(), BootError> {
    let page_addr = (addr / PAGE_SIZE) * PAGE_SIZE;
    
    // Erase page
    FlashHal::erase_page(page_addr)?;
    
    // Write page
    FlashHal::write_buffer(page_addr, buffer)?;
    
    Ok(())
}
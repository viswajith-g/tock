// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

use crate::error::BootError;
use crate::flash_hal::{FlashHal, PAGE_SIZE};
use crate::locate_tlvs::PotentialKernel;
use crate::types::{RelocationInfo, RelocationEntry};
use crate::BootloaderIO;

const R_ARM_ABS32: u8 = 2;

#[inline(always)]
fn looks_like_flash_ptr(x: u32) -> bool {
    // Treat any (value & !1) within on-chip Flash as a relocatable code pointer.
    (x & !1) < 0x0020_0000
}

#[inline(always)]
fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[inline(always)]
fn write_u32_le(dst: &mut [u8], val: u32) {
    dst.copy_from_slice(&val.to_le_bytes());
}

pub fn relocate_kernel_in_place<IO: BootloaderIO>(
    kernel: &PotentialKernel,
    reloc_info: &RelocationInfo,
    _io: &IO,
) -> Result<(), BootError> {
    let kernel_base = kernel.start_address;
    let link_address = reloc_info.link_address as usize;

    // let mut buf = [0u8; 32];
    // _io.debug("Kernel relocator");
    // _io.debug("Kernel start address:");
    // _io.format(kernel_base, &mut buf);
    // _io.debug("Link start address:");
    // _io.format(link_address, &mut buf);

    if kernel_base == link_address {
        // _io.debug("already at link address");
        return Ok(());
    }

    let offset = (kernel_base as i32) - (link_address as i32);
    // _io.debug("relocation offset:");
    // _io.format(offset as usize, &mut buf);

    // Apply TLV relocations (skip vector table region for now)
    apply_tlv_relocations(kernel_base, offset, reloc_info, _io)?;

    // Relocate vector table entries and set VTOR
    relocate_vector_table(kernel_base, offset, _io)?;

    Ok(())
}

fn relocate_vector_table<IO: BootloaderIO>(
    kernel_base: usize,
    offset: i32,
    _io: &IO,
) -> Result<(), BootError> {
    // _io.debug("relocating vector table");
    // let mut buf = [0u8; 32];

    // Read the first page containing the VT
    let mut page = [0u8; PAGE_SIZE];
    read_page(kernel_base, &mut page)?;

    let mut modified = false;

    // Entry 0 = MSP (RAM) — do not relocate.
    // Relocate entries 1..N if they look like Flash pointers, while preserving T-bit.
    for i in 1..100 {
        let o = i * 4;
        if o + 4 > PAGE_SIZE {
            break;
        }
        let v = read_u32_le(&page[o..o + 4]);
        let tbit = v & 1;
        let base = v & !1;
        if looks_like_flash_ptr(base) {
            let new_base = (base as i32 + offset) as u32;
            let new_val = new_base | tbit;
            if new_val != v {
                write_u32_le(&mut page[o..o + 4], new_val);
                modified = true;
            }
        }
    }

    if modified {
        write_page(kernel_base, &page)?;
        // Verify/log VT[1] after
        let mut verify = [0u8; PAGE_SIZE];
        read_page(kernel_base, &mut verify)?;
        // _io.debug("VT[1] before/after:");
        // _io.format(before_reset as usize, &mut buf);
        // _io.format(after_reset as usize, &mut buf);
    }

    // Point VTOR at the relocated VT base so faults/IRQs read the right table
    unsafe {
        const SCB_VTOR: *mut u32 = 0xE000_ED08 as *mut u32;
        core::ptr::write_volatile(SCB_VTOR, kernel_base as u32);
    }

    Ok(())
}

fn apply_tlv_relocations<IO: BootloaderIO>(
    kernel_base: usize,
    offset: i32,
    reloc_info: &RelocationInfo,
    _io: &IO,
) -> Result<(), BootError> {
    // _io.debug("applying TLV relocations");

    // We treat the first 100 words (including MSP and handlers) as the VT region
    // and skip TLV-driven patches there; VT is handled separately
    const VT_WORDS: usize = 100;
    const VT_BYTES: usize = VT_WORDS * 4;

    let mut current_page = usize::MAX;
    let mut page_buffer = [0u8; PAGE_SIZE];
    let mut page_modified = false;
    let mut flash_page_base = 0;

    // let mut buf = [0u8; 32];
    // _io.debug("total number of relocation entries:");
    // _io.format(reloc_info.num_entries as usize, &mut buf);

    for i in 0..reloc_info.num_entries {
        let entry_addr = reloc_info.entries_start + (i as usize * RelocationEntry::SIZE);
        let entry = read_relocation_entry(entry_addr)?;

        // Only handle ABS32 records
        if entry.rel_type != R_ARM_ABS32 {
            continue;
        }
        // Skip anything inside the VT region; we patch VT separately
        if (entry.offset as usize) < VT_BYTES {
            continue;
        }

        // Where in Flash we’ll patch
        let patch_addr = kernel_base + entry.offset as usize;
        let page_num = patch_addr / PAGE_SIZE;

        // Page management
        if page_num != current_page {
            if page_modified {
                write_page(flash_page_base, &page_buffer)?;
            }
            current_page = page_num;
            flash_page_base = page_num * PAGE_SIZE;
            read_page(flash_page_base, &mut page_buffer)?;
            page_modified = false;
        }

        // Read the current word at the site and decide based on it
        let off_in_page = patch_addr % PAGE_SIZE;
        let cur = read_u32_le(&page_buffer[off_in_page..off_in_page + 4]);

        // Split into base + Thumb bit
        let cur_t = cur & 1;
        let cur_b = cur & !1;

        // Don't relocate zeros or obvious non-pointers
        if cur_b == 0 {
            continue;
        }
        // Only relocate if it looks like(?) a pointer into Flash
        if !looks_like_flash_ptr(cur_b) {
            continue;
        }

        // Compute desired relocated value (preserve T-bit)
        let want = ((cur_b as i32 + offset) as u32) | cur_t;

        if cur != want {
            // _io.debug("reloc patch @");
            // _io.format(patch_addr, &mut [0u8; 32]);
            // _io.debug(" orig=");
            // _io.format(cur as usize, &mut [0u8; 32]);
            // _io.debug(" new=");
            // _io.format(want as usize, &mut [0u8; 32]);

            write_u32_le(&mut page_buffer[off_in_page..off_in_page + 4], want);
            page_modified = true;
        }
        // If cur == want, it’s already relocated, nothing to do.
        // We no longer require cur == entry.original_value to proceed.
    }

    if page_modified {
        write_page(flash_page_base, &page_buffer)?;
    }
    Ok(())
}

fn read_relocation_entry(addr: usize) -> Result<RelocationEntry, BootError> {
    let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, RelocationEntry::SIZE) };
    Ok(RelocationEntry {
        offset: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        original_value: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        rel_type: bytes[8],
        reserved: [bytes[9], bytes[10], bytes[11]],
    })
}

fn read_page(addr: usize, buffer: &mut [u8; PAGE_SIZE]) -> Result<(), BootError> {
    let page_addr = (addr / PAGE_SIZE) * PAGE_SIZE;
    let flash = unsafe { core::slice::from_raw_parts(page_addr as *const u8, PAGE_SIZE) };
    buffer.copy_from_slice(flash);
    Ok(())
}

fn write_page(addr: usize, buffer: &[u8; PAGE_SIZE]) -> Result<(), BootError> {
    let page_addr = (addr / PAGE_SIZE) * PAGE_SIZE;
    FlashHal::erase_page(page_addr)?;
    FlashHal::write_buffer(page_addr, buffer)?;
    Ok(())
}

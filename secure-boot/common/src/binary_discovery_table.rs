// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Binaries Discovery Table (BDT) — checksum-free version
//!
//! Layout (4 KB @ 0x0000_8000):
//!   [0x000] Header (16 B)
//!   [0x010] Kernel entries   (MAX_KERNEL_ENTRIES * 16 B)
//!   [....] App entries       (MAX_APP_ENTRIES   * 16 B)
//!
//! Ownership:
//!   - Bootloader: writes header.magic, kernel_count, kernel_entries[]. It may zero/erase the page.
//!   - Kernel:     appends to app_entries[] and updates app_count, **never** erases the page.

use crate::error::BootError;
use crate::types::KernelVersion;

pub const BDT_ADDR: usize = 0x0000_8000;
pub const BDT_SIZE: usize = 4096;

pub const BDT_MAGIC: [u8; 4] = *b"BDTS";

pub const MAX_KERNEL_ENTRIES: usize = 120;
pub const MAX_APP_ENTRIES: usize = 128;

pub mod binary_type {
    pub const KERNEL: u8 = 0x01;
    pub const APP:    u8 = 0x02;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BinaryEntry {
    pub start_address: u32,
    pub size: u32,
    pub version: [u8; 3],
    pub binary_type: u8,
    pub reserved: [u8; 4],
}

impl BinaryEntry {
    pub const fn empty() -> Self {
        Self {
            start_address: 0,
            size: 0,
            version: [0, 0, 0],
            binary_type: 0,
            reserved: [0; 4],
        }
    }

    pub fn is_sane(&self) -> bool {
        self.start_address >= 0x9000 &&
        self.size > 0 &&
        self.start_address < 0x0010_0000 &&
        self.size < 0x0010_0000
    }

    pub fn get_version(&self) -> KernelVersion {
        KernelVersion {
            major: self.version[0] as u16,
            minor: self.version[1] as u16,
            patch: self.version[2] as u16,
        }
    }

    pub fn is_kernel(&self) -> bool { self.binary_type == binary_type::KERNEL }
    pub fn is_app(&self)    -> bool { self.binary_type == binary_type::APP }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BdtHeader {
    pub magic: [u8; 4],   // "BDTS"
    pub kernel_count: u16,
    pub app_count: u16,
    pub reserved: [u8; 8], // pad to 16 bytes, future use (flags/version/etc.)
}

#[repr(C)]
pub struct BinariesDiscoveryTable {
    pub header: BdtHeader,
    pub kernel_entries: [BinaryEntry; MAX_KERNEL_ENTRIES],
    pub app_entries:    [BinaryEntry; MAX_APP_ENTRIES],
    // ~3984 bytes used; ~112 B slack at end of page depending on padding
}

impl BinariesDiscoveryTable {
    pub const fn new() -> Self {
        Self {
            header: BdtHeader {
                magic: BDT_MAGIC,
                kernel_count: 0,
                app_count: 0,
                reserved: [0; 8],
            },
            kernel_entries: [BinaryEntry::empty(); MAX_KERNEL_ENTRIES],
            app_entries: [BinaryEntry::empty(); MAX_APP_ENTRIES],
        }
    }

    #[inline(always)]
    pub fn address() -> usize { BDT_ADDR }

    #[inline(always)]
    pub fn size() -> usize { BDT_SIZE }

    /// Read BDT (magic-only check).
    pub fn read() -> Result<&'static Self, BootError> {
        let bdt = unsafe { &*(BDT_ADDR as *const Self) };
        if bdt.header.magic != BDT_MAGIC {
            return Err(BootError::InvalidBDT);
        }
        Ok(bdt)
    }

    /// Iterate over valid kernel entries.
    pub fn iter_kernel_entries(&self) -> impl Iterator<Item = &BinaryEntry> {
        self.kernel_entries[..(self.header.kernel_count as usize)]
            .iter()
            .filter(|e| e.is_sane())
    }

    /// Iterate over valid app entries.
    pub fn iter_app_entries(&self) -> impl Iterator<Item = &BinaryEntry> {
        self.app_entries[..(self.header.app_count as usize)]
            .iter()
            .filter(|e| e.is_sane())
    }
}

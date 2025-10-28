// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Binaries Discovery Table (BDT)
//! 
//! The BDT tracks all kernels and apps in flash, enabling dynamic placement.
//! It has two sections:
//! - Kernel section: Managed by bootloader, rebuilt each boot
//! - App section: Managed by kernel, persistent across boots

use crate::error::BootError;
use crate::types::KernelVersion;

/// Magic number for BDT
const BDT_SENTINEL: [u8; 4] = *b"BDTS";

/// Maximum entries in kernel section
pub const MAX_KERNEL_ENTRIES: usize = 120;

/// Maximum entries in app section  
pub const MAX_APP_ENTRIES: usize = 128;

/// Binary types
pub mod binary_type {
    pub const KERNEL: u8 = 0x01;
    pub const APP: u8 = 0x02;
}

/// Single binary entry in the BDT
#[derive(Clone, Copy, Debug)]
pub struct BinaryEntry {
    /// Start address in flash
    pub start_address: u32,
    
    /// Size in bytes
    pub size: u32,
    
    /// Version (major, minor, patch)
    pub version: [u8; 3],
    
    /// Binary type (KERNEL or APP)
    pub binary_type: u8,
    
    /// Reserved for future use
    pub reserved: [u8; 4],
}

impl BinaryEntry {
    /// Create empty entry
    pub const fn empty() -> Self {
        Self {
            start_address: 0,
            size: 0,
            version: [0, 0, 0],
            binary_type: 0,
            reserved: [0; 4],
        }
    }
    
    /// Check if entry looks valid (basic sanity check)
    pub fn is_sane(&self) -> bool {
        // Non-zero address
        self.start_address >= 0x9000 &&
        // Non-zero size
        self.size > 0 &&
        // Within flash bounds (nRF52840 has 1MB flash)
        self.start_address < 0x0010_0000 &&
        // Size is reasonable
        self.size < 0x0010_0000
    }
    
    /// Get version
    pub fn get_version(&self) -> KernelVersion {
        KernelVersion {
            major: self.version[0] as u16,
            minor: self.version[1] as u16,
            patch: self.version[2] as u16,
        }
    }
    
    /// Check if this is a kernel entry
    pub fn is_kernel(&self) -> bool {
        self.binary_type == binary_type::KERNEL
    }
    
    /// Check if this is an app entry
    pub fn is_app(&self) -> bool {
        self.binary_type == binary_type::APP
    }
}

/// BDT Header
#[derive(Clone, Copy)]
pub struct BdtHeader {
    /// Magic "BDTS"
    pub magic: [u8; 4],
    
    /// Number of valid kernel entries
    pub kernel_count: u16,
    
    /// Number of valid app entries
    pub app_count: u16,
    
    /// Reserved for future use
    pub reserved: [u8; 2],
    
    /// Checksum of entire BDT
    pub checksum: u32,
}

impl BdtHeader {
    /// Create new empty header
    pub const fn new() -> Self {
        Self {
            magic: BDT_SENTINEL,
            kernel_count: 0,
            app_count: 0,
            reserved: [0; 2],
            checksum: 0,
        }
    }
}

/// Binaries Discovery Table
pub struct BinariesDiscoveryTable {
    /// Header
    pub header: BdtHeader,
    
    /// Kernel entries (managed by bootloader)
    pub kernel_entries: [BinaryEntry; MAX_KERNEL_ENTRIES],
    
    /// App entries (managed by kernel)
    pub app_entries: [BinaryEntry; MAX_APP_ENTRIES],
}

impl BinariesDiscoveryTable {
    /// BDT location in flash
    pub const ADDRESS: usize = 0x0000_8000;
    
    /// BDT size (4KB)
    pub const SIZE: usize = 4096;
    
    /// Initialize empty BDT
    pub const fn new() -> Self {
        Self {
            header: BdtHeader::new(),
            kernel_entries: [BinaryEntry::empty(); MAX_KERNEL_ENTRIES],
            app_entries: [BinaryEntry::empty(); MAX_APP_ENTRIES],
        }
    }
    
    /// Read BDT from flash
    pub fn read() -> Result<&'static Self, BootError> {
        let bdt_ptr = Self::ADDRESS as *const Self;
        let bdt = unsafe { &*bdt_ptr };
        
        // Verify magic
        if bdt.header.magic != BDT_SENTINEL {
            return Err(BootError::InvalidBDT);
        }
        
        // Verify checksum
        let computed = bdt.compute_checksum();
        if computed != bdt.header.checksum {
            return Err(BootError::BDTChecksumFailed);
        }
        
        Ok(bdt)
    }
    
    /// Compute checksum of entire BDT (excluding checksum field itself)
    fn compute_checksum(&self) -> u32 {
        let bdt_ptr = self as *const Self as *const u8;
        let bdt_bytes = unsafe {
            core::slice::from_raw_parts(bdt_ptr, Self::SIZE)
        };
        
        let mut crc = crc32_init();
        
        // Hash everything except the checksum field (bytes 12-15 of header)
        // Header is 16 bytes: magic(4) + counts(4) + reserved(2) + checksum(4)
        crc = crc32_update(crc, &bdt_bytes[0..12]);   // magic + counts + reserved
        crc = crc32_update(crc, &bdt_bytes[16..]);    // skip checksum, hash rest
        
        crc32_finalize(crc)
    }
    
    /// Iterate over kernel entries (only valid count)
    pub fn iter_kernel_entries(&self) -> impl Iterator<Item = &BinaryEntry> {
        self.kernel_entries[..(self.header.kernel_count as usize)]
            .iter()
            .filter(|e| e.is_sane())
    }
    
    /// Iterate over app entries (only valid count)
    pub fn iter_app_entries(&self) -> impl Iterator<Item = &BinaryEntry> {
        self.app_entries[..(self.header.app_count as usize)]
            .iter()
            .filter(|e| e.is_sane())
    }
}

// CRC32 implementation
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entry_sanity() {
        let entry = BinaryEntry {
            start_address: 0x9000,
            size: 131072,
            version: [2, 3, 0],
            binary_type: binary_type::KERNEL,
            reserved: [0; 4],
        };
        
        assert!(entry.is_sane());
    }
    
    #[test]
    fn test_version_comparison() {
        let entry1 = BinaryEntry {
            version: [1, 0, 0],
            ..BinaryEntry::empty()
        };
        
        let entry2 = BinaryEntry {
            version: [2, 0, 0],
            ..BinaryEntry::empty()
        };
        
        assert!(entry2.get_version() > entry1.get_version());
    }
}
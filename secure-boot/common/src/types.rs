// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Common types used throughout the secure boot process

/// Represents the location and boundaries of the kernel in flash
#[derive(Copy, Clone, Debug)]
pub struct KernelRegion {
    /// Start address of kernel code in flash
    pub start: usize,
    
    /// End address of kernel code (start of attributes section)
    pub end: usize,
    
    /// Entry point address (generally the same as start, pointing to _stext)
    pub entry_point: usize,
    
    /// Start address of kernel attributes section
    pub attributes_start: usize,
}

/// ECDSA P-256 signature attribute (TLV type 0x0104)
#[derive(Copy, Clone, Debug)]
pub struct SignatureAttribute {
    /// ECDSA signature r component (32 bytes)
    pub r: [u8; 32],
    
    /// ECDSA signature s component (32 bytes)
    pub s: [u8; 32],
    
    /// Algorithm identifier (0x00000001 = ECDSA P-256 SHA-256)
    pub algorithm_id: u32,
    
    /// Byte range in flash where signature data is located
    pub location: (usize, usize), // (start, end)
}

/// Kernel version information (from TLV type 0x0103)
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

/// Parsed kernel attributes from the attributes section
pub struct KernelAttributes {
    /// Kernel signature (type 0x0104)
    pub signature: Option<SignatureAttribute>,
    
    /// Kernel version (type 0x0103)
    pub kernel_version: Option<KernelVersion>,
    
    /// App memory region: (start_address, length) (type 0x0101)
    pub app_memory: Option<(u32, u32)>,
    
    /// Kernel flash region: (start_address, length) (type 0x0102)
    pub kernel_flash: Option<(u32, u32)>,
}
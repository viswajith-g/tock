// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Secure Boot Common Library
//! 
//! This library provides board-agnostic secure boot functionality for Tock kernels.
//! It handles kernel signature verification using ECDSA P-256 for now.

#![no_std]

pub mod attributes_parser;
pub mod error;
pub mod compute_hash;
pub mod locate_tlvs;
pub mod types;
pub mod signature_verifier;

use crate::error::BootError;
use crate::types::{KernelVersion, KernelRegion};

/// Trait that boards must implement for bootloader I/O operations
pub trait BootloaderIO {
    /// Signal successful verification: LED1
    fn signal_success(&self);
    
    /// Signal verification failure: LED4 blink
    fn signal_failure(&self);
    
    /// Optional: Write debug message to UART
    fn debug_write(&self, _msg: &str) {}

    /// Optional: Blink a board LED `count` times
    fn debug_blink(&self, _pin: u32, _count: usize) {}
}

/// Board-specific configuration that must be provided
pub trait BoardConfig {
    /// Applications start address (_sapps)
    const APP_START: usize;
    
    /// Kernel start address
    const KERNEL_START: usize;
    
    /// ECDSA P-256 public key (64 bytes)
    const PUBLIC_KEY: [u8; 64];
    
    /// Minimum required kernel version
    const MIN_KERNEL_VERSION: KernelVersion;
}

/// Secure bootloader verification flow
/// 
/// This function verifies the kernel image:
/// 1. Locates the kernel region by scanning backwards from APP_START
/// 2. Parses kernel attributes to extract signature and version
/// 3. Checks kernel version against minimum required version
/// 4. Computes hash of kernel image
/// 5. Verifies signature
/// 
/// Returns the kernel entry point address on success.
pub fn verify_and_boot<C: BoardConfig, IO: BootloaderIO>(
    io: &IO,
) -> Result<usize, BootError> {
    // Verify and Boot entered
    // io.debug_blink(15, 1);

    // Locating kernel/attributes_end
    // io.debug_blink(15, 2);
    let region_found = locate_tlvs::define_kernel_region::<C>()?;

    // 3: Parsing attributes
    // io.debug_blink(15, 3);
    let attributes = attributes_parser::parse_attributes(
        region_found.attributes_start,
        C::APP_START,
    )?;

    // Finding signature
    // io.debug_blink(15, 4);
    let signature = attributes.signature.ok_or(BootError::SignatureMissing)?;

    // Check version
    // io.debug_blink(15, 5);
    if let Some(version) = attributes.kernel_version {
        if version < C::MIN_KERNEL_VERSION {
            return Err(BootError::VersionTooOld);
        }
    }

    // Check valid flash TLV
    // io.debug_blink(15, 6);
    let _ = attributes.kernel_flash.ok_or(BootError::InvalidTLV)?;
    

    let (flash_start, _flash_len) = attributes.kernel_flash.ok_or(BootError::InvalidTLV)?;
    let updated_region = KernelRegion {
        start: flash_start as usize,
        end:   region_found.end,
        entry_point: flash_start as usize,
        attributes_start: region_found.attributes_start,
    };

    // Compute hash
    // io.debug_blink(15, 7);
    let hash = compute_hash::compute_kernel_hash_safely(
        &updated_region,
        &signature,
        C::APP_START,
    )?;

    // Verify signature
    // io.debug_blink(15, 8);
    signature_verifier::verify_signature::<C>(&hash, &signature)?;

    // Verification success
    // io.debug_blink(15, 9);
    io.signal_success();
    Ok(updated_region.entry_point)
}

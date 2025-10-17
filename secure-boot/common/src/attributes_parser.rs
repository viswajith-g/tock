// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Parser for Tock kernel attributes (TLV structure)

use crate::error::BootError;
use crate::types::{KernelAttributes, KernelVersion, SignatureAttribute};

/// Parses the kernel attributes section and extracts all TLVs
pub fn parse_attributes(
    attributes_start: usize,
    app_start: usize,
) -> Result<KernelAttributes, BootError> {
    // Calculate the full attributes section size
    let attr_size = app_start - attributes_start;
    
    if attr_size > 512 || attr_size < 8 {
        return Err(BootError::InvalidTLV);
    }
    
    let attr_slice = unsafe {
        core::slice::from_raw_parts(attributes_start as *const u8, attr_size)
    };
    
    parse_tlvs(attr_slice, attributes_start)
}

/// Parses TLVs in reverse order (from end to beginning)
/// 
/// The attributes section layout:
/// [Signature TLV] [Version TLV] [Flash TLV] [App Memory TLV] [Version/Reserved] [TOCK]
fn parse_tlvs(
    attr_slice: &[u8],
    base_addr: usize,
) -> Result<KernelAttributes, BootError> {
    let len = attr_slice.len();
    
    // Skip the sentinel "TOCK" (4 bytes) and version/reserved (4 bytes)
    if len < 8 {
        return Err(BootError::InvalidTLV);
    }
    
    let mut pos = len - 8; // Start parsing from before sentinel and version
    
    let mut attributes = KernelAttributes {
        signature: None,
        kernel_version: None,
        app_memory: None,
        kernel_flash: None,
    };
    
    // Parse TLVs backwards
    while pos >= 4 {
        // Each TLV structure: [Value...] [Type: 2 bytes] [Length: 2 bytes]
        // Read Type and Length (last 4 bytes of current TLV)
        let tlv_type = u16::from_le_bytes([
            attr_slice[pos - 4],
            attr_slice[pos - 3],
        ]);
        let tlv_length = u16::from_le_bytes([
            attr_slice[pos - 2],
            attr_slice[pos - 1],
        ]);
        
        // Calculate where the value starts
        if pos < 4 + tlv_length as usize {
            // Not enough space for this TLV, malformed
            break;
        }
        
        let value_start = pos - 4 - tlv_length as usize;
        let value_end = pos - 4;
        
        // Parse based on TLV type
        match tlv_type {
            0x0104 => {
                // Signature TLV
                if tlv_length != 68 {
                    return Err(BootError::InvalidTLV);
                }
                let flash_addr = base_addr + value_start;
                attributes.signature = Some(parse_signature(
                    &attr_slice[value_start..value_end],
                    flash_addr,
                )?);
            }
            0x0103 => {
                // Kernel Version TLV
                if tlv_length != 8 {
                    return Err(BootError::InvalidTLV);
                }
                attributes.kernel_version = Some(parse_version(
                    &attr_slice[value_start..value_end]
                )?);
            }
            0x0102 => {
                // Kernel Flash TLV
                if tlv_length != 8 {
                    return Err(BootError::InvalidTLV);
                }
                attributes.kernel_flash = Some(parse_pair(
                    &attr_slice[value_start..value_end]
                )?);
            }
            0x0101 => {
                // App Memory TLV
                if tlv_length != 8 {
                    return Err(BootError::InvalidTLV);
                }
                attributes.app_memory = Some(parse_pair(
                    &attr_slice[value_start..value_end]
                )?);
            }
            _ => {
                // Unknown TLV type, skip it
            }
        }
        
        // Move to the next TLV (backwards)
        pos = value_start;
    }
    
    Ok(attributes)
}

/// Parses a signature attribute (68 bytes: 64 bytes key + 4 bytes algorithm_id)
fn parse_signature(data: &[u8], flash_addr: usize) -> Result<SignatureAttribute, BootError> {
    if data.len() != 68 {
        return Err(BootError::InvalidSignature);
    }
    
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&data[0..32]);
    s.copy_from_slice(&data[32..64]);
    
    let algorithm_id = u32::from_le_bytes([
        data[64], data[65], data[66], data[67]
    ]);
    
    Ok(SignatureAttribute {
        r,
        s,
        algorithm_id,
        location: (flash_addr, flash_addr + 64),
    })
}

/// Parse kernel version (8 bytes: major, minor, patch, prerelease)
fn parse_version(data: &[u8]) -> Result<KernelVersion, BootError> {
    if data.len() != 8 {
        return Err(BootError::InvalidTLV);
    }
    
    Ok(KernelVersion {
        major: u16::from_le_bytes([data[0], data[1]]),
        minor: u16::from_le_bytes([data[2], data[3]]),
        patch: u16::from_le_bytes([data[4], data[5]]),
        // Ignore prerelease (data[6..8]) for version comparison
    })
}

/// Parses a pair of u32 values (8 bytes total)
fn parse_pair(data: &[u8]) -> Result<(u32, u32), BootError> {
    if data.len() != 8 {
        return Err(BootError::InvalidTLV);
    }
    
    let first = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let second = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    
    Ok((first, second))
}
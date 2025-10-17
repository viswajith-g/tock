// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Kernel and TLVs location discovery by scanning backwards from application start

use crate::error::BootError;
use crate::types::KernelRegion;
use crate::BoardConfig;

/// Scans the kernel region backwards from APP_START to find the "TOCK" sentinel
pub fn define_kernel_region<C: BoardConfig>() -> Result<KernelRegion, BootError> {
    let app_start = C::APP_START;
    let kernel_start = C::KERNEL_START;
    
    // Find "TOCK" sentinel by scanning backwards from app_start
    let sentinel_address = find_tock_sentinel(app_start)?;
    
    // Scan TLVs backwards to find actual start of attributes
    let attributes_start = scan_tlvs(sentinel_address)?;
    
    Ok(KernelRegion {
        start: kernel_start,
        end: attributes_start,
        entry_point: kernel_start, // _stext is kernel start
        attributes_start,
    })
}

/// Searches from app_start in reverse to find the "TOCK" sentinel
fn find_tock_sentinel(app_start: usize) -> Result<usize, BootError> {
    const TOCK: [u8; 4] = [84, 79, 67, 75];
    
    // Assuming the sentinel will be within 512 bytes before app_start
    let search_start = app_start.saturating_sub(512);
    
    // Search backwards, checking every 4-byte aligned address
    let mut addr = app_start - 4;
    while addr >= search_start {
        let bytes = unsafe { 
            core::slice::from_raw_parts(addr as *const u8, 4) 
        };
        
        if bytes == TOCK {
            return Ok(addr);
        }
        
        if addr < 4 {
            break;
        }
        addr -= 4;
    }
    
    Err(BootError::SentinelNotFound)
}

/// Scan TLVs backwards from sentinel to find start of attributes
fn scan_tlvs(sentinel_address: usize) -> Result<usize, BootError> {
    // Layout: [... TLVs ...] [Version/Reserved] [TOCK]
    // After finding TOCK, skip it to get to the end of the TLV chain
    let mut pos = sentinel_address;
    
    // Skip TOCK pos is at start of Version/Reserved, 
    // which is the end of the TLV chain
    if pos < 4 {
        return Err(BootError::InvalidTLV);
    }
    pos -= 4;
    
    // Walk backwards through TLVs
    for _ in 0..16 {  // Assuming a max of 16 TLVs
        if pos < 8 {
            break; // Reached beginning (last TLV)
        }
        
        // Read TLV tail: [Type: 2 bytes][Length: 2 bytes]
        let tail = unsafe { core::slice::from_raw_parts((pos - 4) as *const u8, 4) };
        let _tlv_type = u16::from_le_bytes([tail[0], tail[1]]);
        let tlv_len = u16::from_le_bytes([tail[2], tail[3]]) as usize;
        
        // Sanity check
        if tlv_len > 1024 || pos < (4 + tlv_len) {
            return Err(BootError::InvalidTLV);
        }
        
        // Move to start of this TLV's value
        pos -= 4 + tlv_len;
    }
    
    Ok(pos)
}
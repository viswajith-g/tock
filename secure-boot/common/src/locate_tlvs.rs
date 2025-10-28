// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Kernel and TLVs location discovery by scanning backwards from application start

use crate::error::BootError;
// use crate::types::KernelRegion;
// use crate::BoardConfig;
use crate::BootloaderIO;
use crate::attributes_parser;

const TOCK: [u8; 4] = [84, 79, 67, 75];

/// Potential kernel found in flash
#[derive(Debug, Clone, Copy)]
pub struct PotentialKernel {
    pub start_address: usize,
    pub size: usize,
    pub attributes_start: usize,
    pub attributes_end: usize,
}

// /// Scans the kernel region backwards from APP_START to find the "TOCK" sentinel
// pub fn define_kernel_region<C: BoardConfig>() -> Result<KernelRegion, BootError> {
//     let app_start = C::APP_START;
//     let kernel_start = C::KERNEL_START;
    
//     // Find "TOCK" sentinel by scanning backwards from app_start
//     let sentinel_address = find_tock_sentinel(app_start)?;
    
//     // Scan TLVs backwards to find actual start of attributes
//     let attributes_start = scan_tlvs(sentinel_address)?;
    
//     Ok(KernelRegion {
//         start: kernel_start,
//         end: attributes_start,
//         entry_point: kernel_start, // _stext is kernel start
//         attributes_start,
//     })
// }

/// Scan flash region for potential kernels
/// 
/// Searches forward through the given flash range looking for TOCK sentinels.
/// Returns up to 8 potential kernels (signature verification happens separately).
pub fn scan_for_potential_kernels<IO: BootloaderIO>(
    scan_start: usize,
    scan_end: usize,
    io: &IO,
) -> Result<[Option<PotentialKernel>; 8], BootError> {
    let mut kernels: [Option<PotentialKernel>; 8] = [None; 8];
    let mut kernel_count = 0;
    let mut buf = [0u8; 32];

    // io.debug("scanning");
    // io.debug("scan_start:");
    // io.format(scan_start, &mut buf);
    // io.debug("scan_end:");
    // io.format(scan_end, &mut buf);
    
    // Align to word boundary
    let mut current_addr = (scan_start + 3) & !3;

    io.debug("current_address:");
    io.format(current_addr, &mut buf);
    
    while current_addr < scan_end && kernel_count < 8 {
        // Look for next TOCK sentinel
        if let Some(sentinel_addr) = find_tock_sentinel(current_addr, scan_end, io) {
            // Try to parse basic kernel info
            match parse_kernel_info(sentinel_addr, current_addr, io) {
                Ok(kernel) => {
                    io.debug("Found a kernel");
                    kernels[kernel_count] = Some(kernel);
                    kernel_count += 1;
                    
                    // Skip past this kernel to continue scanning
                    current_addr = kernel.start_address + kernel.attributes_end;
                    io.debug("current address:");
                    io.format(current_addr, &mut buf);
                }
                Err(_) => {
                    // Couldn't parse this one, skip this sentinel
                    current_addr = sentinel_addr + 4;
                }
            }
        } else {
            // No more sentinels found
            io.debug("no more sentinels");
            break;
        }
    }
    
    Ok(kernels)
}

/// Find next TOCK sentinel in flash range
fn find_tock_sentinel<IO: BootloaderIO>(start: usize, end: usize, io:&IO) -> Option<usize> {
    // Align to word boundary
    let mut addr = (start + 3) & !3;
    // let mut buf = [0u8; 32];
    
    while addr + 4 <= end {
        let bytes = unsafe { 
            core::slice::from_raw_parts(addr as *const u8, 4) 
        };
        
        if bytes == TOCK {
            // io.debug("tock sentinel found:");
            // io.format(addr, &mut buf);
            return Some(addr);
        }
        
        addr += 4;
    }
    
    None
}


/// Parse basic kernel info from a TOCK sentinel location
/// 
/// This extracts kernel boundaries and location but does NOT verify signatures.
fn parse_kernel_info<IO: BootloaderIO>(
    sentinel_addr: usize,
    _kernel_start: usize,
    io: &IO,
) -> Result<PotentialKernel, BootError> {

    let mut buf = [0u8; 32];
    // Find start of attributes (walk backward through TLV chain)
    let attributes_start = scan_tlvs_backward(sentinel_addr, io)?;
    let attributes_end = sentinel_addr + 4;
    
    // Parse attributes to get kernel boundaries
    let attributes = attributes_parser::parse_attributes(attributes_start, attributes_end, io)?;

    // io.debug("parsed attributes");
    
    // Get kernel flash TLV
    let (_kernel_start, kernel_len) = attributes.kernel_flash
        .ok_or(BootError::InvalidTLV)?;
    
    // // let kernel_start = kernel_start as usize;
    let kernel_size = kernel_len as usize;
    // let kernel_size = attributes_end - kernel_start;
    let actual_kernel_start = attributes_start.checked_sub(kernel_size)
        .ok_or(BootError::InvalidKernelRegion)?;
    // let actual_kernel_start = ker

    io.debug("attributes start:");
    io.format(attributes_start, &mut buf);
    io.debug("actual kernel start (calculated):");
    io.format(actual_kernel_start, &mut buf);
    io.debug("kernel size (from TLV):");
    io.format(kernel_size, &mut buf);

    // io.debug("Kernel start and size:");
    // io.format(kernel_start, &mut buf);
    // io.debug("kernel size: ");
    // io.format(kernel_size, &mut buf);
    
    // Sanity checks
    if actual_kernel_start >= attributes_start {
        return Err(BootError::InvalidKernelRegion);
    }

    io.debug("kernel start sanity check passed");

    Ok(PotentialKernel {
        start_address: actual_kernel_start,
        size: kernel_size,
        attributes_start,
        attributes_end,
    })
}


/// Scan TLVs backward from TOCK sentinel to find start of attributes
/// 
/// Layout in flash: [...kernel code...] [TLVs...] [Version/Reserved] [TOCK]
/// Given the TOCK location, this walks backward through the TLV chain
/// to find where the attributes section starts.
fn scan_tlvs_backward<IO: BootloaderIO>(sentinel_address: usize, io: &IO) -> Result<usize, BootError> {
    let mut pos = sentinel_address;
    let mut buf = [0u8; 32];
    // io.debug("Scanning for TLVs");
    // Skip past TOCK sentinel (4 bytes)
    if pos < 4 {
        // io.debug("Invalid TLV1");
        return Err(BootError::InvalidTLV);
    }
    pos -= 4; // Now at Version/Reserved (end of TLV chain)

    const VALID_TLV_TYPES: [u16; 5] = [
        0x0101, // App Memory
        0x0102, // Kernel Flash
        0x0103, // Version
        0x0104, // Relocations
        0x0105, // Signature
    ];
    
    // Walk backward through TLV chain
    loop {
        if pos < 8 {
            return Err(BootError::InvalidTLV);
        }
        
        // Read TLV header
        let header = unsafe { 
            core::slice::from_raw_parts((pos - 4) as *const u8, 4) 
        };
        let tlv_type = u16::from_le_bytes([header[0], header[1]]);
        let tlv_len = u16::from_le_bytes([header[2], header[3]]) as usize;

        io.debug("TLV Length");
        io.format(tlv_len, &mut buf);

        if !VALID_TLV_TYPES.contains(&tlv_type) {
            // Hit garbage data - we've gone past the start
            return Ok(pos);
        }
        
        // Sanity check
        if pos < (4 + tlv_len) {
            return Err(BootError::InvalidTLV);
        }
        
        // Move to start of this TLV's value
        pos -= 4 + tlv_len;

        // io.debug("size of attributes:");
        // io.format((sentinel_address - pos), &mut buf);
        
        // Check if this is the signature TLV (type 0x0105)
        // If so, we've reached the start of attributes
        if tlv_type == 0x0104 {
            io.debug("found start addr of attributes");
            io.format(pos, &mut buf);

            io.debug("size of attributes:");
            io.format(sentinel_address - pos, &mut buf);
            // pos -= 4 + tlv_len;
            return Ok(pos);
        }
    }
}


// /// Searches from app_start in reverse to find the "TOCK" sentinel
// fn find_tock_sentinel(app_start: usize) -> Result<usize, BootError> {
    
//     // Assuming the sentinel will be within 512 bytes before app_start
//     let search_start = app_start.saturating_sub(512);
    
//     // Search backwards, checking every 4-byte aligned address
//     let mut addr = app_start - 4;
//     while addr >= search_start {
//         let bytes = unsafe { 
//             core::slice::from_raw_parts(addr as *const u8, 4) 
//         };
        
//         if bytes == TOCK {
//             return Ok(addr);
//         }
        
//         if addr < 4 {
//             break;
//         }
//         addr -= 4;
//     }
    
//     Err(BootError::SentinelNotFound)
// }

// /// Scan TLVs backwards from sentinel to find start of attributes
// fn scan_tlvs(sentinel_address: usize) -> Result<usize, BootError> {
//     // Layout: [... TLVs ...] [Version/Reserved] [TOCK]
//     // After finding TOCK, skip it to get to the end of the TLV chain
//     let mut pos = sentinel_address;
    
//     // Skip TOCK pos is at start of Version/Reserved, 
//     // which is the end of the TLV chain
//     if pos < 4 {
//         return Err(BootError::InvalidTLV);
//     }
//     pos -= 4;
    
//     // Walk backwards through TLVs
//     for _ in 0..16 {  // Assuming a max of 16 TLVs
//         if pos < 8 {
//             break; // Reached beginning (last TLV)
//         }
        
//         // Read TLV tail: [Type: 2 bytes][Length: 2 bytes]
//         let tail = unsafe { core::slice::from_raw_parts((pos - 4) as *const u8, 4) };
//         let _tlv_type = u16::from_le_bytes([tail[0], tail[1]]);
//         let tlv_len = u16::from_le_bytes([tail[2], tail[3]]) as usize;
        
//         // Sanity check
//         if tlv_len > 1024 || pos < (4 + tlv_len) {
//             return Err(BootError::InvalidTLV);
//         }
        
//         // Move to start of this TLV's value
//         pos -= 4 + tlv_len;
//     }
    
//     Ok(pos)
// }

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_word_alignment() {
        assert_eq!((0x9000 + 3) & !3, 0x9000);
        assert_eq!((0x9001 + 3) & !3, 0x9004);
        assert_eq!((0x9003 + 3) & !3, 0x9004);
    }
}
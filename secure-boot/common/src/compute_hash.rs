// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! SHA-256 hash computation for kernel image verification

use crate::error::BootError;
use sha2::{Digest, Sha256};
use crate::types::{KernelRegion, SignatureAttribute};

#[inline(always)]
fn in_flash(addr: usize) -> bool {
    // Assuming 1MB flash size
    addr < 0x0010_0000
}

#[inline(always)]
fn range_ok(start: usize, end: usize) -> bool {
    start <= end && in_flash(start) && in_flash(end)
}

/// Wrapper to verifies all address ranges before reading.
/// Hashes [region.start .. kernel_end) with the 64-byte signature zeroed.
pub fn compute_kernel_hash(
    region: &KernelRegion,
    signature: &SignatureAttribute,
    kernel_end: usize,
) -> Result<[u8; 32], BootError> {
    let kernel_start = region.start;
    let kernel_end = kernel_end;
    let (signature_start, signature_end) = signature.location;

    // Basic checks
    if !(range_ok(kernel_start, kernel_end) && kernel_end > kernel_start) {
        return Err(BootError::HashError);
    }
    if signature_end.checked_sub(signature_start).unwrap_or(0) != 64 {
        return Err(BootError::InvalidSignature);
    }
    if signature_start < kernel_start || signature_end > kernel_end {
        return Err(BootError::InvalidSignature);
    }

    // let storage_range = storage.map(|(start, len)| {
    //     (start as usize, start as usize + len as usize)
    // });

    // // Validate storage range is within kernel region if present
    // if let Some((ss, se)) = storage_range {
    //     if ss < kernel_start || se > kernel_end {
    //         return Err(BootError::InvalidKernelRegion);
    //     }
    // }

    let mut hasher = Sha256::new();

    unsafe {
        // Hash [kernel_start .. signature_start)
        if signature_start > kernel_start {
            if !range_ok(kernel_start, signature_start) {
                return Err(BootError::HashError);
            }
            let pre_signature = core::slice::from_raw_parts(kernel_start as *const u8, signature_start - kernel_start);
            hasher.update(pre_signature);
        }

        // Hash 64 zeros instead of the key
        hasher.update(&[0u8; 64]);

        // Hash [signature_end .. kernel_end)
        if kernel_end > signature_end {
            if !range_ok(signature_end, kernel_end) {
                return Err(BootError::HashError);
            }
            let post_signature = core::slice::from_raw_parts(signature_end as *const u8, kernel_end - signature_end);
            hasher.update(post_signature);
        }
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Ok(out)
}
// pub fn compute_kernel_hash(
//     region: &KernelRegion,
//     signature: &SignatureAttribute,
//     kernel_end: usize,
//     storage: Option<(u32, u32)>,
// ) -> Result<[u8; 32], BootError> {
//     let kernel_start = region.start;
//     let (signature_start, signature_end) = signature.location;

//     if !(range_ok(kernel_start, kernel_end) && kernel_end > kernel_start) {
//         return Err(BootError::HashError);
//     }
//     if signature_end.checked_sub(signature_start).unwrap_or(0) != 64 {
//         return Err(BootError::InvalidSignature);
//     }
//     if signature_start < kernel_start || signature_end > kernel_end {
//         return Err(BootError::InvalidSignature);
//     }

//     // Build and validate storage skip range
//     let storage_range = match storage {
//         Some((start, len)) => {
//             let s = start as usize;
//             let e = s.checked_add(len as usize).ok_or(BootError::InvalidKernelRegion)?;
//             if s < kernel_start || e > kernel_end {
//                 return Err(BootError::InvalidKernelRegion);
//             }
//             if !range_ok(s, e) {
//                 return Err(BootError::HashError);
//             }
//             Some((s, e))
//         }
//         None => None,
//     };

//     // Build sorted list of excluded ranges (start, end, replacement_bytes)
//     // replacement_bytes: None = skip entirely, Some(slice) = hash these instead
//     let mut skips: [(usize, usize, bool); 2] = [
//         (signature_start, signature_end, true),   // true = zero-fill
//         (usize::MAX, usize::MAX, false),           // placeholder
//     ];

//     if let Some((ss, se)) = storage_range {
//         skips[1] = (ss, se, false); // false = skip entirely
//     }

//     // Sort by start address
//     if skips[0].0 > skips[1].0 {
//         skips.swap(0, 1);
//     }

//     // Sanity check: ranges must not overlap
//     if skips[1].0 != usize::MAX && skips[0].1 > skips[1].0 {
//         return Err(BootError::InvalidKernelRegion);
//     }

//     let mut hasher = Sha256::new();
//     let mut cursor = kernel_start;

//     unsafe {
//         for (skip_start, skip_end, zero_fill) in skips {
//             if skip_start == usize::MAX {
//                 break;
//             }

//             // Hash bytes before this skip
//             if cursor < skip_start {
//                 if !range_ok(cursor, skip_start) {
//                     return Err(BootError::HashError);
//                 }
//                 let chunk = core::slice::from_raw_parts(
//                     cursor as *const u8,
//                     skip_start - cursor,
//                 );
//                 hasher.update(chunk);
//             }

//             // Either zero-fill or skip entirely
//             if zero_fill {
//                 hasher.update(&[0u8; 64]);
//             }

//             cursor = skip_end;
//         }

//         // Hash remaining bytes after all skips
//         if cursor < kernel_end {
//             if !range_ok(cursor, kernel_end) {
//                 return Err(BootError::HashError);
//             }
//             let tail = core::slice::from_raw_parts(
//                 cursor as *const u8,
//                 kernel_end - cursor,
//             );
//             hasher.update(tail);
//         }
//     }

//     let mut out = [0u8; 32];
//     out.copy_from_slice(&hasher.finalize());
//     Ok(out)
// }

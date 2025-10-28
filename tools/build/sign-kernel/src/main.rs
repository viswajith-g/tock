// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Kernel signing tool for Tock secure boot
//! Sign a Tock kernel image: hash [kernel_start..attr_end_paddr), zeroing the signature
//! window inside .attributes, then write signature back into the ELF.
//!
//! cargo add anyhow clap goblin p256 sha2

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use goblin::elf::{program_header::PT_LOAD, Elf};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

// /// Adjust to your board/bootloader split.
// const kernel_start: usize = 0x0000_8000;
// const attr_end_paddr: usize = 0x0004_0000;

/// TLV layout: value is r || s || algo_id
const TLV_TYPE_SIGNATURE: u16 = 0x0105;
const TLV_TYPE_KERNEL_FLASH: u16 = 0x0102;

const SIG_RS_LEN: usize = 64;
const SIG_ALGO_LEN: usize = 4;
const SIG_VALUE_LEN: usize = SIG_RS_LEN + SIG_ALGO_LEN;

// Match your bootloader.
const ALGO_ECDSA_P256_SHA256: u32 = 1;

#[derive(Parser, Debug)]
#[command(author, version, about = "Sign a Tock kernel ELF for secure boot")]
struct Args {
    /// Path to kernel ELF
    kernel: PathBuf,

    /// PEM file containing the P-256 private key (overrides built-in).
    #[arg(long)]
    key: Option<PathBuf>,

    /// Output path; defaults to in-place overwrite of input ELF.
    #[arg(long)]
    out: Option<PathBuf>,
}

// Demo key. Do NOT use in production.
const PRIVATE_KEY_PEM: &str = r#"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9kwjBrAc65xuZSsE
x31rkSDpTl68NRjLbG/ioUPqbaahRANCAATKUz70xgjmgxHR+dTVUB19r8vwFRZO
jSkAzRxjMKf8Ih+c69XR6R9rgQOu4DIi/7zSdghcAShr/8okxhZp1NEd
-----END PRIVATE KEY-----
"#;

fn main() -> Result<()> {
    let args = Args::parse();
    let out_path = args.out.clone().unwrap_or_else(|| args.kernel.clone());

    let mut elf_bytes = fs::read(&args.kernel).context("read ELF")?;
    let elf = Elf::parse(&elf_bytes).context("parse ELF")?;

    // 1) Locate .attributes + its PT_LOAD → get physical base of attributes
    let (attr_off, attr_size) = locate_attributes(&elf, &elf_bytes)?;
    let attr_seg = segment_containing_offset(&elf, attr_off, attr_size)
        .context("PT_LOAD containing .attributes not found")?;
    let attr_paddr = (attr_seg.p_paddr as usize) + (attr_off - attr_seg.p_offset as usize);
    let attr_slice = &elf_bytes[attr_off..attr_off + attr_size];

    // 2) Parse TLVs in .attributes (walk backwards)
    let (sig_val_off_in_attr, _sig_hdr_off_in_attr) =
        find_tlv_value(attr_slice, TLV_TYPE_SIGNATURE)
            .context("Signature TLV not found")?;
    let (_kern_flash_val_off_in_attr, kern_flash_len) =
        parse_kernel_flash_len(attr_slice)
            .context("Kernel Flash TLV (0x0102) not found")?;

    // Physical addresses
    let sig_value_paddr = attr_paddr + sig_val_off_in_attr;

    // IMPORTANT: set hash window to [kernel_start_paddr .. attributes_end_paddr)
    let attributes_end_paddr   = attr_paddr + attr_size;
    let kernel_len             = kern_flash_len as usize; // TLV length is just the kernel length field we read
    let kernel_start_paddr     = attr_paddr.checked_sub(kernel_len)
        .context("attributes_end < kernel_len")?;

    println!("Hashing flash region 0x{kernel_start_paddr:08x}..0x{attributes_end_paddr:08x} ({} bytes)",
             attributes_end_paddr - kernel_start_paddr);

    // Gather PT_LOADs (sorted by p_paddr) for a flash view
    let mut loads: Vec<_> = elf.program_headers.iter().cloned().filter(|ph| ph.p_type == PT_LOAD).collect();
    loads.sort_by_key(|ph| ph.p_paddr);

    // 3) Compute digest over that window, zeroing signature value bytes
    let digest = hash_flash_window(
        &elf_bytes,
        &loads,
        kernel_start_paddr,
        attributes_end_paddr,
        sig_value_paddr,
        SIG_RS_LEN, // 64; only the signature r||s is zeroed while hashing
    )?;

    // 4) Sign and write back (unchanged)
    let signing_key_pem = if let Some(path) = args.key {
        fs::read_to_string(path).context("read private key PEM")?
    } else {
        PRIVATE_KEY_PEM.to_string()
    };
    let sk = SigningKey::from_pkcs8_pem(signing_key_pem.trim()).context("load private key")?;
    let sig: Signature = sk.sign_prehash(&digest).context("sign_prehash")?;
    let rs = sig.to_bytes();

    // Overwrite signature value (r||s) + algo id as before
    let sig_value_off_in_elf = attr_off + sig_val_off_in_attr;
    elf_bytes[sig_value_off_in_elf .. sig_value_off_in_elf + SIG_RS_LEN].copy_from_slice(&rs);
    elf_bytes[sig_value_off_in_elf + SIG_RS_LEN .. sig_value_off_in_elf + SIG_VALUE_LEN]
        .copy_from_slice(&ALGO_ECDSA_P256_SHA256.to_le_bytes());

    fs::write(&out_path, &elf_bytes).context("write signed ELF")?;
    println!("Signed kernel saved to {}", out_path.display());
    Ok(())
}

// ---------- helpers -----------

/// Find a TLV by type; returns (value_start_offset_in_attr, header_offset_in_attr)
fn find_tlv_value(attr: &[u8], tlv_type: u16) -> Result<(usize, usize)> {
    if attr.len() < 8 { return Err(anyhow!(".attributes too small")); }
    if &attr[attr.len()-4..] != b"TOCK" { return Err(anyhow!("TOCK sentinel not found")); }
    let mut pos = attr.len() - 8; // just before version/reserved
    for _ in 0..128 {
        if pos < 4 { break; }
        let t  = u16::from_le_bytes([attr[pos-4], attr[pos-3]]);
        let ln = u16::from_le_bytes([attr[pos-2], attr[pos-1]]) as usize;
        if pos < 4 + ln { return Err(anyhow!("malformed TLV chain")); }
        let value_start = pos - 4 - ln;
        let header_off  = pos - 4;
        if t == tlv_type { return Ok((value_start, header_off)); }
        pos = value_start;
    }
    Err(anyhow!(format!("TLV 0x{tlv_type:04x} not found")))
}   

/// Parse Kernel Flash TLV (0x0102) and return (ignored_start, len)
fn parse_kernel_flash_len(attr: &[u8]) -> Result<(u32, u32)> {
    let (value_off, _hdr) = find_tlv_value(attr, TLV_TYPE_KERNEL_FLASH)?;
    let v = &attr[value_off .. value_off + 8];
    let start = u32::from_le_bytes([v[0],v[1],v[2],v[3]]); // link-time ORIGIN(rom), not used
    let len   = u32::from_le_bytes([v[4],v[5],v[6],v[7]]);
    Ok((start, len))
}

fn locate_attributes<'a>(elf: &Elf<'a>, bytes: &'a [u8]) -> Result<(usize, usize)> {
    let (off, size) = elf
        .section_headers
        .iter()
        .find_map(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name)?;
            (name == ".attributes").then_some((sh.sh_offset as usize, sh.sh_size as usize))
        })
        .context(".attributes section not found")?;

    if off + size > bytes.len() {
        return Err(anyhow!(".attributes extends beyond file"));
    }
    Ok((off, size))
}

fn segment_containing_offset<'a>(
    elf: &'a Elf<'_>,
    off: usize,
    size: usize,
) -> Option<&'a goblin::elf::ProgramHeader> {
    elf.program_headers.iter().find(|ph| {
        ph.p_type == PT_LOAD
            && (off as u64) >= ph.p_offset
            && ((off + size) as u64) <= ph.p_offset + ph.p_filesz
    })
}

/// Verify a [start..start+len) lies within [range_start..range_end).
fn ensure_window_in_region(
    start: usize,
    len: usize,
    range_start: usize,
    range_end: usize,
) -> Result<()> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| anyhow!("overflow computing window end"))?;
    if start < range_start || end > range_end {
        Err(anyhow!(
            "window 0x{start:08x}..0x{end:08x} not inside 0x{range_start:08x}..0x{range_end:08x}"
        ))
    } else {
        Ok(())
    }
}


/// Find Kernel Flash TLV to get kernel region bounds
fn find_kernel_flash_tlv(attr: &[u8]) -> Result<(usize, usize)> {
    if attr.len() < 8 {
        return Err(anyhow!(".attributes too small"));
    }

    // Verify trailing TOCK sentinel
    let tail = &attr[attr.len() - 8..];
    if tail[4..8] != *b"TOCK" {
        return Err(anyhow!("attributes sentinel 'TOCK' not found at end"));
    }

    // Walk TLVs backwards
    let mut pos = attr.len() - 8;
    for _ in 0..64 {
        if pos < 4 {
            break;
        }
        
        let tlv_type = u16::from_le_bytes([attr[pos - 4], attr[pos - 3]]);
        let tlv_len = u16::from_le_bytes([attr[pos - 2], attr[pos - 1]]) as usize;

        if pos < 4 + tlv_len {
            return Err(anyhow!("malformed TLV chain"));
        }
        
        let value_start = pos - 4 - tlv_len;

        if tlv_type == TLV_TYPE_KERNEL_FLASH {
            if tlv_len != 8 {
                return Err(anyhow!("Kernel Flash TLV wrong length: {}", tlv_len));
            }
            
            let value = &attr[value_start..value_start + 8];
            let start = u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize;
            let length = u32::from_le_bytes([value[4], value[5], value[6], value[7]]) as usize;
            
            return Ok((start, length));
        }

        pos = value_start;
    }

    Err(anyhow!("Kernel Flash TLV (0x{TLV_TYPE_KERNEL_FLASH:04x}) not found"))
}

/// Find Signature TLV **value** start offset inside `.attributes`.
/// Attributes end with: [Reserved/Version]["TOCK"]
/// TLVs precede those, each as [Value...][Type: 2 bytes][Length: 2 bytes] (walk backwards).
fn find_signature_tlv_value(attr: &[u8]) -> Result<usize> {
    if attr.len() < 8 {
        return Err(anyhow!(".attributes too small"));
    }

    // Verify trailing TOCK + version+reserved.
    let tail = &attr[attr.len() - 8..];
    if tail[4..8] != *b"TOCK" {
        return Err(anyhow!("attributes sentinel 'TOCK' not found at end"));
    }

    // Walk TLVs backwards.
    let mut pos = attr.len() - 8; // just before version/reserved
    for _ in 0..64 {
        if pos < 4 {
            break;
        }
        // [Type:2][Len:2] at (pos-4..pos), little-endian.
        let tlv_type = u16::from_le_bytes([attr[pos - 4], attr[pos - 3]]);
        let tlv_len = u16::from_le_bytes([attr[pos - 2], attr[pos - 1]]) as usize;

        if pos < 4 + tlv_len {
            return Err(anyhow!("malformed TLV chain in attributes"));
        }
        let value_start = pos - 4 - tlv_len;

        if tlv_type == TLV_TYPE_SIGNATURE {
            if tlv_len != SIG_VALUE_LEN {
                return Err(anyhow!(
                    "Signature TLV length {}, expected {}",
                    tlv_len,
                    SIG_VALUE_LEN
                ));
            }
            return Ok(value_start);
        }

        // Move to previous TLV
        pos = value_start;
    }

    Err(anyhow!(
        "Signature TLV (0x{TLV_TYPE_SIGNATURE:04x}) not found"
    ))
}

/// Hash the flash view of [win_start..win_end).
/// For each PT_LOAD overlapping that window:
///   - hash bytes present in file,
///   - pad (memsz - filesz) with 0x00,
///   - pad gaps between segments with 0x00,
///   - zero the subrange [sig_paddr .. sig_paddr + sig_len) while hashing.
fn hash_flash_window(
    elf_bytes: &[u8],
    loads: &[goblin::elf::ProgramHeader],
    win_start: usize,
    win_end: usize,
    sig_paddr: usize,
    sig_len: usize,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut cur = win_start;

    for ph in loads {
        let seg_start = ph.p_paddr as usize;
        let seg_end = seg_start + ph.p_memsz as usize;

        if seg_end <= win_start {
            continue;
        }
        if seg_start >= win_end {
            break;
        }

        // Pad any gap before this segment.
        if seg_start > cur {
            hash_fill(&mut hasher, seg_start - cur, 0x00);
            // cur = seg_start;
        }

        // Clip segment to window
        let h_start = seg_start.max(win_start);
        let h_end = seg_end.min(win_end);
        let h_len = h_end - h_start;

        if ph.p_filesz > 0 {
            // Portion backed by file bytes
            let seg_file_start = ph.p_offset as usize;
            let seg_file_end = seg_file_start + ph.p_filesz as usize;

            let file_range_start = seg_file_start + (h_start - seg_start);
            let file_range_end = (file_range_start + h_len).min(seg_file_end);

            // Hash the file-backed portion with signature area zeroed.
            if file_range_start < file_range_end {
                let data = &elf_bytes[file_range_start..file_range_end];
                hash_data_with_sig_zero(&mut hasher, data, h_start, sig_paddr, sig_paddr + sig_len);

                // If memsz exceeds filesz within the clipped span, pad tail
                let hashed_len = file_range_end - file_range_start;
                if hashed_len < h_len {
                    hash_fill(&mut hasher, h_len - hashed_len, 0x00);
                }
            } else {
                // No file bytes visible in this clipped range
                hash_fill(&mut hasher, h_len, 0x00);
            }
        } else {
            // Entire segment is memory-only in this file
            hash_fill(&mut hasher, h_len, 0x00);
        }

        cur = h_end;
    }

    // Pad any remaining tail of the window
    if cur < win_end {
        hash_fill(&mut hasher, win_end - cur, 0x00);
    }

    let digest = hasher.finalize();
    Ok(digest.into())
}

fn hash_fill(hasher: &mut Sha256, size: usize, byte: u8) {
    let mut buf = [0u8; 4096];
    buf.fill(byte);
    let mut rem = size;
    while rem > 0 {
        let chunk = rem.min(buf.len());
        hasher.update(&buf[..chunk]);
        rem -= chunk;
    }
}

/// Hash `data` whose flash address starts at `region_start`. If it overlaps
/// `[sig_start..sig_end)`, hash zeros for that overlap.
fn hash_data_with_sig_zero(
    hasher: &mut Sha256,
    data: &[u8],
    region_start: usize,
    sig_start: usize,
    sig_end: usize,
) {
    let region_end = region_start + data.len();

    // No overlap
    if sig_end <= region_start || sig_start >= region_end {
        hasher.update(data);
        return;
    }

    let ovl_start = sig_start.max(region_start) - region_start;
    let ovl_end = sig_end.min(region_end) - region_start;

    if ovl_start > 0 {
        hasher.update(&data[..ovl_start]);
    }

    // zeros for overlap
    let zeros_len = ovl_end.saturating_sub(ovl_start);
    if zeros_len > 0 {
        // SIG_RS_LEN cap is fine; but handle larger overlaps generically
        let zeros = [0u8; SIG_VALUE_LEN];
        let mut rem = zeros_len;
        while rem > 0 {
            let chunk = rem.min(zeros.len());
            hasher.update(&zeros[..chunk]);
            rem -= chunk;
        }
    }

    if ovl_end < data.len() {
        hasher.update(&data[ovl_end..]);
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

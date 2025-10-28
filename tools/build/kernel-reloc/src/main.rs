// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Relocation extraction and embedding tool for Tock kernels
//!
//! Extract R_ARM_ABS32 relocations from a kernel ELF and embed them into the
//! relocation TLV that lives inside `.attributes`, with a dynamically computed
//! TLV length.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use goblin::elf::{section_header, Elf};
use std::fs;
use std::path::PathBuf;

/// ARM relocation types
const R_ARM_ABS32: u32 = 2;

/// Optional overall safety cap (tool will still clamp to reserved space)
const MAX_RELOCATIONS: usize = 10_000;

/// Flash address range (only keep relocations targeting flash)
const FLASH_START: u32 = 0x0000_0000;
const FLASH_END:   u32 = 0x0010_0000; // 1MB

/// TLV type for kernel relocations (value only; header is [type:2][len:2])
const TLV_TYPE_RELOCATION: u16 = 0x0104;

#[derive(Parser, Debug)]
#[command(name = "kernel-reloc")]
#[command(about = "Extract and embed relocations in Tock kernel ELF")]
struct Args {
    /// Input ELF file (modified in-place unless --out is given)
    #[arg(help = "Path to kernel ELF file")]
    elf_path: PathBuf,

    /// Optional output file (defaults to in-place)
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct RelocationEntry {
    offset: u32,         // offset from kernel start (link_address)
    original_value: u32, // absolute target value before relocation
    rel_type: u8,        // == 2 (R_ARM_ABS32)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let out_path = args.out.clone().unwrap_or_else(|| args.elf_path.clone());

    println!("Processing: {}", args.elf_path.display());

    // Read + parse ELF
    let mut elf_bytes = fs::read(&args.elf_path).context("Failed to read ELF file")?;
    let elf = Elf::parse(&elf_bytes).context("Failed to parse ELF")?;

    // Link address (start of .text)
    let link_address = get_link_address(&elf)?;
    println!("Kernel link address: 0x{:08x}", link_address);

    // Collect relocations across ALL SHT_REL sections (e.g., .rel.text, .rel.rodata, …)
    // let relocations = extract_relocations_text_only(&elf, &elf_bytes, link_address)?;
    let relocations = extract_runtime_relocations(&elf, &elf_bytes, link_address)?;
    println!(
        "Found {} R_ARM_ABS32 relocations pointing to flash",
        relocations.len()
    );
    if relocations.is_empty() {
        eprintln!("Warning: No relocations found. Kernel may not be relocatable.");
    }
    if relocations.len() > MAX_RELOCATIONS {
        bail!(
            "Too many relocations: {} (cap: {})",
            relocations.len(),
            MAX_RELOCATIONS
        );
    }

    // Locate .attributes in file space
    let (attr_off, attr_size) = locate_attributes(&elf, &elf_bytes)?;

    // Find (by type) the relocation TLV inside .attributes (walking backwards)
    let tlv_lookup = find_tlv_value_and_header(
        &elf_bytes[attr_off..attr_off + attr_size],
        TLV_TYPE_RELOCATION,
    );

    // Resolve header/value/capacity
    let (rel_value_off_in_elf, rel_header_off_in_elf, value_capacity_bytes) = match tlv_lookup {
        Ok((value_start_in_attr, header_off_in_attr, existing_len)) => {
            let header_off_in_elf = attr_off + header_off_in_attr;

            if existing_len == 0 {
                // Header is present but length is a placeholder (0) → use labels for capacity
                let anchors = find_reloc_anchors(&elf)?;
                let start_off  = vaddr_to_file_offset(&elf, anchors.value_start_vaddr)?;
                let header_off = vaddr_to_file_offset(&elf, anchors.header_vaddr)?;
                (start_off, header_off, header_off - start_off)
            } else {
                // Real TLV already present; capacity is distance to header
                let value_off = attr_off + value_start_in_attr;
                (value_off, header_off_in_elf, header_off_in_attr - value_start_in_attr)
            }
        }
        Err(_) => {
            // No TLV found by type → fall back to labels
            let anchors = find_reloc_anchors(&elf)?;
            let start_off  = vaddr_to_file_offset(&elf, anchors.value_start_vaddr)?;
            let header_off = vaddr_to_file_offset(&elf, anchors.header_vaddr)?;
            (start_off, header_off, header_off - start_off)
        }
    };

    // Capacity checks
    if value_capacity_bytes < 8 {
        bail!("Relocation TLV value area too small (< 8 bytes)");
    }
    let entries_bytes_capacity = value_capacity_bytes - 8;
    let entries_cap = entries_bytes_capacity / 12;

    // Clamp number of entries to reserved capacity
    let num_entries = relocations.len().min(entries_cap);
    if num_entries < relocations.len() {
        eprintln!(
            "Warning: {} relocations found, clamped to capacity {}",
            relocations.len(),
            entries_cap
        );
    }

    // Compute TLV length we will write (value only)
    let tlv_len_u32 = 8 + (num_entries as u32) * 12;
    let tlv_len_u16 = tlv_len_u32 as u16;

    // ---- WRITE VALUE **BACKWARDS FROM THE HEADER** ----
    // let value_start_for_write = rel_header_off_in_elf - (tlv_len_u32 as usize);
    // let mut pos = value_start_for_write;
    let mut pos = rel_value_off_in_elf;

    // link_address
    elf_bytes[pos..pos + 4].copy_from_slice(&link_address.to_le_bytes());
    pos += 4;

    // num_entries
    elf_bytes[pos..pos + 4].copy_from_slice(&(num_entries as u32).to_le_bytes());
    pos += 4;

    // entries
    for r in relocations.iter().take(num_entries) {
        elf_bytes[pos..pos + 4].copy_from_slice(&r.offset.to_le_bytes());         pos += 4;
        elf_bytes[pos..pos + 4].copy_from_slice(&r.original_value.to_le_bytes()); pos += 4;
        elf_bytes[pos] = r.rel_type;                                              pos += 1;
        elf_bytes[pos..pos + 3].fill(0);                                          pos += 3;
    }

    // Write back
    fs::write(&out_path, &elf_bytes).context("Failed to write modified ELF")?;
    println!("Successfully embedded {} relocations", num_entries);
    Ok(())
}

// ---------- Relocation collection ----------

/// Extract R_ARM_ABS32 relocations only from `.rel.text`,
/// keep only those whose original value points to flash,
/// convert to (offset-from-link-address).
fn extract_runtime_relocations(
    elf: &Elf,
    elf_data: &[u8],
    link_address: u32,
) -> Result<Vec<RelocationEntry>> {
    let mut out = Vec::new();

    // Process both .rel.text and .rel.relocate
    for sh in &elf.section_headers {
        if sh.sh_type != section_header::SHT_REL {
            continue;
        }

        let section_name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        
        // Only process .rel.text and .rel.relocate
        if section_name != ".rel.text" && section_name != ".rel.relocate" {
            continue;
        }

        println!("Processing {}", section_name);

        let start = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        if start + size > elf_data.len() {
            eprintln!("Warning: {} extends beyond file", section_name);
            continue;
        }
        
        let rel_data = &elf_data[start..start + size];
        if rel_data.len() % 8 != 0 {
            eprintln!("Warning: {} size is not a multiple of 8", section_name);
            continue;
        }

        for chunk in rel_data.chunks_exact(8) {
            let offset = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let info = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            let rel_type = info & 0xff;

            if rel_type != R_ARM_ABS32 {
                continue;
            }

            // Read original value at that vaddr
            let original_value = match read_u32_at_vaddr(elf, elf_data, offset) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Warning: cannot read value at 0x{offset:08x} from {}: {e}", section_name);
                    continue;
                }
            };

            // Keep only flash targets
            if !(FLASH_START..FLASH_END).contains(&original_value) {
                continue;
            }

            let koff = match offset.checked_sub(link_address) {
                Some(k) => k,
                None => {
                    eprintln!("Warning: relocation offset 0x{offset:08x} precedes link address 0x{link_address:08x}");
                    continue;
                }
            };

            out.push(RelocationEntry {
                offset: koff,
                original_value,
                rel_type: R_ARM_ABS32 as u8,
            });
        }
    }

    out.sort_by_key(|r| r.offset);
    out.dedup_by_key(|r| r.offset);  // Remove any duplicates
    Ok(out)
}


// ---------- ELF helpers ----------

/// Get the kernel's link address from the .text section start
fn get_link_address(elf: &Elf) -> Result<u32> {
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name == ".text" {
                return Ok(sh.sh_addr as u32);
            }
        }
    }
    bail!("Could not find .text section to determine link address");
}

// Anchors resolved from linker-script labels
struct RelocAnchors {
    value_start_vaddr: u64,
    header_vaddr: u64,
}

/// Find `_tock_attr_reloc_start` and `_tock_attr_reloc_header` in the ELF symtab.
/// These are the labels you defined in the linker script around the relocation TLV.
fn find_reloc_anchors(elf: &goblin::elf::Elf) -> Result<RelocAnchors> {
    let mut start = None;
    let mut header = None;

    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            match name {
                "_tock_attr_reloc_start"  => start = Some(sym.st_value),
                "_tock_attr_reloc_header" => header = Some(sym.st_value),
                _ => {}
            }
        }
    }

    match (start, header) {
        (Some(vs), Some(h)) if h > vs => Ok(RelocAnchors {
            value_start_vaddr: vs,
            header_vaddr: h,
        }),
        _ => bail!("relocation TLV labels not found; ensure linker defines _tock_attr_reloc_start/_tock_attr_reloc_header"),
    }
}

fn find_section_offset(elf: &Elf, vaddr: u64) -> Option<(usize /*file_off*/, usize /*within_section*/)> {
    for sh in &elf.section_headers {
        let start = sh.sh_addr;
        let end = start + sh.sh_size;
        if vaddr >= start && vaddr < end {
            let delta = (vaddr - start) as usize;
            return Some((sh.sh_offset as usize + delta, delta));
        }
    }
    None
}

/// Read a u32 at a given vaddr (search sections and translate to file offset)
fn read_u32_at_vaddr(elf: &Elf, data: &[u8], vaddr: u32) -> Result<u32> {
    let (file_off, _) = find_section_offset(elf, vaddr as u64)
        .ok_or_else(|| anyhow!("vaddr 0x{vaddr:08x} not in any section"))?;
    let bytes = &data[file_off..file_off + 4];
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn vaddr_to_file_offset(elf: &Elf, vaddr: u64) -> Result<usize> {
    let (file_off, _) = find_section_offset(elf, vaddr)
        .ok_or_else(|| anyhow!("vaddr 0x{vaddr:08x} not in any section"))?;
    Ok(file_off)
}

/// Locate `.attributes` in the ELF (file offset + size)
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

/// Find a TLV by type in `.attributes` (walks backwards).
/// Returns (value_start_off, header_off, value_len), all **relative to the start of `.attributes`**.
fn find_tlv_value_and_header(attr: &[u8], tlv_type_target: u16) -> Result<(usize, usize, usize)> {
    if attr.len() < 8 {
        return Err(anyhow!(".attributes too small"));
    }

    // Trailer: [Reserved:3][Version:1]["TOCK":4]
    let tail = &attr[attr.len() - 8..];
    if tail[4..8] != *b"TOCK" {
        return Err(anyhow!("attributes sentinel 'TOCK' not found at end"));
    }

    // Start just before the version/reserved area
    let mut pos = attr.len() - 8;

    // Walk TLVs backwards: ... [Value][Type:2][Len:2] [Value][Type][Len] ... [Version/Reserved]["TOCK"]
    for _ in 0..512 {
        if pos < 4 {
            break;
        }
        let ty = u16::from_le_bytes([attr[pos - 4], attr[pos - 3]]);
        let ln = u16::from_le_bytes([attr[pos - 2], attr[pos - 1]]) as usize;

        if pos < 4 + ln {
            return Err(anyhow!("malformed TLV chain in attributes"));
        }
        let value_start = pos - 4 - ln;
        let header_off  = pos - 4;

        if ty == tlv_type_target {
            return Ok((value_start, header_off, ln));
        }

        pos = value_start; // previous TLV
    }

    Err(anyhow!(format!("TLV 0x{tlv_type_target:04x} not found")))
}

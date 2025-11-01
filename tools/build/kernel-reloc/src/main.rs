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
// use goblin::elf::program_header::PT_LOAD;
use goblin::elf::program_header::{PT_LOAD, PF_X, PF_R};
use goblin::elf64::section_header::{SHF_WRITE, SHF_EXECINSTR, SHF_ALLOC, SHN_UNDEF};
use goblin::elf64::header::{ET_DYN, ET_EXEC};
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

fn rom_image_end_from_phdrs(elf: &goblin::elf::Elf) -> u32 {

    let mut hi = 0u64;
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        // Treat anything mapped below SRAM as ROM/Flash
        if ph.p_vaddr < 0x2000_0000 {
            let end = ph.p_vaddr.saturating_add(ph.p_memsz);
            if end > hi {
                hi = end;
            }
        }
    }
    // Fallback: if nothing matched, keep a conservative 1 MiB top
    (if hi == 0 { 0x0010_0000 } else { hi }) as u32
}


fn main() -> Result<()> {
    let args = Args::parse();
    let out_path = args.out.clone().unwrap_or_else(|| args.elf_path.clone());

    println!("Processing: {}", args.elf_path.display());

    // Read + parse ELF
    let mut elf_bytes = fs::read(&args.elf_path).context("Failed to read ELF file")?;
    let elf = Elf::parse(&elf_bytes).context("Failed to parse ELF")?;

    println!("ELF type: {:?}", elf.header.e_type);

    let syms = build_sym_index(&elf);

    // Link address (start of .text)
    let link_address = get_link_address(&elf)?;
    println!("Kernel link address: 0x{:08x}", link_address);

    // Existing symbols
    let srelocate = get_sym_addr_u32(&elf, "_srelocate")?;
    let erelocate = get_sym_addr_u32(&elf, "_erelocate")?;
    let etext     = get_sym_addr_u32(&elf, "_etext")?;

    // Derive the true ROM image end from PT_LOAD segments (NOT _sattributes)
    let rom_image_end = rom_image_end_from_phdrs(&elf);

    eprintln!(
        "SYM _srelocate=0x{:08x} _erelocate=0x{:08x} _etext=0x{:08x} ROM_END=0x{:08x}",
        srelocate, erelocate, etext, rom_image_end
    );

    // // UPDATED CALL: pass rom_image_end
    // let relocations = extract_runtime_relocations(
    //     &elf,
    //     &elf_bytes,
    //     link_address,
    //     srelocate,
    //     erelocate,
    //     etext,
    //     rom_image_end,
    // )?;

    let mut relocations = extract_runtime_relocations(
        &elf, &elf_bytes, link_address, srelocate, erelocate, etext, rom_image_end
    )?;

    // existing offsets (from real REL entries)
    let existing: std::collections::HashSet<u32> =
        relocations.iter().map(|r| r.offset).collect();

    let synthetic = find_missing_relocations(
        &elf,
        &elf_bytes,
        link_address,
        srelocate,
        erelocate,
        etext,
        rom_image_end,
        &syms,
        &existing,
    );

    relocations.extend(synthetic);
    relocations.sort_by_key(|r| r.offset);
    relocations.dedup_by_key(|r| r.offset);

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

    // let n_text     = relocations.iter().filter(|r| r.offset < 0x100000).count();
    // let n_raminit  = /* count entries whose site_vaddr had been mapped from relocate window, if you tracked it */;
    // println!("#relocs total={} text_like={} raminit_like={}", relocations.len(), n_text, n_raminit);
    Ok(())
}

// ---------- Relocation collection ----------

/// Extract R_ARM_ABS32 relocations only from `.rel.text`,
/// keep only those whose original value points to flash,
/// convert to (offset-from-link-address).
// fn extract_runtime_relocations(
//     elf: &Elf,
//     elf_data: &[u8],
//     link_address: u32,
//     srelocate: u32,
//     erelocate: u32,
//     etext: u32,
//     image_end: u32, // NEW: end bound for “inside kernel image”
// ) -> Result<Vec<RelocationEntry>> {
//     use goblin::elf::header::{ET_DYN, ET_EXEC, ET_REL};
//     use goblin::elf::section_header::{SHT_REL, SHF_ALLOC};

//     // Keep these local so this stays drop-in.
//     const R_ARM_ABS32: u8 = 2;

//     // Safety margin: don’t emit relocations that target the vector table
//     const VT_BYTES: u32 = 100 * 4;

//     let mut out = Vec::new();
//     let mut skipped_nonimage = 0usize;
//     let mut cnt_text = 0usize;
//     let mut cnt_reloc = 0usize;

//     // Map a VMA (runtime address) back to a file offset for reading original bytes.
//     fn vaddr_to_file_off(elf: &Elf, vaddr: u64) -> Option<usize> {
//         use goblin::elf::program_header::PT_LOAD;

//         // Prefer program headers (accurate for ET_EXEC/ET_DYN)
//         for ph in &elf.program_headers {
//             if ph.p_type == PT_LOAD {
//                 let start = ph.p_vaddr;
//                 let end = ph.p_vaddr + ph.p_memsz;
//                 if vaddr >= start && vaddr + 4 <= end {
//                     let delta = (vaddr - start) as usize;
//                     if delta + 4 <= ph.p_filesz as usize {
//                         return Some(ph.p_offset as usize + delta);
//                     }
//                 }
//             }
//         }
//         // Fall back to sections
//         for sh in &elf.section_headers {
//             let start = sh.sh_addr;
//             let end = start + sh.sh_size;
//             if vaddr >= start && vaddr + 4 <= end {
//                 let delta = (vaddr - start) as usize;
//                 return Some(sh.sh_offset as usize + delta);
//             }
//         }
//         None
//     }

//     // ET_EXEC/ET_DYN => r_offset is absolute VMA
//     // ET_REL         => r_offset is section-relative
//     let is_exec_like = matches!(elf.header.e_type, ET_EXEC | ET_DYN);

//     for (relsec_idx, relsec) in elf.section_headers.iter().enumerate() {
//         if relsec.sh_type != SHT_REL {
//             continue;
//         }

//         let tgt_idx = relsec.sh_info as usize;
//         if tgt_idx >= elf.section_headers.len() {
//             continue;
//         }
//         let tgt = &elf.section_headers[tgt_idx];

//         if (tgt.sh_flags & (SHF_ALLOC as u64)) == 0 {
//             continue; // only loaded sections
//         }

//         let tgt_name = elf.shdr_strtab.get_at(tgt.sh_name).unwrap_or("");
//         if tgt_name.starts_with(".debug")
//             || matches!(tgt_name, ".comment" | ".symtab" | ".strtab" | ".shstrtab" | ".attributes")
//         {
//             continue;
//         }

//         let start = relsec.sh_offset as usize;
//         let size = relsec.sh_size as usize;
//         if start + size > elf_data.len() || size % 8 != 0 {
//             eprintln!("Warning: bad REL section {} (idx {})", tgt_name, relsec_idx);
//             continue;
//         }

//         let tgt_base = tgt.sh_addr as u32;
//         let tgt_end  = tgt.sh_addr + tgt.sh_size;

//         for rec in elf_data[start..start + size].chunks_exact(8) {
//             let r_offset = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
//             let r_info   = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
//             let rel_type = (r_info & 0xff) as u8;

//             if rel_type != R_ARM_ABS32 {
//                 continue;
//             }

//             // --- Compute the site VMA correctly for the ELF type ---
//             let site_vaddr = if is_exec_like {
//                 // In ET_EXEC/ET_DYN, r_offset is already a VMA
//                 r_offset
//             } else {
//                 // In ET_REL, r_offset is section-relative — normalize
//                 if (r_offset as u64) >= tgt.sh_addr && (r_offset as u64) < tgt_end {
//                     r_offset
//                 } else {
//                     tgt_base.saturating_add(r_offset)
//                 }
//             };

//             // If this relocation site belongs to .relocate (RAM at runtime),
//             // the original bytes to patch *live in flash* at:
//             //   flash_site = _etext + (site - _srelocate)
//             let flash_site_vaddr = if site_vaddr >= srelocate && site_vaddr < erelocate {
//                 etext.saturating_add(site_vaddr - srelocate)
//             } else {
//                 site_vaddr
//             };

//             // Read the original 4-byte word from the file (at the flash site)
//             let file_off = match vaddr_to_file_off(elf, flash_site_vaddr as u64) {
//                 Some(o) if o + 4 <= elf_data.len() => o,
//                 _ => {
//                     eprintln!(
//                         "Warning: cannot map site 0x{:08x} for {}",
//                         flash_site_vaddr, tgt_name
//                     );
//                     continue;
//                 }
//             };
//             let original_value = u32::from_le_bytes([
//                 elf_data[file_off + 0],
//                 elf_data[file_off + 1],
//                 elf_data[file_off + 2],
//                 elf_data[file_off + 3],
//             ]);

//             // Strip Thumb bit for filtering (preserve it when writing out)
//             let base = original_value & !1;

//             // (A) Drop null/silly constants
//             if base == 0 {
//                 continue;
//             }

//             // (B) Keep only targets inside the actual kernel image:
//             //     [link_address .. image_end) — excludes .attributes/TLVs and outside flash noise.
//             if base < link_address || base >= image_end {
//                 if skipped_nonimage < 16 {
//                     eprintln!(
//                         "skip(out-of-image): site=0x{flash_site_vaddr:08x} sec={tgt_name} orig=0x{original_value:08x}"
//                     );
//                 }
//                 skipped_nonimage += 1;
//                 continue;
//             }

//             // Offset of the site from the kernel link address (to patch at runtime)
//             let site_off_from_link = match flash_site_vaddr.checked_sub(link_address) {
//                 Some(k) => k,
//                 None => {
//                     eprintln!(
//                         "Warning: site 0x{:08x} precedes link addr 0x{:08x}",
//                         flash_site_vaddr, link_address
//                     );
//                     continue;
//                 }
//             };

//             // (C) Do not emit relocations for the vector-table (first 100 words)
//             if site_off_from_link < VT_BYTES {
//                 continue;
//             }

//             if tgt_name == ".text"     { cnt_text  += 1; }
//             if tgt_name == ".relocate" { cnt_reloc += 1; }

//             out.push(RelocationEntry {
//                 offset: site_off_from_link,
//                 original_value,
//                 rel_type, // R_ARM_ABS32
//             });
//         }
//     }

//     eprintln!(
//         "counts: .text={} .relocate={} total={} (skipped_nonimage={})",
//         cnt_text, cnt_reloc, cnt_text + cnt_reloc, skipped_nonimage
//     );

//     out.sort_by_key(|r| r.offset);
//     out.dedup_by_key(|r| r.offset);
//     Ok(out)
// }

fn extract_runtime_relocations(
    elf: &Elf,
    elf_data: &[u8],
    link_address: u32,
    srelocate: u32,
    erelocate: u32,
    etext: u32,
    rom_image_end: u32,
) -> Result<Vec<RelocationEntry>> {
    use goblin::elf::section_header::{SHT_REL, SHF_ALLOC};

    const REL_T: u8 = R_ARM_ABS32 as u8;
    const VT_BYTES: u32 = 100 * 4;

    let is_exec_like = matches!(elf.header.e_type, ET_EXEC | ET_DYN);
    let is_rel       = matches!(elf.header.e_type, ET_REL);

    let mut out = Vec::new();
    let mut cnt_text = 0usize;
    let mut cnt_reloc = 0usize;

    for (relsec_idx, relsec) in elf.section_headers.iter().enumerate() {
        if relsec.sh_type != SHT_REL { continue; }

        let tgt_idx = relsec.sh_info as usize;
        if tgt_idx >= elf.section_headers.len() { continue; }
        let tgt = &elf.section_headers[tgt_idx];

        // only loaded targets
        if (tgt.sh_flags & (SHF_ALLOC as u64)) == 0 { continue; }

        let tgt_name = elf.shdr_strtab.get_at(tgt.sh_name).unwrap_or("");
        if tgt_name.starts_with(".debug")
            || matches!(tgt_name, ".comment" | ".symtab" | ".strtab" | ".shstrtab" | ".attributes")
        {
            continue;
        }

        let start = relsec.sh_offset as usize;
        let size  = relsec.sh_size as usize;
        if start + size > elf_data.len() || size % 8 != 0 {
            eprintln!("Warning: bad REL section {} (idx {})", tgt_name, relsec_idx);
            continue;
        }

        let tgt_base = tgt.sh_addr as u32;
        let tgt_end  = (tgt.sh_addr + tgt.sh_size) as u32;

        for rec in elf_data[start..start + size].chunks_exact(8) {
            let r_offset = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
            let r_info   = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
            let rel_type = (r_info & 0xff) as u8;
            if rel_type != REL_T { continue; }

            // Compute the *site* VMA
            // - ET_EXEC/ET_DYN: r_offset is already a VMA
            // - ET_REL: r_offset is section-relative (to target) — normalize
            let site_vaddr = if is_exec_like {
                r_offset
            } else if is_rel {
                if (r_offset as u64) >= tgt.sh_addr && (r_offset as u64) < (tgt.sh_addr + tgt.sh_size) {
                    r_offset
                } else {
                    tgt_base.saturating_add(r_offset)
                }
            } else {
                // should not happen, be conservative
                tgt_base.saturating_add(r_offset)
            };

            // Where do the *original bytes to patch* live in FLASH?
            // For sites that will reside in RAM at runtime (.relocate), their init bytes are in flash at:
            //    flash_site = _etext + (site - _srelocate)
            // Otherwise, the site bytes are already in flash at site_vaddr.
            let flash_site_vaddr = if site_vaddr >= srelocate && site_vaddr < erelocate {
                etext.saturating_add(site_vaddr - srelocate)
            } else {
                site_vaddr
            };

            // Map to file and read the original 32-bit word EXACTLY (preserve Thumb bit)
            let file_off = match vaddr_to_file_off(elf, flash_site_vaddr) {
                Some(o) if o + 4 <= elf_data.len() => o,
                _ => {
                    eprintln!("Warning: cannot map site 0x{:08x} (tgt={})", flash_site_vaddr, tgt_name);
                    continue;
                }
            };
            let original_value = u32::from_le_bytes([
                elf_data[file_off + 0],
                elf_data[file_off + 1],
                elf_data[file_off + 2],
                elf_data[file_off + 3],
            ]);

            // Sanity filter: keep only targets inside the actual kernel image,
            // and drop null constants. Compare on base (mask Thumb) but *store* full value.
            let base = original_value & !1;
            if base == 0 { continue; }
            if base < link_address || base >= rom_image_end {
                continue;
            }

            // Offset of site from link_address (what the loader adds to physical base)
            let off = match flash_site_vaddr.checked_sub(link_address) {
                Some(o) => o,
                None => continue,
            };

            if off < VT_BYTES { continue; } // don't patch vector table

            if tgt_name == ".text"     { cnt_text  += 1; }
            if tgt_name == ".relocate" { cnt_reloc += 1; }

            out.push(RelocationEntry {
                offset: off,
                original_value, // keep Thumb bit intact!
                rel_type: REL_T,
            });
        }
    }

    eprintln!("counts: .text={} .relocate={} total={}", cnt_text, cnt_reloc, out.len());
    out.sort_by_key(|r| r.offset);
    out.dedup_by_key(|r| r.offset);
    eprintln!("After dedup: {} relocations", out.len());

    // small sample so you can hexdump-verify quickly
    for r in out.iter().take(6) {
        eprintln!("SAMPLE reloc @+0x{:06x} orig=0x{:08x}", r.offset, r.original_value);
    }

    Ok(out)
}


fn find_missing_relocations(
    elf: &Elf,
    elf_data: &[u8],
    link_address: u32,
    srelocate: u32,
    erelocate: u32,
    etext: u32,
    rom_image_end: u32,
    syms: &SymIndex,
    existing_offsets: &std::collections::HashSet<u32>,
) -> Vec<RelocationEntry> {
    let mut synthetic = Vec::new();

    // vaddr -> file offset
    fn vaddr_to_file_off(elf: &Elf, vaddr: u32) -> Option<usize> {
        for sh in &elf.section_headers {
            let start = sh.sh_addr as u32;
            let end   = start.saturating_add(sh.sh_size as u32);
            if vaddr >= start && vaddr < end {
                let delta = vaddr - start;
                return Some((sh.sh_offset as u32 + delta) as usize);
            }
        }
        for ph in &elf.program_headers {
            if ph.p_type == PT_LOAD {
                let start = ph.p_vaddr as u32;
                let end   = start.saturating_add(ph.p_filesz as u32);
                if vaddr >= start && vaddr < end {
                    let delta = vaddr - start;
                    return Some((ph.p_offset as u32 + delta) as usize);
                }
            }
        }
        None
    }

    // Flash image of .relocate: bytes are at [etext .. etext + (erelocate - srelocate))
    let init_start = match vaddr_to_file_off(elf, etext) {
        Some(off) => off,
        None => {
            eprintln!("Warning: Cannot find file offset for _etext");
            return synthetic;
        }
    };
    let init_size = (erelocate - srelocate) as usize;
    let init_end  = init_start + init_size;
    if init_end > elf_data.len() {
        eprintln!("Warning: .relocate init extends beyond file");
        return synthetic;
    }

    eprintln!(
        "Scanning for synthetic relocations: file offset 0x{:x} to 0x{:x}",
        init_start, init_end
    );

    for file_off in (init_start..init_end).step_by(4) {
        let word = u32::from_le_bytes([
            elf_data[file_off + 0],
            elf_data[file_off + 1],
            elf_data[file_off + 2],
            elf_data[file_off + 3],
        ]);

        // Quick rejects
        let base = word & !1;
        if base < (link_address + 0x100) || base >= rom_image_end {
            continue;
        }
        if !vaddr_maps_to_rom_ptload(elf, base) {
            continue;
        }
        match classify_vaddr(elf, base) {
            SectClass::Text | SectClass::Rodata | SectClass::Exidx => {}
            _ => continue,
        }

        // *** NEW, STRONG FILTER: must match a known symbol ***
        let looks_like_symbol =
            syms.func_addrs_even.contains(&(base))     // function stored without T-bit
            || syms.func_addrs_thumb.contains(&(base)) // function stored with T-bit
            || syms.obj_addrs.contains(&(word));       // objects must match exactly (no T-bit)

        if !looks_like_symbol {
            continue; // drop constants like 0x0400, 0x1236, etc.
        }

        // Site address in flash for this .relocate word
        let flash_vaddr = etext + ((file_off - init_start) as u32);
        let offset = flash_vaddr - link_address;

        if !existing_offsets.contains(&offset) {
            eprintln!(
                "Synthetic: file_off=0x{:08x} flash_vaddr=0x{:08x} offset=0x{:08x} value=0x{:08x}",
                file_off, flash_vaddr, offset, word
            );
            synthetic.push(RelocationEntry {
                offset,
                original_value: word,  // preserve T-bit on funcs
                rel_type: 2,
            });
        }
    }

    eprintln!("Found {} synthetic relocations", synthetic.len());
    synthetic
}


// fn extract_runtime_relocations(
//     elf: &Elf,
//     elf_data: &[u8],
//     link_address: u32,
//     srelocate: u32,
//     etext: u32,
// ) -> Result<Vec<RelocationEntry>> {
//     use goblin::elf::section_header::SHT_REL;

//     let mut out = Vec::new();

//     for sh in &elf.section_headers {
//         if sh.sh_type != SHT_REL {
//             continue;
//         }
//         let section_name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");

//         // Only runtime-relevant relocations:
//         // if section_name != ".rel.text" && section_name != ".rel.relocate" {
//         //     continue;
//         // }
//         if section_name != ".rel.text"
//         && section_name != ".rel.relocate"
//         && section_name != ".rel.got"
//         && section_name != ".rel.rodata" {
//             continue;
//         }

//         let start = sh.sh_offset as usize;
//         let size  = sh.sh_size as usize;
//         if start + size > elf_data.len() || size % 8 != 0 {
//             continue;
//         }

//         for chunk in elf_data[start..start + size].chunks_exact(8) {
//             let r_offset = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
//             let r_info   = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
//             let rel_type = (r_info & 0xff) as u8;
//             if rel_type != R_ARM_ABS32 as u8 {
//                 continue;
//             }

//             // Compute the *flash* address where the relocation site bytes live.
//             // - For .rel.text: site is already in flash at r_offset.
//             // - For .rel.relocate: RAM site r_offset is initialized from flash at:
//             //     flash_site = _etext + (r_offset - _srelocate)
//             let flash_site_vaddr = if section_name == ".rel.relocate" {
//                 if r_offset < srelocate {
//                     // malformed; skip
//                     continue;
//                 }
//                 let delta = r_offset - srelocate;
//                 etext.checked_add(delta).unwrap_or_default()
//             } else {
//                 // .rel.text
//                 r_offset
//             };

//             // Read the original (linked) 32-bit target value from the *flash* site
//             let original_value = match read_u32_at_vaddr(elf, elf_data, flash_site_vaddr) {
//                 Ok(v) => v,
//                 Err(_) => continue,
//             };

//             // Keep only relocations that point into flash (code/consts)
//             if !(FLASH_START..FLASH_END).contains(&original_value) {
//                 continue;
//             }

//             // Store offset relative to kernel link address, always as a *flash* site
//             let site_off_from_link = match flash_site_vaddr.checked_sub(link_address) {
//                 Some(k) => k,
//                 None => continue,
//             };

//             out.push(RelocationEntry {
//                 offset: site_off_from_link,
//                 original_value,
//                 rel_type,
//             });
//         }
//     }

//     out.sort_by_key(|r| r.offset);
//     out.dedup_by_key(|r| r.offset);
//     Ok(out)
// }



// ---------- ELF helpers ----------

// --- mapper: prefer PT_LOAD first (accurate for ET_EXEC/ET_DYN), then sections ---
fn vaddr_to_file_off(elf: &Elf, vaddr: u32) -> Option<usize> {

    // PT_LOAD first
    for ph in &elf.program_headers {
        if ph.p_type == PT_LOAD {
            let start = ph.p_vaddr as u32;
            let end   = start.saturating_add(ph.p_filesz as u32);
            if vaddr >= start && vaddr + 4 <= end {
                let delta = vaddr - start;
                return Some((ph.p_offset as u32 + delta) as usize);
            }
        }
    }
    // fall back to section headers
    for sh in &elf.section_headers {
        let start = sh.sh_addr as u32;
        let end   = start.saturating_add(sh.sh_size as u32);
        if vaddr >= start && vaddr + 4 <= end {
            let delta = vaddr - start;
            return Some((sh.sh_offset as u32 + delta) as usize);
        }
    }
    None
}

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

fn get_sym_addr_u32(elf: &goblin::elf::Elf, name: &str) -> anyhow::Result<u32> {
    for sym in &elf.syms {
        if let Some(n) = elf.strtab.get_at(sym.st_name) {
            if n == name {
                return Ok(sym.st_value as u32);
            }
        }
    }
    anyhow::bail!("symbol `{name}` not found");
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

#[inline]
fn sect_name<'a>(elf: &'a goblin::elf::Elf, shndx: usize) -> &'a str {
    elf.shdr_strtab.get_at(elf.section_headers[shndx].sh_name).unwrap_or("")
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SectClass { Text, Rodata, Exidx, Other, NotInImage }

fn classify_vaddr(elf: &goblin::elf::Elf, vaddr: u32) -> SectClass {
    // Find section by vaddr
    let mut idx: Option<usize> = None;
    for (i, sh) in elf.section_headers.iter().enumerate() {
        let start = sh.sh_addr as u32;
        let end   = start.saturating_add(sh.sh_size as u32);
        if vaddr >= start && vaddr < end {
            idx = Some(i);
            break;
        }
    }
    let Some(i) = idx else { return SectClass::NotInImage; };
    let sh = &elf.section_headers[i];

    // Must be loaded into memory
    if (sh.sh_flags & (SHF_ALLOC as u64)) == 0 {
        return SectClass::NotInImage;
    }

    let name = sect_name(elf, i);

    // Executable code?
    if (sh.sh_flags & (SHF_EXECINSTR as u64)) != 0 {
        return SectClass::Text;
    }

    // Explicit exidx is allowed (not writable, ALLOC)
    if name == ".ARM.exidx" {
        return SectClass::Exidx;
    }

    // Read-only data: ALLOC but not WRITE
    let is_write = (sh.sh_flags & (SHF_WRITE as u64)) != 0;
    if !is_write {
        return SectClass::Rodata;
    }

    SectClass::Other
}

fn vaddr_maps_to_rom_ptload(elf: &goblin::elf::Elf, vaddr: u32) -> bool {
    use goblin::elf::program_header::{PT_LOAD, PF_R};

    let mut saw_ptload = false;
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD { continue; }
        saw_ptload = true;
        let start = ph.p_vaddr as u32;
        let end   = start.saturating_add(ph.p_memsz as u32);
        if vaddr >= start && vaddr < end {
            // Treat PT_LOAD < SRAM as ROM; require readable
            if start < 0x2000_0000 && (ph.p_flags & (PF_R as u32)) != 0 {
                return true;
            }
        }
    }

    if !saw_ptload {
        // Fallback: section-class check (ALLOC and below SRAM)
        for sh in &elf.section_headers {
            let start = sh.sh_addr as u32;
            let end   = start.saturating_add(sh.sh_size as u32);
            if vaddr >= start && vaddr < end {
                let alloc = (sh.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64) != 0;
                return alloc && start < 0x2000_0000;
            }
        }
    }

    false
}

#[derive(Default)]
struct SymIndex {
    // Even-aligned code addresses for STT_FUNC (no T-bit)
    func_addrs_even: std::collections::HashSet<u32>,
    // Thumb-form code addresses (even|1) so we can accept stored Thumb pointers directly
    func_addrs_thumb: std::collections::HashSet<u32>,
    // Data/rodata symbol addresses (STT_OBJECT or NOTYPE in ALLOC & !WRITE)
    obj_addrs: std::collections::HashSet<u32>,
}

fn build_sym_index(elf: &goblin::elf::Elf) -> SymIndex {
    use goblin::elf::sym::*;

    let mut idx = SymIndex::default();

    // Utility: check if a section index is ALLOC, and optionally whether it's writable.
    let mut sect_flags = Vec::with_capacity(elf.section_headers.len());
    for sh in &elf.section_headers {
        sect_flags.push(sh.sh_flags as u64);
    }

    for sym in &elf.syms {
        // if sym.st_shndx == STN_UNDEF as usize { continue; }
        if sym.st_shndx == SHN_UNDEF as usize { continue; }
        if sym.st_size == 0 { /* still OK for funcs/labels */ }

        let shndx = sym.st_shndx as usize;
        if shndx >= elf.section_headers.len() { continue; }
        let flags = sect_flags[shndx];

        // Only symbols that actually get ALLOCed into the image
        if (flags & (SHF_ALLOC as u64)) == 0 { continue; }

        let v = sym.st_value as u32;

        match sym.st_type() {
            STT_FUNC => {
                // Save both forms (even == code base; thumb == base|1)
                let even = v & !1;
                idx.func_addrs_even.insert(even);
                idx.func_addrs_thumb.insert(even | 1);
            }
            STT_OBJECT | STT_NOTYPE => {
                // Treat NOTYPE conservatively: only if section is read-only (ALLOC, !WRITE)
                let is_write = (flags & (SHF_WRITE as u64)) != 0;
                if !is_write {
                    idx.obj_addrs.insert(v);
                }
            }
            _ => {}
        }
    }

    idx
}

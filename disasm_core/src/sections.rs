//! Section / segment enumeration with executable flagging and Shannon entropy.
//!
//! Backs the `sections()` table function and feeds the `disassemble` sweep
//! (which decodes the executable sections). Every container parse is wrapped so
//! a malformed blob yields zero sections, never a panic; declared sizes are
//! clamped to the actual blob length so a lying header cannot read out of
//! bounds.

use goblin::Object;

use crate::limits::{MAX_SECTIONS, MAX_SECTION_BYTES};

/// One section / segment of a container.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (`.text`, `__text`, …); empty if unnamed.
    pub name: String,
    /// `code | data | rodata | bss | debug | other`.
    pub kind: String,
    /// Virtual address of the section (absolute VA; for PE, image base + RVA).
    pub vaddr: u64,
    /// Declared section size in bytes (virtual size; may exceed file bytes).
    pub size: u64,
    /// File offset of the section's bytes.
    pub file_off: u64,
    /// True if the section is executable.
    pub exec: bool,
    /// Shannon entropy (bits/byte, 0..8) over the available file bytes; 0.0 when
    /// the section occupies no file bytes (e.g. `.bss`).
    pub entropy: f64,
    /// `(offset, len)` into the original blob for the section's readable file
    /// bytes, already clamped to the blob length and to [`MAX_SECTION_BYTES`].
    /// `None` for sections with no file bytes.
    pub data_range: Option<(usize, usize)>,
}

impl Section {
    /// Borrow the section's file bytes from the original blob, honoring the
    /// clamped `data_range`. Empty slice if the section has no file bytes.
    pub fn bytes<'a>(&self, blob: &'a [u8]) -> &'a [u8] {
        match self.data_range {
            Some((off, len)) if off <= blob.len() => {
                let end = off.saturating_add(len).min(blob.len());
                &blob[off..end]
            }
            _ => &[],
        }
    }
}

/// Shannon entropy in bits/byte over `data` (0.0 for empty input).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Compute a clamped `(offset, len)` byte range into a blob of length `blob_len`.
fn clamp_range(off: u64, len: u64, blob_len: usize) -> Option<(usize, usize)> {
    let off = usize::try_from(off).ok()?;
    if off >= blob_len {
        return None;
    }
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    let len = len.min(blob_len - off).min(MAX_SECTION_BYTES);
    if len == 0 {
        None
    } else {
        Some((off, len))
    }
}

/// Enumerate the sections / segments of `bytes`. Returns an empty vector for a
/// raw blob or any parse failure. Bounded to [`MAX_SECTIONS`] rows.
pub fn sections(bytes: &[u8]) -> Vec<Section> {
    parse(bytes).unwrap_or_default()
}

fn parse(bytes: &[u8]) -> Option<Vec<Section>> {
    let obj = Object::parse(bytes).ok()?;
    let mut out = Vec::new();
    match obj {
        Object::Elf(elf) => elf_sections(&elf, bytes, &mut out),
        Object::PE(pe) => pe_sections(&pe, bytes, &mut out),
        Object::Mach(goblin::mach::Mach::Binary(macho)) => mach_sections(&macho, bytes, &mut out),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            if let Some(Ok(goblin::mach::SingleArch::MachO(macho))) = fat.into_iter().next() {
                mach_sections(&macho, bytes, &mut out);
            }
        }
        _ => {}
    }
    out.truncate(MAX_SECTIONS);
    Some(out)
}

fn finalize(mut s: Section, blob: &[u8]) -> Section {
    s.entropy = shannon_entropy(s.bytes(blob));
    s
}

fn elf_sections(elf: &goblin::elf::Elf, blob: &[u8], out: &mut Vec<Section>) {
    const SHF_EXECINSTR: u64 = 0x4;
    const SHF_WRITE: u64 = 0x1;
    const SHT_NOBITS: u32 = 8;
    const SHT_PROGBITS: u32 = 1;
    for sh in &elf.section_headers {
        if out.len() >= MAX_SECTIONS {
            break;
        }
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let exec = sh.sh_flags & SHF_EXECINSTR != 0;
        let nobits = sh.sh_type == SHT_NOBITS;
        let data_range = if nobits {
            None
        } else {
            clamp_range(sh.sh_offset, sh.sh_size, blob.len())
        };
        let kind = if exec {
            "code"
        } else if name.starts_with(".debug") {
            "debug"
        } else if nobits {
            "bss"
        } else if sh.sh_type == SHT_PROGBITS && sh.sh_flags & SHF_WRITE != 0 {
            "data"
        } else if name.starts_with(".rodata") || name == ".rdata" {
            "rodata"
        } else {
            "other"
        };
        out.push(finalize(
            Section {
                name,
                kind: kind.to_string(),
                vaddr: sh.sh_addr,
                size: sh.sh_size,
                file_off: sh.sh_offset,
                exec,
                entropy: 0.0,
                data_range,
            },
            blob,
        ));
    }
}

fn pe_sections(pe: &goblin::pe::PE, blob: &[u8], out: &mut Vec<Section>) {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
    const IMAGE_SCN_CNT_UNINIT: u32 = 0x0000_0080;
    let image_base = pe.image_base;
    for s in &pe.sections {
        if out.len() >= MAX_SECTIONS {
            break;
        }
        let name = s.name().unwrap_or("").trim_end_matches('\0').to_string();
        let ch = s.characteristics;
        let exec = ch & IMAGE_SCN_MEM_EXECUTE != 0 || ch & IMAGE_SCN_CNT_CODE != 0;
        // File bytes are min(virtual_size, size_of_raw_data) at pointer_to_raw_data.
        let raw_len = (s.size_of_raw_data as u64).min(s.virtual_size as u64);
        let uninit = ch & IMAGE_SCN_CNT_UNINIT != 0;
        let data_range = if uninit {
            None
        } else {
            clamp_range(s.pointer_to_raw_data as u64, raw_len, blob.len())
        };
        let kind = if exec {
            "code"
        } else if name.starts_with(".debug") {
            "debug"
        } else if uninit {
            "bss"
        } else if ch & IMAGE_SCN_MEM_WRITE != 0 {
            "data"
        } else if name == ".rdata" || name == ".rodata" {
            "rodata"
        } else {
            "other"
        };
        out.push(finalize(
            Section {
                name,
                kind: kind.to_string(),
                vaddr: image_base + s.virtual_address as u64,
                size: s.virtual_size as u64,
                file_off: s.pointer_to_raw_data as u64,
                exec,
                entropy: 0.0,
                data_range,
            },
            blob,
        ));
    }
}

fn mach_sections(macho: &goblin::mach::MachO, blob: &[u8], out: &mut Vec<Section>) {
    const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
    const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
    const S_TYPE_ZEROFILL: u32 = 0x1; // section type in low 8 bits
    for seg in &macho.segments {
        let segname = seg.name().unwrap_or("").to_string();
        let Ok(sects) = seg.sections() else { continue };
        for (sect, _data) in sects {
            if out.len() >= MAX_SECTIONS {
                break;
            }
            let sectname = sect.name().unwrap_or("").to_string();
            let flags = sect.flags;
            let exec = flags & S_ATTR_PURE_INSTRUCTIONS != 0
                || flags & S_ATTR_SOME_INSTRUCTIONS != 0
                || (segname == "__TEXT" && sectname == "__text");
            let zerofill = flags & 0xff == S_TYPE_ZEROFILL;
            let data_range = if zerofill {
                None
            } else {
                clamp_range(sect.offset as u64, sect.size, blob.len())
            };
            let kind = if exec {
                "code"
            } else if segname.contains("DEBUG") || sectname.contains("debug") {
                "debug"
            } else if zerofill || segname == "__BSS" {
                "bss"
            } else if sectname == "__const" || segname == "__TEXT" {
                "rodata"
            } else if segname == "__DATA" {
                "data"
            } else {
                "other"
            };
            let full = format!("{segname},{sectname}");
            out.push(finalize(
                Section {
                    name: full,
                    kind: kind.to_string(),
                    vaddr: sect.addr,
                    size: sect.size,
                    file_off: sect.offset as u64,
                    exec,
                    entropy: 0.0,
                    data_range,
                },
                blob,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[7, 7, 7, 7]), 0.0);
        let h = shannon_entropy(&(0u8..=255).collect::<Vec<u8>>());
        assert!((h - 8.0).abs() < 1e-9, "uniform bytes → 8 bits, got {h}");
    }

    #[test]
    fn raw_blob_no_sections() {
        assert!(sections(b"hello world not a binary").is_empty());
    }
}

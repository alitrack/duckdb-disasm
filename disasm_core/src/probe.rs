//! Cheap container sniffing and `(arch, mode)` resolution.
//!
//! [`probe`] reads only the container header (via goblin) to answer "what is
//! this and how would I disassemble it" without decoding a single instruction:
//! the format (`pe`/`elf`/`macho`/`fat-macho`/`raw`), the Capstone arch/mode,
//! bitness, endianness, and entry VA. It is the fast pre-filter for a large scan
//! and the backbone of the `format()` and `entrypoint()` scalars.
//!
//! All parsing is wrapped: a truncated or hostile header yields a `raw` probe
//! with empty fields, never a panic.

use goblin::Object;

/// ELF `e_machine` values we map (subset of the full set).
mod elf_machine {
    pub const EM_386: u16 = 3;
    pub const EM_MIPS: u16 = 8;
    pub const EM_PPC: u16 = 20;
    pub const EM_PPC64: u16 = 21;
    pub const EM_S390: u16 = 22;
    pub const EM_ARM: u16 = 40;
    pub const EM_X86_64: u16 = 62;
    pub const EM_AARCH64: u16 = 183;
    pub const EM_RISCV: u16 = 243;
}

/// PE `IMAGE_FILE_MACHINE_*` values we map.
mod pe_machine {
    pub const I386: u16 = 0x014c;
    pub const ARM: u16 = 0x01c0;
    pub const ARMNT: u16 = 0x01c4;
    pub const AMD64: u16 = 0x8664;
    pub const ARM64: u16 = 0xaa64;
    pub const RISCV64: u16 = 0x5064;
}

/// Mach-O `CPU_TYPE_*` values we map (the 0x0100_0000 bit marks 64-bit).
mod mach_cpu {
    pub const X86: u32 = 7;
    pub const X86_64: u32 = 0x0100_0007;
    pub const ARM: u32 = 12;
    pub const ARM64: u32 = 0x0100_000c;
    pub const POWERPC: u32 = 18;
    pub const POWERPC64: u32 = 0x0100_0012;
}

/// The resolved Capstone selection: a worker arch string, its canonical mode
/// string, and an endianness flag. Produced from a container header or from the
/// caller's explicit `arch`/`mode` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchSel {
    /// `x86 | arm | arm64 | mips | ppc | sysz | riscv`.
    pub arch: String,
    /// For x86: `x16|x32|x64`. For 32-bit ARM: `arm|thumb`. For the rest:
    /// `little|big`.
    pub mode: String,
    /// True for big-endian decode (ARM BE, MIPS/PPC/SysZ big).
    pub big_endian: bool,
}

impl ArchSel {
    fn new(arch: &str, mode: &str, big_endian: bool) -> Self {
        ArchSel {
            arch: arch.to_string(),
            mode: mode.to_string(),
            big_endian,
        }
    }
}

/// The result of a container probe.
#[derive(Debug, Clone, Default)]
pub struct Probe {
    /// `pe | elf | macho | fat-macho | raw`.
    pub container: String,
    /// Resolved arch (`x86`, `arm64`, …), or `None` for an unrecognized blob.
    pub arch: Option<String>,
    /// Canonical mode string for the arch, or `None`.
    pub mode: Option<String>,
    /// 16/32/64, or `None`.
    pub bits: Option<u8>,
    /// `little | big`, or `None`.
    pub endian: Option<String>,
    /// Entry-point virtual address, or `None` (raw blob / no entry).
    pub entry: Option<u64>,
}

impl Probe {
    fn raw() -> Self {
        Probe {
            container: "raw".to_string(),
            ..Default::default()
        }
    }

    /// The `(arch, mode, endian)` selection this probe resolved, if any.
    pub fn arch_sel(&self) -> Option<ArchSel> {
        let arch = self.arch.as_ref()?;
        let mode = self.mode.as_ref()?;
        Some(ArchSel::new(
            arch,
            mode,
            self.endian.as_deref() == Some("big"),
        ))
    }
}

/// The architecture tokens the disassembler's `arch` argument accepts — the
/// canonical primary names ([`resolve_explicit`] additionally maps common
/// aliases such as `x64`/`aarch64` onto these). This is the single source of the
/// closed `choices` set the worker advertises for `arch` and the rows of the
/// `supported_targets` reference view, so metadata and behaviour cannot drift.
pub const SUPPORTED_ARCHES: &[&str] = &["x86", "arm", "arm64", "mips", "ppc", "sysz", "riscv"];

/// The decode-mode tokens the disassembler's `mode` argument accepts: `x16` /
/// `x32` / `x64` select the x86 width; `arm` / `thumb` pick the 32-bit ARM
/// instruction set; `big` / `little` set endianness for the remaining arches.
pub const SUPPORTED_MODES: &[&str] = &["x16", "x32", "x64", "arm", "thumb", "big", "little"];

/// Translate an explicit `arch` (+ optional `mode`) argument pair into an
/// [`ArchSel`], applying sensible per-arch mode defaults. Returns `None` for an
/// unknown arch string.
pub fn resolve_explicit(arch: &str, mode: Option<&str>) -> Option<ArchSel> {
    let arch = arch.trim().to_ascii_lowercase();
    let mode = mode.map(|m| m.trim().to_ascii_lowercase());
    let m = mode.as_deref();
    let big = matches!(m, Some("big"));
    let sel = match arch.as_str() {
        "x86" | "x86_64" | "x64" | "i386" => {
            let mode = match m {
                Some("x16") => "x16",
                Some("x32") | Some("32") => "x32",
                // Default x86 to 64-bit, the dominant malware surface.
                Some("x64") | Some("64") | None => "x64",
                _ => "x64",
            };
            ArchSel::new("x86", mode, false)
        }
        "arm" => {
            let mode = match m {
                Some("thumb") => "thumb",
                _ => "arm",
            };
            ArchSel::new("arm", mode, big)
        }
        "arm64" | "aarch64" => ArchSel::new("arm64", if big { "big" } else { "little" }, big),
        "mips" => ArchSel::new("mips", if big { "big" } else { "little" }, big),
        "ppc" | "powerpc" => ArchSel::new("ppc", if big { "big" } else { "little" }, big),
        "sysz" | "s390" | "systemz" => ArchSel::new("sysz", "big", true),
        "riscv" => ArchSel::new("riscv", if big { "big" } else { "little" }, big),
        _ => return None,
    };
    Some(sel)
}

/// Sniff `bytes` as a container, returning a [`Probe`]. Never panics: any parse
/// failure (truncated/hostile header) degrades to a `raw` probe.
pub fn probe(bytes: &[u8]) -> Probe {
    parse(bytes).unwrap_or_else(Probe::raw)
}

fn parse(bytes: &[u8]) -> Option<Probe> {
    let obj = Object::parse(bytes).ok()?;
    Some(match obj {
        Object::Elf(elf) => {
            let big = !elf.little_endian;
            let (arch, mode) = elf_arch(elf.header.e_machine, big, elf.entry);
            Probe {
                container: "elf".to_string(),
                bits: Some(if elf.is_64 { 64 } else { 32 }),
                endian: Some(endian_str(big)),
                entry: Some(elf.entry),
                mode,
                arch,
            }
        }
        Object::PE(pe) => {
            let (arch, mode) = pe_arch(pe.header.coff_header.machine);
            Probe {
                container: "pe".to_string(),
                bits: Some(if pe.is_64 { 64 } else { 32 }),
                endian: Some("little".to_string()),
                // Make the entry absolute (image base + RVA) so it is consistent
                // with the absolute section VAs and `entrypoint()` can locate it.
                entry: Some(pe.image_base + pe.entry as u64),
                mode,
                arch,
            }
        }
        Object::Mach(goblin::mach::Mach::Binary(macho)) => mach_probe(&macho),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            // Report the primary (first) slice for arch/mode/entry, but mark the
            // container fat so callers know there are multiple slices.
            let mut p = Probe {
                container: "fat-macho".to_string(),
                ..Default::default()
            };
            if let Some(Ok(goblin::mach::SingleArch::MachO(macho))) = fat.into_iter().next() {
                let inner = mach_probe(&macho);
                p.arch = inner.arch;
                p.mode = inner.mode;
                p.bits = inner.bits;
                p.endian = inner.endian;
                p.entry = inner.entry;
            }
            p
        }
        _ => Probe::raw(),
    })
}

fn mach_probe(macho: &goblin::mach::MachO) -> Probe {
    let big = !macho.little_endian;
    let (arch, mode) = mach_arch(macho.header.cputype(), big);
    Probe {
        container: "macho".to_string(),
        bits: Some(if macho.is_64 { 64 } else { 32 }),
        endian: Some(endian_str(big)),
        entry: Some(macho.entry),
        mode,
        arch,
    }
}

fn endian_str(big: bool) -> String {
    if big { "big" } else { "little" }.to_string()
}

fn elf_arch(machine: u16, big: bool, entry: u64) -> (Option<String>, Option<String>) {
    use elf_machine::*;
    let (a, m) = match machine {
        EM_386 => ("x86", "x32".to_string()),
        EM_X86_64 => ("x86", "x64".to_string()),
        // ELF ARM: the entry's low bit marks Thumb.
        EM_ARM => (
            "arm",
            if entry & 1 == 1 { "thumb" } else { "arm" }.to_string(),
        ),
        EM_AARCH64 => ("arm64", endian_str(big)),
        EM_MIPS => ("mips", endian_str(big)),
        EM_PPC => ("ppc", endian_str(big)),
        EM_PPC64 => ("ppc", endian_str(big)),
        EM_S390 => ("sysz", "big".to_string()),
        EM_RISCV => ("riscv", endian_str(big)),
        _ => return (None, None),
    };
    (Some(a.to_string()), Some(m))
}

fn pe_arch(machine: u16) -> (Option<String>, Option<String>) {
    use pe_machine::*;
    let (a, m) = match machine {
        I386 => ("x86", "x32"),
        AMD64 => ("x86", "x64"),
        // PE 32-bit ARM is always Thumb-2.
        ARM | ARMNT => ("arm", "thumb"),
        ARM64 => ("arm64", "little"),
        RISCV64 => ("riscv", "little"),
        _ => return (None, None),
    };
    (Some(a.to_string()), Some(m.to_string()))
}

fn mach_arch(cputype: u32, big: bool) -> (Option<String>, Option<String>) {
    use mach_cpu::*;
    let (a, m) = match cputype {
        X86 => ("x86", "x32".to_string()),
        X86_64 => ("x86", "x64".to_string()),
        ARM => ("arm", "arm".to_string()),
        ARM64 => ("arm64", endian_str(big)),
        POWERPC => ("ppc", "big".to_string()),
        POWERPC64 => ("ppc", "big".to_string()),
        _ => return (None, None),
    };
    (Some(a.to_string()), Some(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_blob_probes_raw() {
        let p = probe(b"not a binary at all, just text");
        assert_eq!(p.container, "raw");
        assert!(p.arch.is_none());
        assert!(p.arch_sel().is_none());
    }

    #[test]
    fn explicit_defaults() {
        assert_eq!(
            resolve_explicit("x86", None).unwrap(),
            ArchSel::new("x86", "x64", false)
        );
        assert_eq!(
            resolve_explicit("x86", Some("x32")).unwrap(),
            ArchSel::new("x86", "x32", false)
        );
        assert_eq!(
            resolve_explicit("arm", Some("thumb")).unwrap(),
            ArchSel::new("arm", "thumb", false)
        );
        assert_eq!(
            resolve_explicit("sysz", None).unwrap(),
            ArchSel::new("sysz", "big", true)
        );
        assert!(resolve_explicit("bogus", None).is_none());
    }

    #[test]
    fn empty_is_raw_not_panic() {
        assert_eq!(probe(b"").container, "raw");
    }
}

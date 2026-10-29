//! Entry-point resolution: the container entry VA, the resolved `(arch, mode)`,
//! the file offset of the entry, and the section that contains it.
//!
//! Backs the `entrypoint()` scalar. For a raw blob every field is `None`.

use crate::probe::{self, Probe};
use crate::sections::{self, Section};

/// The resolved entry point.
#[derive(Debug, Clone, Default)]
pub struct EntryPoint {
    /// Resolved arch string, or `None` for a raw blob.
    pub arch: Option<String>,
    /// Resolved mode string, or `None`.
    pub mode: Option<String>,
    /// Entry virtual address, or `None`.
    pub vaddr: Option<u64>,
    /// File offset of the entry byte, or `None` if not mappable to a section.
    pub file_off: Option<u64>,
    /// Name of the section containing the entry VA, or `None`.
    pub section: Option<String>,
}

/// Resolve the entry point of `bytes`.
pub fn entrypoint(bytes: &[u8]) -> EntryPoint {
    let p: Probe = probe::probe(bytes);
    if p.container == "raw" {
        return EntryPoint::default();
    }
    let secs = sections::sections(bytes);
    let vaddr = p.entry;
    let containing: Option<&Section> = vaddr.and_then(|va| {
        secs.iter()
            .find(|s| va >= s.vaddr && va < s.vaddr.saturating_add(s.size))
    });
    let file_off = match (vaddr, containing) {
        (Some(va), Some(s)) => Some(s.file_off + (va - s.vaddr)),
        _ => None,
    };
    EntryPoint {
        arch: p.arch,
        mode: p.mode,
        vaddr,
        file_off,
        section: containing.map(|s| s.name.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_blob_all_none() {
        let e = entrypoint(b"not a binary");
        assert!(e.arch.is_none() && e.vaddr.is_none() && e.section.is_none());
    }
}

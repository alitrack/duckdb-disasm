//! Hard caps that keep every transform **bounded** on adversarial input.
//!
//! The worker's highest-risk input class is the blob *being malware itself*: a
//! crafted header can declare a multi-GB code section, lie about sizes, or pack
//! millions of one-byte "instructions". Every fan-out is clamped so a single
//! hostile blob can never OOM or wedge the worker — it yields a bounded,
//! diagnostic result instead.

/// Maximum number of instruction rows emitted for a single `disassemble` call,
/// summed across every swept section. A crafted huge code section is truncated
/// at this many rows rather than allowed to balloon.
pub const MAX_INSNS: usize = 5_000_000;

/// Maximum number of bytes fed to Capstone from any one section. Capstone is
/// always handed a bounded slice; a lying section size cannot read past this.
pub const MAX_SECTION_BYTES: usize = 64 * 1024 * 1024;

/// Maximum number of section rows returned by `sections`.
pub const MAX_SECTIONS: usize = 4_096;

/// Maximum number of import rows returned by `imports`.
pub const MAX_IMPORTS: usize = 65_536;

/// Maximum number of string rows returned by `strings`.
pub const MAX_STRINGS: usize = 200_000;

/// Maximum length (in characters) of an individual extracted string. Longer
/// runs are truncated to this length so one giant printable run cannot blow up
/// memory.
pub const MAX_STRING_LEN: usize = 4_096;

/// Maximum number of capability rows returned by `capabilities`.
pub const MAX_CAPABILITIES: usize = 4_096;

/// Maximum input blob size considered for entropy / string scanning of the
/// *whole* file (section scans use [`MAX_SECTION_BYTES`]).
pub const MAX_SCAN_BYTES: usize = 256 * 1024 * 1024;

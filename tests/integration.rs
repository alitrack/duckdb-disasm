//! SQL-level integration tests: LOAD the built `.duckdb_extension` into a real
//! in-memory DuckDB and exercise the full function surface (2 scalars).
//!
//! Run: `cargo test --release` (after the cdylib is built and stamped to
//! `target/release/disasm.duckdb_extension`).
//!
//! The fixture is a minimal, hand-built **ELF64 x86-64 executable** (header +
//! one `PT_LOAD` program header, entry VA `0x400000`) written to
//! `test/sample_elf64.blob` by the test harness at runtime, so the test is
//! self-contained (no external binary needed). Note: the bundled v1.1.0 test
//! engine renders a STRUCT's VARCHAR child via `-> 'f'` as *JSON text*
//! (quote-wrapped), while numeric / boolean children CAST cleanly.

use quack_rs::testing::InMemoryDb;

fn db() -> InMemoryDb {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/release/disasm.duckdb_extension");
    assert!(path.exists(), "build first: make release -> {path:?}");
    let d = InMemoryDb::open_unsigned().expect("open in-memory db");
    d.execute_batch(&format!("LOAD '{}'", path.display()))
        .expect("load extension");
    d
}

/// Write the minimal ELF64 x86-64 blob and return it as hex (for `from_hex`).
fn elf64_hex() -> String {
    fn put16(buf: &mut [u8], v: u16, o: usize) {
        buf[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(buf: &mut [u8], v: u32, o: usize) {
        buf[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(buf: &mut [u8], v: u64, o: usize) {
        buf[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    let mut b = vec![0u8; 64 + 56 + 0x400];
    // e_ident (16 bytes)
    b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 2; // 64-bit
    b[5] = 1; // little-endian
    b[6] = 1; // ELF version
    b[7] = 1; // System V
    // ELF64 header (offsets are absolute, from byte 16)
    put16(&mut b, 2, 16); // e_type = ET_EXEC
    put16(&mut b, 62, 18); // e_machine = x86-64
    put32(&mut b, 1, 20); // e_version
    put64(&mut b, 0x400000, 24); // e_entry
    put64(&mut b, 64, 32); // e_phoff
    put64(&mut b, 0, 40); // e_shoff
    put32(&mut b, 0, 48); // e_flags
    put16(&mut b, 64, 52); // e_ehsize
    put16(&mut b, 56, 54); // e_phentsize
    put16(&mut b, 1, 56); // e_phnum
    put16(&mut b, 64, 58); // e_shentsize
    put16(&mut b, 0, 60); // e_shnum
    put16(&mut b, 0, 62); // e_shstrndx
    // Program header at offset 64 (56 bytes): PT_LOAD, vaddr 0x400000
    put32(&mut b, 1, 64); // p_type = PT_LOAD
    put32(&mut b, 5, 68); // p_flags = R+X
    put64(&mut b, 0, 72); // p_offset
    put64(&mut b, 0x400000, 80); // p_vaddr
    put64(&mut b, 0, 88); // p_paddr
    put64(&mut b, 0x400, 96); // p_filesz
    put64(&mut b, 0x400, 104); // p_memsz
    put64(&mut b, 0x1000, 112); // p_align
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn format_elf() {
    let d = db();
    let hex = elf64_hex();
    // container is a VARCHAR child -> JSON-quote-wrapped under v1.1.0.
    let container: String = d
        .query_one(&format!("SELECT CAST(disasm_format(from_hex('{hex}')) -> 'container' AS VARCHAR)"))
        .unwrap();
    assert_eq!(container, "\"elf\"");
    let arch: String = d
        .query_one(&format!("SELECT CAST(disasm_format(from_hex('{hex}')) -> 'arch' AS VARCHAR)"))
        .unwrap();
    assert_eq!(arch, "\"x86\"");
    // Numeric / endian children.
    let bits: i32 = d
        .query_one(&format!("SELECT CAST(disasm_format(from_hex('{hex}')) -> 'bits' AS INTEGER)"))
        .unwrap();
    assert_eq!(bits, 64);
    let entry: i64 = d
        .query_one(&format!("SELECT CAST(disasm_format(from_hex('{hex}')) -> 'entry' AS BIGINT)"))
        .unwrap();
    assert_eq!(entry, 0x400000i64);
}

#[test]
fn entrypoint_elf() {
    let d = db();
    let hex = elf64_hex();
    let vaddr: i64 = d
        .query_one(&format!("SELECT CAST(disasm_entrypoint(from_hex('{hex}')) -> 'vaddr' AS BIGINT)"))
        .unwrap();
    assert_eq!(vaddr, 0x400000i64);
}

#[test]
fn garbage_is_raw_total() {
    let d = db();
    // An unrecognized blob -> container='raw' (quoted under v1.1.0), NULL detail.
    let container: String = d
        .query_one("SELECT CAST(disasm_format(CAST('not a binary' AS BLOB)) -> 'container' AS VARCHAR)")
        .unwrap();
    assert_eq!(container, "\"raw\"");
    let vaddr: Option<i64> = d
        .query_one("SELECT CAST(disasm_entrypoint(CAST('not a binary' AS BLOB)) -> 'vaddr' AS BIGINT)")
        .unwrap();
    assert!(vaddr.is_none());
}

#[test]
fn null_input_is_null() {
    let d = db();
    let c: Option<String> = d
        .query_one("SELECT CAST(disasm_format(s) -> 'container' AS VARCHAR) FROM (SELECT NULL::BLOB AS s)")
        .unwrap();
    assert!(c.is_none());
}

// DuckDB loadable extension: binary container probe + entry-point resolution,
// in SQL.
//
// Thin quack-rs binding over `disasm_core` (a verbatim, **Capstone-free** subset
// of Query-farm's vgi-disasm disasm-core crate, MIT): it reads only the
// PE/ELF/Mach-O headers via `goblin` to answer "what container is this blob,
// and where does it start". It depends only on `goblin` + `std` — the
// Capstone disassembler (a native-C build) and the instruction/section/import/
// string *table* surface are deliberately NOT ported in v1. Only the Arrow IPC
// transport was replaced with direct C-API vector I/O.
//
// Function surface (v1 — 2 scalars, no disassembly):
//
//   disasm_format(blob)      -> STRUCT(container, arch, mode, bits, endian, entry)
//   disasm_entrypoint(blob)  -> STRUCT(arch, mode, vaddr, file_off, section)
//
// `blob` is a BLOB: a PE / ELF / Mach-O (incl. a fat Mach-O primary slice)
// binary, or raw bytes. Both functions are **total** and bounded (adversarial
// section sizes are clamped by `limits`), so arbitrary / hostile input never
// yields a SQL error — an unrecognized blob returns `container='raw'` with the
// detail fields NULL. `NULL` input yields a `NULL` struct.

use quack_rs::connection::{Connection, Registrar};
use quack_rs::error::ExtensionError;
use quack_rs::scalar::ScalarFunctionBuilder;
use quack_rs::types::{LogicalType, TypeId};
use quack_rs::vector::{VectorReader, VectorWriter};

use disasm_core::entrypoint::EntryPoint;
use disasm_core::probe::Probe;

/// Read a BLOB cell into bytes; None when the row is NULL/invalid.
unsafe fn payload_bytes(value: &VectorReader, row: usize) -> Option<Vec<u8>> {
    if !value.is_valid(row) {
        return None;
    }
    Some(value.read_blob(row).to_vec())
}

/// Write an `Option<String>` into a struct VARCHAR field (col), or NULL it.
unsafe fn sw_var(sw: &mut quack_rs::vector::StructWriter, row: usize, col: usize, v: Option<String>) {
    match v {
        Some(s) => sw.write_varchar(row, col, &s),
        None => sw.set_null(row, col),
    }
}

/// Write an `Option<u64>` into a struct UBigInt field (col), or NULL it.
unsafe fn sw_u64(sw: &mut quack_rs::vector::StructWriter, row: usize, col: usize, v: Option<u64>) {
    match v {
        Some(n) => sw.write_u64(row, col, n),
        None => sw.set_null(row, col),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// disasm_format(blob) -> STRUCT(container, arch, mode, bits, endian, entry)
// ─────────────────────────────────────────────────────────────────────────────

const FORMAT_FIELDS: &[(&str, TypeId)] = &[
    ("container", TypeId::Varchar),
    ("arch", TypeId::Varchar),
    ("mode", TypeId::Varchar),
    ("bits", TypeId::UInteger),
    ("endian", TypeId::Varchar),
    ("entry", TypeId::UBigInt),
];

quack_rs::scalar_callback!(format_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, FORMAT_FIELDS.len());
        for row in 0..row_count {
            match payload_bytes(&blob, row) {
                Some(bytes) => {
                    let p: Probe = disasm_core::probe::probe(&bytes);
                    sw.write_varchar(row, 0, &p.container);
                    sw_var(&mut sw, row, 1, p.arch);
                    sw_var(&mut sw, row, 2, p.mode);
                    match p.bits {
                        Some(b) => sw.write_u32(row, 3, b as u32),
                        None => sw.set_null(row, 3),
                    }
                    sw_var(&mut sw, row, 4, p.endian);
                    sw_u64(&mut sw, row, 5, p.entry);
                }
                None => {
                    sw.set_row_null(row);
                }
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// disasm_entrypoint(blob) -> STRUCT(arch, mode, vaddr, file_off, section)
// ─────────────────────────────────────────────────────────────────────────────

const ENTRYPOINT_FIELDS: &[(&str, TypeId)] = &[
    ("arch", TypeId::Varchar),
    ("mode", TypeId::Varchar),
    ("vaddr", TypeId::UBigInt),
    ("file_off", TypeId::UBigInt),
    ("section", TypeId::Varchar),
];

quack_rs::scalar_callback!(entrypoint_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, ENTRYPOINT_FIELDS.len());
        for row in 0..row_count {
            match payload_bytes(&blob, row) {
                Some(bytes) => {
                    let e: EntryPoint = disasm_core::entrypoint::entrypoint(&bytes);
                    sw_var(&mut sw, row, 0, e.arch);
                    sw_var(&mut sw, row, 1, e.mode);
                    sw_u64(&mut sw, row, 2, e.vaddr);
                    sw_u64(&mut sw, row, 3, e.file_off);
                    sw_var(&mut sw, row, 4, e.section);
                }
                None => {
                    sw.set_row_null(row);
                }
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Registration + entry point
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    con.register_scalar(
        ScalarFunctionBuilder::new("disasm_format")
            .param(TypeId::Blob)
            .returns_logical(LogicalType::struct_type(FORMAT_FIELDS))
            .function(format_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("disasm_entrypoint")
            .param(TypeId::Blob)
            .returns_logical(LogicalType::struct_type(ENTRYPOINT_FIELDS))
            .function(entrypoint_fn),
    )?;

    Ok(())
}

quack_rs::entry_point_v2!(disasm_init_c_api, |con| register_all(con));

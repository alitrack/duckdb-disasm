# duckdb-disasm

**Binary container probe + entry-point resolution, in SQL.** Feed the raw
bytes of a PE / ELF / Mach-O (including a fat Mach-O's primary slice) — or even
raw, unrecognized bytes — and ask *"what container is this, and where does it
start."* Right in DuckDB, no `file`, no `readelf`, no `objdump -h`, no Python.

```sql
LOAD 'disasm.duckdb_extension';

-- Triage a column of carved / network blobs
SELECT
  disasm_format(b) -> 'container' AS container,   -- 'pe' / 'elf' / 'macho' / 'fat-macho' / 'raw'
  disasm_format(b) -> 'arch'      AS arch,        -- 'x86' / 'arm64' / …
  disasm_format(b) -> 'bits'      AS bits,        -- 32 / 64
  disasm_format(b) -> 'endian'    AS endian,      -- 'little' / 'big'
  disasm_format(b) -> 'entry'     AS entry_va,
  disasm_entrypoint(b) -> 'section' AS entry_section
FROM sandbox.carved_blobs;
```

## Why

Malware samples, crash dumps, and network captures are *blobs*, and the first
question about any of them is "what *is* this, and where does it start?" —
i.e. the container type (PE/ELF/Mach-O), the target architecture, and the
entry point. Answering it in SQL today means shelling out to `file` /
`readelf` / `objdump` and parsing their text, then re-joining. This extension
makes the probe a SQL primitive: the blob is a `BLOB` column, the answer is a
`STRUCT` you can `WHERE` on, `GROUP BY`, or `MATCH_RECOGNIZE` over a
download sequence.

## Functions

| Function | Returns | Notes |
|---|---|---|
| `disasm_format(blob)` | `STRUCT(container, arch, mode, bits, endian, entry)` | Container + architecture probe, read straight from the binary headers. `container` is always set (`pe`/`elf`/`macho`/`fat-macho`/`raw`); the detail fields are `NULL` for an unrecognized blob. **Total** and bounded (adversarial section sizes are clamped), so hostile input never errors. |
| `disasm_entrypoint(blob)` | `STRUCT(arch, mode, vaddr, file_off, section)` | Resolves the entry point and the (arch, mode) it implies, including the file offset and the section that contains the entry VA. All fields `NULL` for a raw blob. **Total** and bounded. |

`blob` is a `BLOB` (raw binary). Both are **total**: an unrecognized blob
returns `container='raw'` with `NULL` detail — never a SQL error. `NULL`
input yields a `NULL` struct.

## Scope (v1)

- **The header-only probe + entry-point path** (verbatim port of a
  **Capstone-free** subset of Query-farm's `vgi-disasm` `disasm-core` crate,
  MIT — `goblin` + `std` only). This is the two *scalar* functions of the
  original worker.
- **Not ported:** the instruction-level disassembly (`disassemble`), section
  fan-out, imports, strings, and capabilities — those are the worker's *table*
  functions (one row per instruction / section / import / string) and depend
  on the **native-C Capstone** build. A Capstone-backed disassembly extension
  is a separate, heavier port.

## Build

```sh
make release        # -> target/release/disasm.duckdb_extension
make test           # bundled DuckDB runs tests/integration.rs (SQL-level)
```

The cdylib links the DuckDB C extension ABI (resolved at `LOAD` time) plus the
`goblin` binary-parsing crate (pure Rust, no native build, no I/O, no network,
no Arrow). `panic = "unwind"` keeps a bug in the extension from aborting the
host process.

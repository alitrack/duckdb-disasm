// disasm-core (trimmed) — the container *probe* + *entry-point* subset of
// Query-farm's vgi-disasm disasm-core crate (MIT), ported verbatim except for
// the module list.
//
// The 4 retained modules (`probe`, `entrypoint`, `sections`, `limits`) answer
// "what container is this blob, and where does it start" by reading only the
// PE/ELF/Mach-O headers via `goblin`. They are mutually self-contained (only
// `crate::probe` / `crate::sections` / `crate::limits` cross-refs) and depend
// only on `goblin` + `std`.
//
// Deliberately EXCLUDED: `engine` (the Capstone disassembler), `sweep`,
// `capabilities`, `groups`, `imports`, `strings` — those drag in the
// **native-C Capstone** build (a `cc`-compiled C lib) and are the *table*
// surface of the original worker (one row per instruction / section / import /
// string), not a pure scalar. A Capstone-backed disassembly extension is a
// separate, heavier port.

pub mod entrypoint;
pub mod limits;
pub mod probe;
pub mod sections;

pub use entrypoint::{EntryPoint};
pub use probe::{Probe};

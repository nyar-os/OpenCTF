# open-ctf-core

The binary inspection kernel behind [OpenCTF](../../../README.md). One engine for
PE, ELF and Mach-O: headers and sections, imports and exports, symbols, strings,
entropy, relocations, resources, TLS, load configuration, code signatures,
chained fixups, disassembly and byte-level diffing.

## Usage

Add it to your `Cargo.toml`:

```toml
[dependencies]
open-ctf-core = { path = "projects/crates/ctf-core" }
```

```rust
use open_ctf_core::OpenCtf;

let mut ctf = OpenCtf::new("path/to/binary")?;
let info = ctf.identity()?;
let sections = ctf.sections()?;
```

The kernel is read-only and pure Rust. Every answer is a typed, serializable
structure, so the same results power the Node-API surface, the CLI and the GUI.

## Notes

- Parsing leans on the shared `boost.rs` engine so format decoding stays in
  lockstep across the OpenX family.
- This crate is published as part of the OpenCTF workspace; see the repository
  README for the full capability matrix.

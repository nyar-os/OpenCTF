# open-ctf-domain

The product domain of [OpenCTF](../../../README.md): the challenge model,
candidates, evidence, reports and the workflows that orchestrate the format and
solver crates around the pinned `boost.rs` inspection engine.

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
open-ctf-domain = { path = "projects/crates/ctf-domain" }
```

```rust
use open_ctf_domain::{OpenCtf, OpenCtfOptions};

let session = OpenCtf::new(OpenCtfOptions::new("path/to/binary"))?;
let info = session.info()?;
let sections = session.sections()?;
```

Every answer is a typed, serializable structure, so the same results power the
Node-API surface, the CLI and the GUI.

## Notes

- Format facts come from `open-ctf-formats` and algorithms from
  `open-ctf-solvers`; this crate only orchestrates them.
- Session work (open, header, sections, strings, search, hex dumps, reads,
  patches, address mapping) and byte observation behind `diff`, `find`, `text`,
  `dump`, `entropy` and `carve` come from `boost.rs/data-binary-inspect`.
- Format-owner copies that still exist live in `open-ctf-formats`, are marked
  `TODO(boost): owner migration` and are listed in
  [`documentation/duplication.md`](../../../documentation/duplication.md).

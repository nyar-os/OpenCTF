# open-ctf-napi

The thin Node-API surface of [OpenCTF](../../../README.md). It exposes the
`open-ctf-core` kernel to Node.js as a `cdylib`, and is the only native layer
between JavaScript and the inspection engine.

## Usage

This crate is not consumed directly. Install the npm package instead:

```sh
npm install @wae/open-ctf
```

The package resolves the prebuilt platform addon (`@wae/open-ctf-<os>-<arch>`)
at load time, so no toolchain is required on the host.

## Build

```sh
cargo build -p open-ctf-napi --release
```

The resulting `open_ctf_napi.dll` / `.node` is staged into the per-platform
packages by `wae native build`. Keep this layer thin: new capabilities belong
in `open-ctf-core` first, then get a one-line binding here.

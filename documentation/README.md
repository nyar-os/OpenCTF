# OpenCTF maintainer guide

Repository layout, build and test commands, dependency pins, CI, and the actual
state of the npm release path. Reader-facing documentation lives in
[../readme.md](../readme.md) and
[../projects/packages/open-ctf/README.md](../projects/packages/open-ctf/README.md);
agent-facing documentation lives in [agents.md](agents.md).

## Project layout

| Path                                           | What it is                                                                                                                                                                                                                                                                                                                                                                      |
|------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `../projects/crates/ctf-domain`                | Rust crate `open-ctf-domain`: `Challenge`, `Candidate`/`CandidateSet`, `Evidence`, `ChallengeReport`, the stable `CtfError`, the `OpenCtf`/`BinaryView` session facade and `workflow/{identify,triage,solve,verify}`. Byte-observation projections (`text`, `find`, `diff`, `entropy`, `dump`, `carve`) call the pinned `data-binary-inspect`. |
| `../projects/crates/ctf-solvers`               | Rust crate `open-ctf-solvers`: Caesar, single-byte XOR, cyclic patterns, decoders, digests, JWT and URL decomposition. Algorithms only; no format parsing. |
| `../projects/crates/ctf-formats`               | Rust crate `open-ctf-formats`: pcap, png, packer and the `archive` (ASAR) reader, plus the PE/ELF/Mach-O/container modules that still copy a Boost owner. Copies carry `TODO(boost): owner migration` and are listed in [duplication.md](duplication.md). |
| `../projects/crates/ctf-napi`                  | Rust crate `open-ctf-napi`: `cdylib` Node-API exports and the Studio WebView host. It maps JSON in and JSON out; no analysis lives here. |
| `projects/packages/open-ctf`                   | TypeScript package `@wae/open-ctf`: `OpenCTF` session (`src/api.ts`), CLI (`src/cli.ts`, bin `open-ctf`), GUI helpers, stable errors, types and `locales/en-US/cli.json`. |
| `projects/packages/open-ctf/tests`             | TypeScript smoke test compiled with `tsconfig.test.json` into `dist-test`. Test files do not live under `src`. |
| `../projects/crates/*/tests`                   | Rust integration tests, grouped by owner: `ctf-formats/tests/projections.rs`, `ctf-solvers/tests/{algorithms,fixtures}.rs`, `ctf-domain/tests/{challenge,candidate,workflow}.rs`. |
| `projects/packages/open-ctf-ui`                | `@wae/open-ctf-ui`: VMZ static shell for the Studio window. `vmz build . --profile static` emits `dist/static`, staged into `open-ctf/dist/gui`. |
| `projects/packages/open-ctf-skills`            | `@wae/open-ctf-skills`: skill document under `skills/`. No runtime library and no analysis. |
| `projects/packages/open-ctf-<platform>-<arch>` | Five prebuilt addon packages: `win32-x64`, `darwin-x64`, `darwin-arm64`, `linux-x64`, `linux-arm64`. Each is a thin manifest around a staged `.node` file. |
| `projects/sites/homepage`                      | `@wae/open-ctf-homepage`: VMZ product site. |
| `wae.config.ts`                                | Build order, native targets, platform package mapping, staging, skills registration, CI job names and window behaviour. |
| `Cargo.toml`                                   | Cargo workspace; members are `projects/crates/*`, default members `ctf-domain` and `ctf-napi`. |
| `pnpm-workspace.yaml`                          | pnpm workspace covering `projects/packages/*` and `projects/sites/*`. |

The CLI, SDK and Studio all read the same domain crate. A behaviour change in
`ctf-domain` reaches every surface; `capabilities()` is the single disclosure
point.

## Build and test

Prerequisites: Node.js 18 or newer, pnpm 10.28.0 (from the root
`package.json`), Rust 1.90 with edition 2024 (from `rust-toolchain.toml` /
`Cargo.toml`).

```bash
pnpm install                  # workspace dependencies
pnpm build:napi               # wae native build (crate open-ctf-napi)
pnpm build                    # wae build: native -> ts -> ui -> skills -> staging
pnpm typecheck                # pnpm -r --filter "./projects/packages/*" run typecheck
pnpm test                     # package tests
pnpm test:rust                # cargo test --release
pnpm check:rust               # fmt check + clippy -D warnings + workspace tests
```

Useful narrower commands:

```bash
cargo test -p open-ctf-domain
cargo test -p open-ctf-domain --release
cargo test -p open-ctf-napi
pnpm build:ts                 # tsc for @wae/open-ctf
pnpm build:ui                 # static Studio shell
pnpm stage:native             # wae native stage into platform package directories
pnpm gui                      # build and launch the Studio window
```

`pnpm test` runs `tsc -p tsconfig.test.json` and then
`node --test dist-test/tests/smoke.test.js`. The smoke test imports the
TypeScript sources through `../src/*.js`; native-dependent assertions skip
themselves when the addon is absent, so a green run without `pnpm build:napi`
proves less than it appears to.

## Internalization rule

The engine and the CLI never spawn an external process. Every decode,
decompression and bytecode interpretation — PE / ELF / Mach-O, NSIS, asar,
CPython `marshal`, 7z with LZMA — is implemented in-tree or in a pinned
`boost.rs` crate. Analysis workflows must not depend on `bsdtar`, `7z`,
disassembler SDKs or third-party deobfuscator tools; a capability that today
exists only as a one-off analysis script (for example a JavaScript
deobfuscation pass) is internalized into the engine before it becomes a
product surface.

## Dependency pins

Cross-repository dependencies pin a full 40-character revision, not a branch or
tag:

- The workspace `Cargo.toml` pins `data-binary-inspect`, `data-binary-pe` and
  `data-compression` to `0e2b81c435713bad883a27e577baa01ff40322f1` from
  `oovm/boost.rs`.
- The workspace `Cargo.toml` pins `wae` to
  `f92f818fde7174154d77a87b55a5e44b367034c9` from `doki-land/wae-framework`.

`open-ctf-formats` deliberately parses the PE debug directory and CodeView
records itself because the pinned `data-binary-inspect` release does not expose
them. The module is marked `TODO(boost): owner migration` and listed in
[duplication.md](duplication.md). Do not "fix" that by bumping the pin without
re-reading the upstream API and running the projection tests.

## Release and publishing

The publishable set is the five platform addon packages plus
`@wae/open-ctf-skills`. `@wae/open-ctf`, `@wae/open-ctf-ui` and the homepage are
`private: true`, and `wae.config.ts` leaves `release` unset.

The intended npm release contract is:

1. Build and stage the native addon so each platform package contains its
   `.node` file.
2. Publish from CI with npm Trusted Publisher / OIDC, triggered by a version
   tag: `permissions: id-token: write` and `environment: NPM_PUBLISH`. No
   long-lived npm token is stored in workflow YAML.
3. Keep local publishing to inspection only: `nifty publish --dry-run`, or
   `nifty publish --placeholder` to claim never-published `0.0.0` names.
4. Keep `.secrets/nifty.json` local. The whole `.secrets/` directory is
   git-ignored.

### Verified state (2026-11-26)

The name-claim and trust bootstrap is done, the real release path is **not
wired**:

- `nifty publish --placeholder` claimed all six publishable names at `0.0.0`
  (`darwin-arm64`, `darwin-x64`, `linux-arm64`, `linux-x64`, `win32-x64`,
  `skills`).
- `nifty trust` configured the npm Trusted Publisher record for the same six
  packages against `nyar-os/OpenCTF` / `publish-npm.yml` / `NPM_PUBLISH`, and
  `nifty trust --dry-run --refresh` reports every record as matching. The
  `NPM_PUBLISH` environment exists on the repository.
- No version tag has been pushed, so no real version is published.
  `wae.config.ts` therefore keeps `release` unset and this repository has no
  working automated npm release. Do not claim otherwise in a README or a release
  note.
- `nifty publish` aborts when a native platform package has no staged `.node`,
  so staging is a hard prerequisite for any future publish job.

## CI workflows

| Workflow               | Trigger                                   | What it runs                                                                                                                                                                                                              |
|------------------------|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `check-rust.yml`       | Push and pull request to `master` / `dev` | Matrix of Ubuntu, macOS and Windows; installs nightly with `rustfmt` and `clippy`; `cargo build --workspace --release`; `cargo test --workspace --release`. It does not run fmt or clippy checks; `pnpm check:rust` does. |
| `check-typescript.yml` | Push and pull request to `master` / `dev` | Ubuntu; pnpm and Node 22; `pnpm install --no-frozen-lockfile`; `pnpm typecheck`; `pnpm test`.                                                                                                                             |

## Documentation map

| File                                                                               | Audience    | Owns                                                        |
|------------------------------------------------------------------------------------|-------------|-------------------------------------------------------------|
| [../readme.md](../readme.md)                                                       | readers     | Product landing, getting started, highlights and boundaries |
| [../projects/packages/open-ctf/README.md](../projects/packages/open-ctf/README.md) | npm readers | Exports, usage, constraints                                 |
| [capabilities.md](capabilities.md)                                                 | everyone    | Support matrix, limits and unsupported boundaries           |
| [cli.md](cli.md)                                                                   | users       | Every command, flag, default and exit code                  |
| [agents.md](agents.md)                                                             | agents      | Capability discovery, stable codes and guardrails           |
| [architecture.md](architecture.md)                                                 | maintainers | Modules, call path, determinism and error contract          |
| This file                                                                          | maintainers | Layout, build, CI and release state                         |

Change the owning file, not a copy. Never put build commands, workspace trees
or CI notes in a reader-facing README.

The project is Apache-2.0; see [../License.md](../License.md).

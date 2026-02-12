# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-spiderfoot` — A pure-Rust reimplementation of SpiderFoot, providing automated OSINT reconnaissance with an event-driven module bus, a correlation engine, and a native GUI. It is part of the **Lancer** bug-bounty toolkit and ships as a single binary that can run as a GUI (default), a CLI scanner (`--cli`), or a web UI with REST API (`-l IP:PORT`).

## Architecture

This is a Cargo workspace with five crates:

- `lancer-spiderfoot/src/main.rs` — binary entry point; clap CLI parsing and mode dispatch (GUI / CLI / web)
- `lancer-spiderfoot/src/gui.rs` — egui desktop GUI surface
- `lancer-spiderfoot/src/output.rs` — output formatters (tab, csv, json, gexf, graphml, html, xlsx)
- `sf-core/src/lib.rs` — library root for the core engine; re-exports all engine primitives
- `sf-core/src/event.rs` — event taxonomy and `EventType` definitions
- `sf-core/src/module.rs` — `Module` trait that every source/detector implements
- `sf-core/src/scan.rs` — async scan state machine driving the event bus
- `sf-core/src/persist.rs` — SQLite persistence via sqlx (runtime queries, no compile-time DB)
- `sf-core/src/ratelimit.rs` — per-source rate limiting; `sf-core/src/apikeys.rs` — API-key rotation pools
- `sf-modules/src/lib.rs` — 240+ source/detector/tool modules, one file each, registered via the `inventory` crate
- `sf-graph/src/graph.rs` — petgraph event graph; `sf-graph/src/engine.rs` — YAML correlation engine; `sf-graph/src/export.rs` — GEXF/GraphML/JSON export
- `sf-web/src/api.rs` — axum REST API; `sf-web/src/pages.rs` — web UI pages; `sf-web/src/state.rs` — shared SSE live-event state

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- GUI is gated behind the default `gui` feature; `--no-default-features` builds a headless CLI binary.
- Library code lives in each crate's `src/lib.rs`; binary entry point in `lancer-spiderfoot/src/main.rs`.
- Modules in `sf-modules` are registered at compile time using the `inventory` crate — add a new file and register it rather than editing a central list.
- API keys are read from `~/.config/spiderfoot/sf.cfg` (TOML) or from `SPIDERFOOT_<MODULE>_API_KEY` environment variables; key rotation pools are supported via arrays.
- HTTP is done through `reqwest` with `default-tls` (schannel on Windows) to avoid NASM toolchain requirements for `ring`/`aws-lc`.

## Build / test / run

```
build.bat                   # Windows → build\lancer-spiderfoot.exe
build-windows.bat           # Windows packaged dist → dist\lancer-spiderfoot-windows-x86_64\
./build-linux.sh            # Linux/macOS
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.

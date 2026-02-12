# lancer-spiderfoot

A Rust reimplementation of [SpiderFoot](https://github.com/smicallef/spiderfoot) —
automated OSINT reconnaissance with an event-driven module bus, a correlation
engine, and a native GUI. Part of the **Lancer** bug-bounty toolkit.

> 🦀 Pure-Rust. A single binary that is a **GUI** by default, a **CLI** scanner
> with `--cli`, and a **web UI + REST API** with `-l IP:PORT`.

## Workspace

| Crate | Role |
|-------|------|
| `lancer-spiderfoot` | Binary: clap CLI, egui GUI, mode dispatch, output formats |
| `sf-core` | Engine: event taxonomy, `Module` trait, async event bus, scan state machine, SQLite persistence, API-key rotation, per-source rate limiting |
| `sf-modules` | 240+ source/detector/tool modules (one file each, `inventory`-registered) |
| `sf-graph` | petgraph event graph, YAML correlation engine, GEXF/GraphML/JSON export |
| `sf-web` | axum web UI + REST API with an SSE live event feed |

## Usage

```bash
# Native GUI (default)
lancer-spiderfoot

# CLI scan
lancer-spiderfoot -s acme.com -u passive -o json

# Web UI + REST API
lancer-spiderfoot -l 127.0.0.1:5001

# List modules / event types
lancer-spiderfoot -M
lancer-spiderfoot -T

# Parity self-test
lancer-spiderfoot --self-test
```

### CLI flags (SpiderFoot `sf.py` parity)

`-s` target · `-m` modules · `-t` types · `-u` use-case · `-o` output
(`tab|csv|json|gexf|graphml|html|xlsx`) · `-H` no headers · `-n` strip newlines ·
`-r` source data · `-S` max length · `-D` delimiter · `-F` filter types · `-M`
list modules · `-T` list types · `-l` listen · `-C` correlate · `-d` debug ·
`-q` quiet · `-x` strict · `-f` filter · `--max-threads` · `--max-events`.

## Configuration

`~/.config/spiderfoot/sf.cfg` (TOML):

```toml
[global]
_dnsserver = "8.8.8.8"
_fetchtimeout = 30
_socks_proxy = "socks5://127.0.0.1:9050"

[modules.sfp_shodan]
api_key = "..."

[modules.sfp_github]
api_keys = ["tok1", "tok2"]   # rotation pool
```

API keys also load from `SPIDERFOOT_<MODULE>_API_KEY` environment variables.

## Build

### Windows
```
build.bat
```
Output: `build\lancer-spiderfoot.exe`

For a packaged dist build: `build-windows.bat` → `dist\lancer-spiderfoot-windows-x86_64\`.

### Linux / macOS
```bash
./build-linux.sh
```
Output: `build/lancer-spiderfoot`

### Requirements
- [Rust / Cargo](https://rustup.rs)
- (Windows) Visual C++ Build Tools 2019/2022

## Regenerating the catalog

The module catalog and correlation rules are generated from manifests:

```bash
python gen_modules.py        # sf-modules/src/modules/*.rs + mod.rs
python gen_correlations.py   # correlations/*.yaml
```

## License

MIT

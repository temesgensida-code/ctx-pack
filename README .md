# ctx-pack

A dual-layer (Bash + Python) CLI that scans a codebase, filters out noise,
audits for secrets, token-counts everything, and packs it into a single
LLM-optimized Markdown file — so you stop hand-picking files or blowing past
context limits when working with Claude/ChatGPT on a real repo.

## Architecture

```
ctx-pack/
├── bin/
│   └── ctx-pack          # Bash entry point: args, .gitignore ingestion, file discovery
├── src/
│   ├── pack_engine.py     # Python async engine: read, secret-scan, token-count, rank, render
│   └── requirements.txt
├── tests/                 # (next step: pytest suite)
├── docs/
└── README.md
```

**Separation of concerns:**
- **Bash** owns everything OS-level and cheap: argument parsing, `.gitignore`
  parsing, `find`-based traversal and filtering. It never opens a file's
  contents — it only decides which paths are candidates, then streams them
  NUL-delimited over stdin to Python.
- **Python** owns everything that needs real logic: concurrent I/O
  (`asyncio` + `aiofiles`), binary/size/encoding safety checks, the secret
  guard, token budgeting/ranking, and Markdown rendering.

## Install

```bash
git clone <repo> ctx-pack
cd ctx-pack
pip install -r src/requirements.txt
chmod +x bin/ctx-pack
ln -s "$(pwd)/bin/ctx-pack" /usr/local/bin/ctx-pack   # optional, put it on PATH
```

## Usage

```bash
ctx-pack -d ./my-project -o context.md -b 30000
ctx-pack --exclude "*.lock" --exclude "dist/*" -b 50000
ctx-pack -d . --no-gitignore --include-hidden -v
```

| Flag | Description | Default |
|---|---|---|
| `-d, --dir` | Target directory to scan | `.` |
| `-o, --output` | Output markdown file | `ctx-pack.md` |
| `-b, --budget` | Token budget (0 = unlimited) | `0` |
| `--exclude` | Extra glob pattern to exclude (repeatable) | — |
| `--no-gitignore` | Don't honor `.gitignore` files | off |
| `--include-hidden` | Include dotfiles/dotdirs | off |
| `-v, --verbose` | Verbose logging | off |

## Safety features

- **Secret guard**: regex-based scan for AWS keys, generic API keys/tokens,
  private key blocks, Slack tokens, JWTs, and password assignments. Matches
  are masked (`[REDACTED:...]`) and logged to stderr — never silently
  dropped, never silently leaked.
- **`.env` awareness**: files matching `.env*` are flagged explicitly even
  though their contents still go through the same masking pass.
- **Binary/size/encoding guards**: binary files are detected via a
  null-byte + non-text-ratio heuristic and skipped; files over 2 MB are
  skipped; non-UTF-8 files fall back to latin-1 with a warning, or are
  skipped if unreadable. All skips are reported in the final Markdown, never
  silently dropped.

## Token budgeting

If `tiktoken` can reach the network for its `cl100k_base` ranking file, exact
GPT-style token counts are used. Otherwise the engine falls back to a
`len(text) // 4` heuristic automatically — no crash, just a warning.

When a budget is set, files are greedily packed in priority order
(source code → config → docs → data/logs), smallest-first within a tier, and
anything that doesn't fit is listed in an "Omitted Due to Token Budget"
table rather than silently vanishing.

## Roadmap (round two)

- [ ] pytest suite covering secret patterns, binary detection, budget edge cases
- [ ] Configurable priority rules via `.ctxpackrc`
- [ ] `rich`-based progress/summary UI
- [ ] Import-graph-aware ranking (pull in a file's direct dependencies first)
- [ ] `--stdin-only` mode for piping arbitrary file lists (e.g. from `git diff --name-only`)

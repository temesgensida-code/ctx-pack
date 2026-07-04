#!/usr/bin/env python3
"""
pack_engine.py — the async processing core of ctx-pack.

Reads a NUL-delimited list of candidate file paths on stdin (produced by the
`ctx-pack` bash entry point), then:

  1. Reads every file concurrently with asyncio + aiofiles.
  2. Classifies each file (binary / too large / unreadable / ok).
  3. Runs a secret-guard regex pass and masks anything that looks like a
     credential, logging a warning to stderr for each hit.
  4. Computes token counts (tiktoken if available, else a fast heuristic).
  5. If a token budget is set, ranks files by priority and greedily fits as
     many as possible into the budget, reporting what got dropped.
  6. Renders a single Markdown document: an ASCII directory tree followed by
     one fenced code block per included file, headed by its relative path.

Design notes for round two (left as clear extension points):
  - `PRIORITY_RULES` is a simple ordered list; could become a pluggable
    strategy (e.g. import-graph-aware ranking).
  - `SECRET_PATTERNS` covers common cases; a real product would pull from an
    updated ruleset (e.g. gitleaks-style TOML) rather than hardcoding here.
  - Progress bar rendering is minimal; could be swapped for a proper
    `rich`-based UI without touching the core pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import aiofiles
except ImportError:
    print(
        "[pack_engine] error: 'aiofiles' is required. Install with: "
        "pip install aiofiles",
        file=sys.stderr,
    )
    sys.exit(1)

_ENCODER = None
try:
    import tiktoken

    try:
        # This downloads/caches a BPE ranking file on first use — it can
        # fail with no network access (offline dev boxes, CI sandboxes,
        # air-gapped environments), so we degrade gracefully rather than
        # crash the whole pipeline.
        _ENCODER = tiktoken.get_encoding("cl100k_base")
    except Exception as e:  # noqa: BLE001 - deliberately broad, see above
        print(
            f"[pack_engine] tiktoken available but offline/unreachable "
            f"({e.__class__.__name__}); falling back to heuristic token "
            f"counting.",
            file=sys.stderr,
        )
        _ENCODER = None

except ImportError:
    print(
        "[pack_engine] tiktoken not installed; falling back to heuristic "
        "token counting.",
        file=sys.stderr,
    )


def count_tokens(text: str) -> int:
    if _ENCODER is not None:
        return len(_ENCODER.encode(text, disallowed_special=()))
    # Heuristic fallback: ~4 chars/token for English-ish source code.
    # Good enough for budgeting decisions when tiktoken is unreachable.
    return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# ANSI colors (kept dependency-free so the engine runs anywhere python3 runs)
# ---------------------------------------------------------------------------
class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"


def log(msg: str, color: str = Ansi.CYAN) -> None:
    print(f"{color}[pack_engine]{Ansi.RESET} {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"{Ansi.YELLOW}[pack_engine][warn]{Ansi.RESET} {msg}", file=sys.stderr)


def alert(msg: str) -> None:
    print(f"{Ansi.RED}[pack_engine][secret-guard]{Ansi.RESET} {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB — beyond this, skip with a warning
CONCURRENCY_LIMIT = 64            # cap simultaneous open files

# Extension -> priority tier. Lower number = packed first when budget is tight.
PRIORITY_RULES: list[tuple[re.Pattern, int]] = [
    (re.compile(r"\.(py|js|ts|tsx|jsx|go|rs|java|kt|c|cpp|h|hpp|rb|php)$"), 0),  # source
    (re.compile(r"\.(md|rst|txt)$"), 2),                                        # docs
    (re.compile(r"\.(json|ya?ml|toml|ini|cfg|env\.example)$"), 1),              # config
    (re.compile(r"\.(lock|log|csv|tsv)$"), 3),                                  # data/noise
]
DEFAULT_PRIORITY = 1

# Regex secret guard. Deliberately conservative (favors false positives over
# leaking a real key) since we always mask, never silently drop.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{16,}['\"]?")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----")),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Generic Bearer/JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Password Assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?")),
]


@dataclass
class FileRecord:
    abs_path: Path
    rel_path: str
    ok: bool = False
    skipped_reason: Optional[str] = None
    content: str = ""
    tokens: int = 0
    priority: int = DEFAULT_PRIORITY
    secrets_found: int = 0
    included: bool = False


# ---------------------------------------------------------------------------
# Binary detection
# ---------------------------------------------------------------------------
def looks_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    # Heuristic: too many non-text bytes -> binary
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    nontext = sum(byte not in text_chars for byte in sample)
    return nontext / max(1, len(sample)) > 0.30


def classify_priority(path: str) -> int:
    for pattern, tier in PRIORITY_RULES:
        if pattern.search(path):
            return tier
    return DEFAULT_PRIORITY


# ---------------------------------------------------------------------------
# Secret guard
# ---------------------------------------------------------------------------
def mask_secrets(text: str, rel_path: str) -> tuple[str, int]:
    hits = 0
    for label, pattern in SECRET_PATTERNS:
        def _mask(m: re.Match, label=label) -> str:
            nonlocal hits
            hits += 1
            return f"[REDACTED:{label}]"

        text, n = pattern.subn(_mask, text)
    return text, hits


# ---------------------------------------------------------------------------
# Async file processing
# ---------------------------------------------------------------------------
async def process_file(path: Path, root: Path, sem: asyncio.Semaphore) -> FileRecord:
    rel = str(path.relative_to(root))
    rec = FileRecord(abs_path=path, rel_path=rel, priority=classify_priority(rel))

    async with sem:
        try:
            size = path.stat().st_size
        except OSError as e:
            rec.skipped_reason = f"stat failed: {e}"
            return rec

        if size == 0:
            rec.skipped_reason = "empty file"
            return rec

        if size > MAX_FILE_BYTES:
            rec.skipped_reason = f"too large ({size / 1024:.0f} KB > {MAX_FILE_BYTES // 1024} KB limit)"
            return rec

        try:
            async with aiofiles.open(path, "rb") as f:
                raw = await f.read()
        except OSError as e:
            rec.skipped_reason = f"read error: {e}"
            return rec

        if looks_binary(raw[:4096]):
            rec.skipped_reason = "binary file"
            return rec

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
                warn(f"{rel}: decoded as latin-1 (non-UTF-8 content)")
            except Exception as e:
                rec.skipped_reason = f"encoding error: {e}"
                return rec

        # .env files are almost always secrets by definition — flag loudly
        # but still allow packing (masked), since users sometimes need
        # structure/key-names without values.
        if path.name.startswith(".env"):
            warn(f"{rel}: looks like an environment file — values will be masked")

        masked_text, hits = mask_secrets(text, rel)
        if hits:
            alert(f"{rel}: masked {hits} potential secret(s)")

        rec.content = masked_text
        rec.tokens = count_tokens(masked_text)
        rec.ok = True
        return rec


async def process_all(paths: list[Path], root: Path) -> list[FileRecord]:
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = [process_file(p, root, sem) for p in paths]
    records: list[FileRecord] = []
    total = len(tasks)
    done = 0
    for coro in asyncio.as_completed(tasks):
        rec = await coro
        records.append(rec)
        done += 1
        _render_progress(done, total)
    print(file=sys.stderr)  # newline after progress bar
    return records


def _render_progress(done: int, total: int, width: int = 30) -> None:
    frac = done / total if total else 1.0
    filled = int(width * frac)
    bar = "█" * filled + "░" * (width - filled)
    print(
        f"\r{Ansi.CYAN}[pack_engine]{Ansi.RESET} reading files "
        f"[{Ansi.GREEN}{bar}{Ansi.RESET}] {done}/{total}",
        end="",
        file=sys.stderr,
        flush=True,
    )


# ---------------------------------------------------------------------------
# Budget fitting
# ---------------------------------------------------------------------------
def fit_to_budget(records: list[FileRecord], budget: int) -> tuple[list[FileRecord], list[FileRecord]]:
    """Greedily include files by (priority asc, tokens asc) until the budget
    is exhausted. Returns (included, dropped_for_budget)."""
    ok_records = [r for r in records if r.ok]

    if budget <= 0:
        for r in ok_records:
            r.included = True
        return ok_records, []

    ranked = sorted(ok_records, key=lambda r: (r.priority, r.tokens))
    included: list[FileRecord] = []
    dropped: list[FileRecord] = []
    running_total = 0

    for r in ranked:
        if running_total + r.tokens <= budget:
            r.included = True
            included.append(r)
            running_total += r.tokens
        else:
            dropped.append(r)

    # Preserve original path order for the final render, budget logic just
    # decided *membership*.
    included_set = {id(r) for r in included}
    ordered_included = [r for r in ok_records if id(r) in included_set]
    return ordered_included, dropped


def render_budget_bar(used: int, budget: int, width: int = 30) -> str:
    frac = min(1.0, used / budget) if budget else 0.0
    filled = int(width * frac)
    color = Ansi.GREEN if frac < 0.8 else (Ansi.YELLOW if frac < 1.0 else Ansi.RED)
    bar = "█" * filled + "░" * (width - filled)
    pct = frac * 100
    return f"[{color}{bar}{Ansi.RESET}] {used:,}/{budget:,} tokens ({pct:.1f}%)"


# ---------------------------------------------------------------------------
# ASCII tree + markdown rendering
# ---------------------------------------------------------------------------
def build_ascii_tree(rel_paths: list[str]) -> str:
    tree: dict = {}
    for rel in rel_paths:
        parts = Path(rel).parts
        node = tree
        for part in parts:
            node = node.setdefault(part, {})

    lines: list[str] = ["."]

    def _walk(node: dict, prefix: str = "") -> None:
        entries = sorted(node.items(), key=lambda kv: (not kv[1], kv[0].lower()))
        # directories (non-empty dict) first? Keep simple: alphabetical,
        # but stable and readable either way.
        entries = sorted(node.items(), key=lambda kv: kv[0].lower())
        for i, (name, child) in enumerate(entries):
            is_last = i == len(entries) - 1
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{name}")
            if child:
                extension = "    " if is_last else "│   "
                _walk(child, prefix + extension)

    _walk(tree)
    return "\n".join(lines)


LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "tsx",
    ".jsx": "jsx", ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
    ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp", ".rb": "ruby",
    ".php": "php", ".sh": "bash", ".bash": "bash", ".md": "markdown",
    ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml",
    ".html": "html", ".css": "css", ".sql": "sql",
}


def lang_for(rel_path: str) -> str:
    return LANG_BY_EXT.get(Path(rel_path).suffix.lower(), "")


def render_markdown(
    root_name: str,
    included: list[FileRecord],
    dropped_for_budget: list[FileRecord],
    skipped: list[FileRecord],
    budget: int,
    elapsed: float,
) -> str:
    total_tokens = sum(r.tokens for r in included)
    out: list[str] = []

    out.append(f"# Context Pack: `{root_name}`")
    out.append("")
    out.append(
        f"_Generated by ctx-pack · {len(included)} file(s) · "
        f"{total_tokens:,} tokens · {elapsed:.2f}s_"
    )
    out.append("")

    if budget > 0:
        out.append(f"**Token budget:** {total_tokens:,} / {budget:,} used")
        out.append("")

    out.append("## Directory Structure")
    out.append("")
    out.append("```")
    out.append(build_ascii_tree([r.rel_path for r in included]))
    out.append("```")
    out.append("")

    if dropped_for_budget:
        out.append("## ⚠️ Omitted Due to Token Budget")
        out.append("")
        out.append("| File | Tokens | Priority Tier |")
        out.append("|---|---|---|")
        for r in sorted(dropped_for_budget, key=lambda r: -r.tokens):
            out.append(f"| `{r.rel_path}` | {r.tokens:,} | {r.priority} |")
        out.append("")

    if skipped:
        out.append("## ℹ️ Skipped Files")
        out.append("")
        out.append("| File | Reason |")
        out.append("|---|---|")
        for r in skipped:
            out.append(f"| `{r.rel_path}` | {r.skipped_reason} |")
        out.append("")

    out.append("## Files")
    out.append("")
    for r in included:
        lang = lang_for(r.rel_path)
        out.append(f"### `{r.rel_path}`")
        out.append("")
        out.append(f"```{lang}")
        out.append(r.content.rstrip("\n"))
        out.append("```")
        out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def read_stdin_paths() -> list[Path]:
    raw = sys.stdin.buffer.read()
    if not raw:
        return []
    parts = raw.split(b"\x00")
    return [Path(p.decode("utf-8", errors="replace")) for p in parts if p]


async def main_async(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    paths = read_stdin_paths()

    if not paths:
        warn("No file paths received on stdin.")
        return 0

    log(f"Processing {len(paths)} file(s) with up to {CONCURRENCY_LIMIT} concurrent readers...")
    start = time.monotonic()
    records = await process_all(paths, root)
    elapsed = time.monotonic() - start

    skipped = [r for r in records if not r.ok]
    included, dropped_for_budget = fit_to_budget(records, args.budget)

    total_tokens = sum(r.tokens for r in included)
    log(f"Read {len(records)} file(s) in {elapsed:.2f}s "
        f"({len(included)} included, {len(skipped)} skipped, "
        f"{len(dropped_for_budget)} dropped for budget)")

    if args.budget > 0:
        log(render_budget_bar(total_tokens, args.budget), color=Ansi.MAGENTA)
        if dropped_for_budget:
            warn(f"{len(dropped_for_budget)} file(s) did not fit in the "
                 f"{args.budget:,}-token budget and were omitted (see report).")
    else:
        log(f"Total tokens (no budget set): {total_tokens:,}")

    markdown = render_markdown(
        root_name=root.name,
        included=included,
        dropped_for_budget=dropped_for_budget,
        skipped=skipped,
        budget=args.budget,
        elapsed=elapsed,
    )

    out_path = Path(args.output)
    async with aiofiles.open(out_path, "w", encoding="utf-8") as f:
        await f.write(markdown)

    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="ctx-pack async processing engine")
    p.add_argument("--root", required=True, help="Root directory paths are relative to")
    p.add_argument("--output", required=True, help="Markdown output file path")
    p.add_argument("--budget", type=int, default=0, help="Token budget (0 = unlimited)")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args(argv)


def main() -> None:
    args = parse_args(sys.argv[1:])
    try:
        status = asyncio.run(main_async(args))
    except KeyboardInterrupt:
        warn("Interrupted.")
        status = 130
    sys.exit(status)


if __name__ == "__main__":
    main()

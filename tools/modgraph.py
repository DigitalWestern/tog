#!/usr/bin/env python3
"""Module-graph metrics for the structural refactor (REFACTOR.md §1).

Re-run with `python3 tools/modgraph.py` from the repo root. Prints the
baseline table: file count, line counts, oversize files and functions,
store fan-in, and two-way module dependencies. Pure source scan; no
dependencies beyond the standard library.
"""
import os
import re
import sys
from collections import defaultdict

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
ROOT = os.path.normpath(ROOT)


def module_path(rel):
    parts = rel[:-3].split(os.sep)  # strip .rs
    if parts[-1] == "mod":
        parts = parts[:-1]
    if parts == ["lib"] or parts == ["main"]:
        return parts[0]
    return "::".join(parts)


def split_tests(text):
    """Return (non_test_text, test_line_count) by cutting at `#[cfg(test)]`."""
    m = re.search(r"^#\[cfg\(test\)\]\s*\n\s*mod tests\b", text, re.M)
    if not m:
        return text, 0
    return text[: m.start()], text[m.start():].count("\n")


def strip_noise(text):
    """Blank out comments and string/char literals (keeping newlines) so
    braces inside them do not confuse the function-length scan."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * text[i:j].count("\n"))
            i = j
            continue
        if c == "r" and i + 1 < n and text[i + 1] in "#\"":
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == "\"":
                close = "\"" + "#" * hashes
                k = text.find(close, j + 1)
                k = n if k < 0 else k + len(close)
                out.append("\n" * text[i:k].count("\n"))
                i = k
                continue
        if c == "\"":
            j = i + 1
            while j < n and text[j] != "\"":
                j += 2 if text[j] == "\\" else 1
            out.append("\n" * text[i:j + 1].count("\n"))
            i = j + 1
            continue
        if c == "'":
            # char literal: 'x', '\n', '\u{..}'; otherwise a lifetime
            if i + 2 < n and text[i + 1] != "\\" and text[i + 2] == "'":
                i += 3
                continue
            if i + 1 < n and text[i + 1] == "\\":
                j = text.find("'", i + 2)
                i = n if j < 0 else j + 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def crate_refs(body):
    """Yield the segment lists of every `crate::...` path, expanding
    `use crate::{a, b::c, d::{e, f}}` groups one level deep."""
    for m in re.finditer(r"\bcrate::([A-Za-z0-9_:]+)(\{[^}]*\})?", body):
        head = [s for s in m.group(1).split("::") if s]
        group = m.group(2)
        if not group:
            yield head
            continue
        inner = group[1:-1]
        for item in re.split(r",", inner):
            item = item.strip()
            if not item:
                continue
            item = re.sub(r"\s+as\s+\w+$", "", item)
            sub = re.sub(r"\{.*", "", item)
            yield head + [s for s in sub.split("::") if s]


def function_lengths(text):
    """Rough: a fn at indentation <= 4 runs until the matching brace."""
    out = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^( {0,4})(pub(\([a-z]+\))? )?(async )?(unsafe )?fn ([A-Za-z0-9_]+)", line)
        if not m:
            i += 1
            continue
        name = m.group(6)
        depth = 0
        started = False
        j = i
        while j < len(lines):
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth <= 0:
                break
            if not started and lines[j].rstrip().endswith(";"):
                break  # trait method signature without a body
            j += 1
        out.append((name, j - i + 1))
        i = j + 1
    return out


def main():
    files = []
    for dirpath, _, names in os.walk(ROOT):
        for n in names:
            if n.endswith(".rs"):
                files.append(os.path.relpath(os.path.join(dirpath, n), ROOT))
    files.sort()
    modules = {module_path(f): f for f in files}
    known = set(modules)
    # shim-aware: `crate::store` and `crate::kernel::store` both resolve to
    # the module whose leaf name matches when the full path is not known.
    leaf = defaultdict(list)
    for m in known:
        leaf[m.split("::")[-1]].append(m)

    def resolve(segments):
        best = None
        for k in range(len(segments), 0, -1):
            cand = "::".join(segments[:k])
            if cand in known:
                best = cand
                break
        if best is None and segments and len(leaf.get(segments[0], [])) == 1:
            best = leaf[segments[0]][0]
        return best

    edges = defaultdict(set)
    total = 0
    non_test = 0
    big_files = []
    big_fns = []
    for m, f in modules.items():
        text = open(os.path.join(ROOT, f), encoding="utf-8").read()
        n = text.count("\n")
        total += n
        body, _ = split_tests(text)
        nb = body.count("\n")
        non_test += nb
        if nb > 1500:
            big_files.append((f, nb))
        for name, length in function_lengths(strip_noise(body)):
            if length > 150:
                big_fns.append((f, name, length))
        for segs in crate_refs(body):
            tgt = resolve(segs)
            if tgt and tgt != m and tgt not in ("lib", "main"):
                edges[m].add(tgt)
    cycles = sorted(
        {tuple(sorted((a, b))) for a in edges for b in edges[a] if a in edges.get(b, ())}
    )
    store_users = sorted(m for m in edges if any(t.endswith("store") for t in edges[m]))
    top = sorted({f.split(os.sep)[0] for f in files})
    print(f"source files under src/: {len(files)}; top level: {', '.join(top)}")
    print(f"lines of Rust: {total} total; {non_test} non-test")
    print(f"files over 1,500 non-test lines: {len(big_files)}")
    for f, n in sorted(big_files, key=lambda x: -x[1]):
        print(f"  {n:6d}  {f}")
    print(f"non-test functions over 150 lines: {len(big_fns)}")
    for f, name, n in sorted(big_fns, key=lambda x: -x[2]):
        print(f"  {n:6d}  {f}::{name}")
    print(f"modules that depend on store: {len(store_users)} of {len(files)}")
    print(f"two-way module dependencies (cycles): {len(cycles)}")
    for a, b in cycles:
        print(f"  {a} <-> {b}")
    if "--edges" in sys.argv:
        for a in sorted(edges):
            print(f"{a} -> {', '.join(sorted(edges[a]))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

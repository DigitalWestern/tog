# Blanket — next actions (2026-09-05)

**Status for a fresh agent (2026-09-05, evening):** blanket is a Rust
package-manager kernel (read ARCHITECTURE.md). **Linux x86_64 landed
today** on branch `linux-port`, PR #1 → `main`: all seven ecosystems pass
`tests/acceptance.sh` (35/35) on Fedora 44 with a bubblewrap sandbox, 158
offline unit tests, every ignored e2e gate green with
`BLANKET_SANDBOX_TESTS=required`. LINUX_PORT.md is the changelog. Hit rate
on the same 60 pinned repos: **python Linux 16/30 vs macOS 18/30; npm
21/30 on both** (HITRATE.md). Two adversarial reviews (Claude, GPT-6
Astra) returned MERGE-AFTER-FIXES; their fixes are listed at the top of
item 8. **Mac verification is done** (2026-09-05, dbf7ac4): `cargo test`,
`bash tests/acceptance.sh` 35/35, and cold-then-warm syncs of the
python/go/node fixtures (warm runs re-project the same objects in ~10 ms
with no fetch/plan/lock/build lines). The three rounds found a
locale-dependent Go fixture and a latent macOS dotnet bug, both fixed.
Only the optional stage-6 live shared-store check (rsync a Mac store onto
the Linux box) remains undone. On Linux run e2e gates with `TMPDIR` on a
real disk. Items
1–3 are done; 4, 5, 7 are not started; **items 8–12 are the Python
coverage plan** written from the actual misses, with the specimen repo
for every edge case so nobody has to rediscover them. Delegation: Codex
Luna implements, Astra reviews (Claude subagents when Codex is
rate-limited); unit tests `cargo test`, e2e `cargo test -- --ignored`.

**What actually matters, in order** (the rest of this file is the
backlog; this paragraph is the priority): the product is "one command in
any repo gives a hermetic, cached, reproducible environment, identical on
the Mac and the Linux box." Necessary and open: the two review fixes,
merge, the Mac run, interpreter selection from `requires-python` with
CPython 3.10/3.11 pins (item 8), the wheel `headers` scheme (item 9).
Makes it a tool rather than a demo: poetry/PDM/setup.py manifests (item
10), build isolation for compiled sdists (item 11). Optional until a
project the author actually uses needs it: pinned native libraries (item
12), hardware-specific requirement files, 30/30 as a number. The real
acceptance bar is the author's own repos on both machines; the hit-rate
corpus is a regression metric, not the goal.

*From a conversation about whether the product works yet. Thesis: the
reason blanket exists is that people are lazy. Every "fail closed, loud"
in LIMITATIONS.md is correct engineering and a lost user. Bun and uv won
by working on nearly every project first and being strict never; Nix was
strict first and nobody came. Blanket should be permissive by default
with strictness as a company-controlled switch.*

## 1. Measure the hit rate (do this first) — DONE (2026-09-02)

Harness: `python3 tests/hitrate.py` (top-starred GitHub repos with a
manifest, shallow clone, `blanket sync` with a throwaway store, 600s cap,
failure class per miss). Result: **Python 3/30 (10%), npm 17/30 (56%)** — see `HITRATE.md` for
the per-repo table and what it reorders: pyproject.toml input (Python's
#1 miss) folded into item 3; pnpm/yarn monorepos (npm's #1 miss) added
as item 7.

Pull 30 popular real repos each for Python and npm off GitHub. Run
`blanket sync` on each with zero config. Count successes. Record the
failure class for each miss.

That one number is the product truth: "on a random real project, does
`blanket sync` work?" Seven tailors don't answer it. Expect Python and
npm around 60 to 70 percent; the number reorders everything below.

## 2. `blanket run dev` / `test` / `build` — DONE (commit 1a1308c)

Shipped: `blanket run <script>` runs package.json scripts (pre/name/post,
npm env, exit codes) inside the projected env; Sol reviewed twice.

Read the `scripts` section of package.json, look up the name, run that
command inside the projected environment. Roughly an afternoon. This is
the single most-typed command in JavaScript development; without it
nobody survives the first five minutes. (Roadmap: task runner v0.)

## 3. Permissive by default, strict as a switch — DONE (commit 3a3d96c)

Go through every fail-closed item in LIMITATIONS.md and ask: can blanket
install this anyway and record in the closure that it could not verify
it? Most can. The closure already has an "unattested" concept from the
forest projection work.

- Individual default: install, mark the exception, keep going.
- Company policy file: "unattested packages fail sync", "git deps not
  allowed", etc. Strict mode returns for whoever wants it.
- Never loosen anything silent. Loud-and-permissive is fine; silent-and-
  wrong (RECORD files, wheel tags) stays on the fix list regardless of
  mode.

This strengthens the enterprise pitch: the manifest stops being
"everything is verified" and becomes "here are exactly the 3 of 400 that
aren't," which is where their risk actually lives.

## 4. Git dependencies via commit hash

Record repo plus exact commit, fetch, build from source in the sandbox
(same path sdists already take). A commit hash is a fingerprint; this is
a missing feature, not a hole in the model. It's how bun does it.
Unblocks private forks, unreleased fixes, and unpublished libraries.

## 5. Built-in artifacts list

Ship a table inside blanket of packages whose setup scripts download
extra files: address, sha256, expected location. Electron first. Blanket
downloads and verifies before running the script with network denied.
Same bytes at the same moment as npm would download; the only change is
who does it. A few dozen entries cover the famous cases; users should
never write these themselves.

## 7. pnpm-lock.yaml (and yarn.lock) importer — DONE (2026-09-06)

7 of 13 npm misses were pnpm workspaces whose `workspace:`/`catalog:`
protocols npm cannot re-resolve. Implemented dependency-free pnpm v9/v6 and
Yarn classic v1 importers, deterministic root-plus-per-workspace hoisting,
workspace-local links and `.bin` maps, package.json bin discovery, platform
filtering, and closure `lock_source`; Berry is rejected with an item-7
diagnostic. Round 2 measured 5/8 on the pinned eight-repo npm slice; the
remaining three are a native/install-script permission failure and two git
sources deferred to item 4. See the dated table in HITRATE.md.

## 8. Interpreter selection + CPython 3.10/3.11/3.14 pins — DONE (2026-09-05)

Implemented constraint-aware CPython selection with explicit `.python-version` precedence and PEP 440/Poetry metadata sources.
Pinned CPython 3.10.21, 3.11.16, and 3.14.7 on both platforms with cache/closure/e2e coverage.

## 9. Wheel `.data/headers` scheme — DONE

- Implemented pip/uv-compatible `headers` placement, preserving raw metadata distribution names and existing collision behavior.
- Audited `scripts`/`data` routing and containment, with unit coverage plus the ignored greenlet 3.5.5 sync/import e2e on both supported platforms.

## 10. Manifest coverage: poetry, PDM, setup.py, requirements dirs — DONE

Implemented in `src/manifest.rs` with one normalized requirement intermediate,
separate `no_manifest`/`unreadable_manifest` diagnostics, and successful
interpreter-only empty plans.

- **poetry** (specimen: sherlock-project/sherlock) —
  `[tool.poetry.dependencies]` with caret/tilde constraints (`^0.4.1` →
  `>=0.4.1,<0.5.0`, `~1.2` → `>=1.2,<1.3`), the `python` row excluded and
  fed to item 8, table-form deps (`{version=…, optional=true, markers=…,
  extras=[…]}`), optional deps skipped unless an extra names them,
  `[tool.poetry.group.*.dependencies]` excluded by default. If a
  `poetry.lock` exists prefer it (it carries hashes) — a lockfile
  importer, same argument as item 7. Implemented, including Poetry constraint
  conversion, table dependencies, optional extras, main-group reachability,
  file hashes, and lock disagreement exceptions.
- **PDM / uv / hatch** — `[project.dependencies]` already works; add
  `[tool.pdm.dev-dependencies]` and `[dependency-groups]` (PEP 735) as
  excluded-by-default groups; honor `uv.lock` when present. Implemented with
  host wheel selection and uv fallback when no compatible locked file exists.
- **setup.py that computes its dependencies** (specimen:
  FoundationAgents/MetaGPT reads requirements.txt at import time;
  vllm-project/vllm builds the list from `requirements/*.txt` with
  platform branches). The only faithful reading is running
  `python setup.py egg_info` (or `pip`'s metadata build) **inside the
  sandbox** with the repo checked out read-only and no network, then
  parsing `requires.txt`/`PKG-INFO`. Cache by tree hash of the repo
  inputs. `setup.cfg` `[options] install_requires` is a plain parse. Implemented
  with cached sandboxed egg_info and requires.txt/PKG-INFO parsing.
- **requirements directories** (specimen: vllm) — `-r`/`-c` includes
  (relative to the including file, cycle-safe), inline `#` comments
  after a requirement, `--extra-index-url`/`--index-url`/`--find-links`
  lines (record them as unattested inputs for the policy switch; never
  silently follow), environment markers, and hardware-specific files
  (`cpu.txt`, `cuda.txt`, `rocm.txt`, `xpu.txt`): choose by an explicit
  `blanket.toml` hint or default to `cpu`, and say which was chosen.
  Convention search order when nothing is declared: `requirements.txt`,
  `requirements/common.txt` or `base.txt`, `requirements-*.txt` excluded.
- **Zero-dependency projects** (specimen: ytdl-org/youtube-dl,
  setup.cfg with no install_requires): a manifest that declares nothing
  is a **successful** sync with an interpreter and an empty env, not
  `no_inputs`; it is reported as an empty manifest. Split the failure
  classes: `no_manifest` (nothing found) vs `unreadable_manifest` (found,
  could not parse — always a blanket bug). `empty_manifest` is success-only,
  never an error.

## 11. Build isolation for compiled sdists — DONE (2026-09-05)

Implemented archive inspection, cached PEP 517 build environments,
schema-3 sdist identities, recursive build-requirement sdists, and pinned
Rust/Cargo vendoring for compiled sdists. Added ignored real-package coverage
for tomli-w, insightface 0.7.3, and tokenizers 0.13.3.

Three misses are sdists that need things at build time that blanket does
not give the sandbox: tokenizers 0.13.3 (Rust), insightface 0.7.3
(numpy + Cython), manimpango 0.6.1 (pango/cairo headers → item 12).
Today sdists build with `--no-build-isolation` in a sandbox that sees
only the interpreter.

- Resolve `[build-system].requires` (default `setuptools>=40.8, wheel`
  when absent, per PEP 517) with uv against the same index snapshot, as
  a separate small env object keyed by the requirement set; mount it
  read-only into the build sandbox and put it on `PYTHONPATH`. Its id is
  an input of the sdist's derivation fingerprint.
- Rust: blanket already pins a Rust toolchain (`src/cargo.rs`). When the
  backend is maturin/setuptools-rust, or the sdist has a `Cargo.toml`,
  mount the toolchain object, set `CARGO_HOME` to scratch, and vendor
  the crate graph from `Cargo.lock` through the existing cargo fetch path
  (the sandbox has no network — vendoring is the only option). Record the
  Rust toolchain id in the fingerprint.
- Edge cases: sdists with no `Cargo.lock` (resolve once, record the lock
  as unattested); `setup_requires` in old setup.py (not handled because
  pip would need network in the sandbox); backends that need `cmake`/`ninja` from
  PyPI wheels (they resolve fine as build requires); numpy ABI — build
  against the **oldest** numpy the runtime env allows, or the runtime
  env's exact numpy, never a newer one.

## 12. Pinned native libraries — DONE (2026-09-06)

Implemented option (a), Linux first. `src/nativelibs.rs` realizes one
input-addressed `native-libs/libset/3` object from a pinned conda-forge
closure, relocates every text/binary prefix occurrence during staging, and
exposes it read-only to compiled sdists and npm `node-gyp` builds. The conda
pkg-config wrapper is replaced with a direct real-binary launcher so the
libset-only `PKG_CONFIG_PATH`/`PKG_CONFIG_LIBDIR` cannot be widened by host
paths. Because relocation embeds the absolute object path, the canonical
store root is also an identity input: different `BLANKET_STORE` roots produce
different native ids. These wrapper, relocation, and identity changes are the
libset v2 -> v3 bump. The native object id is recorded in the sdist/npm
derivation and environment identities; Python and Node closure envelopes
retain the reference for liveness/GC. Fast pure setuptools sdists do not
mount it; archives with C/C++/Cython or `binding.gyp` and all isolated PEP 517
builds do.

The Linux pin is the 2022-era conda-forge closure listed in
`src/nativelibs.rs` (legacy `.tar.bz2` records; the extractor also supports
`.conda`). It includes pango/cairo and their complete repodata dependency
closure, including the shared GCC 12 runtime. The realized object is about
289.1 MiB on Fedora 44. `manimpango==0.6.1` now builds from its sdist and
imports successfully with only the object-library runpath at runtime.

macOS arm64 is intentionally not realized yet: no native v1 pin is shipped,
and requesting it fails closed before store/network access. The ignored
Linux gate is:

    BLANKET_STORE=$HOME/scratch/tmp/nx12-store TMPDIR=$HOME/scratch/tmp \
    BLANKET_SANDBOX_TESTS=required cargo test --test native_libs -- --ignored

Later: run uv's resolve-time metadata builds inside the sandbox.

manimpango needs pango+cairo headers through pkg-config; nokogiri only
needed host zlib. Two honest options, pick when the first real project
asks: (a) a small pinned library set (pango, cairo, libffi, openssl,
zlib, libxml2…) realized like any other toolchain object and mounted
read-only, with `PKG_CONFIG_PATH` pointed at it — ids stay host-
independent; or (b) allow declared host library reads under an
unattested exception, which is faster but makes the object depend on the
 host. (a) is the one consistent with the store model; it also subsumes
 the "pinned Linux C toolchain" roadmap item.

## Hit-rate bookkeeping (so the number stays honest)

- Every miss carries a class that maps to an item in this file; a miss
  with no item is the first thing to add.
- `no_manifest` counts against blanket only if a human can point at
  where the dependencies are declared; otherwise it is out of the
  denominator and listed separately.
- Re-measure on the Linux box (12 cores) with the pinned lock after each
  item; update the HITRATE.md table with a dated column rather than
  overwriting.

## 13. Store GC — DONE (2026-09-06)

Implemented `blanket gc` with project-root registration, closure and
transitive object liveness, keep-days cache retention, dry-run reporting,
stale-stage cleanup, and opt-in `--project` forest/backup cleanup.

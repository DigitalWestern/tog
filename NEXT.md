# Blanket — next actions (2026-09-02)

*From a conversation about whether the product works yet. Thesis: the
reason blanket exists is that people are lazy. Every "fail closed, loud"
in LIMITATIONS.md is correct engineering and a lost user. Bun and uv won
by working on nearly every project first and being strict never; Nix was
strict first and nobody came. Blanket should be permissive by default
with strictness as a company-controlled switch.*

## 1. Measure the hit rate (do this first) — IN PROGRESS (2026-09-02)

Harness: `python3 tests/hitrate.py` (top-starred GitHub repos with a
manifest, shallow clone, `blanket sync` with a throwaway store, 600s cap,
failure class per miss). Results land in `HITRATE.md` when the run ends.

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

## 3. Permissive by default, strict as a switch — IN PROGRESS

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

## Later, but before anyone runs it for a year

- `blanket gc`: delete store objects, forests, and backups that no
  project points at. Store grows forever today.

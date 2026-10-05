# Hit rate

How often a bare `tog` works with zero configuration on popular real
repositories. It is a measurement, not a gate, but run it before merging
anything that touches npm projection or the store's real-directory checks.

**Method.** `python3 tools/hitrate.py --repos tools/hitrate/hitrate-repos.lock`
takes 30 top-starred Python and 30 top-starred npm repositories pinned to
fixed commits, shallow-clones each, and runs `tog sync` (the bare form's hidden alias,
so no help screen lands in the log) against a
throwaway store with a 600 s cap. Each failure is classified by the
`RULES` regexes in `tools/hitrate.py`. Raw results are dated CSVs under
`tools/hitrate/`; they are historical records and are never rewritten. A
full 60-repo run takes about 95 minutes on the Linux box.

**Three numbers per ecosystem**, all derived from one permissive run:

1. **permissive ok**: the developer-experience number.
2. **company-policy ok**: ok with no exception that
   `docs/human/policy-company.toml` denies. Quote this one to a security
   buyer.
3. **strict ok**: ok with zero exceptions. Not a product number: several
   exception kinds (`file-collision`, `built_from_source`) are not
   security findings. `skipped_optional` was one too until 2026-10-05
   (#71); it is no longer an exception (see that section).

Only Python and npm are measured. Earlier runs (2026-09-02 macOS,
2026-09-05/06 Linux) are in git history and in their CSVs.

## Linux x86_64 — 2026-10-05: strict without `skipped_optional` (#71)

Not a new run: a re-scoring of the 2026-09-23 CSV. An optional group the
user did not request is now recorded as `optional_groups_skipped` in the
closure, not as an exception, so it no longer counts against strict.
Strict adds refusals only, so strict ok is permissive ok with zero
recorded exceptions (the method the 2026-09-11 section describes), and
removing one kind from a permissive CSV gives the strict number a run with
this change would report. Permissive and company-policy do not move:
company policy never denied the kind.

| ecosystem | permissive | company-policy | strict | 2026-09-23 strict |
|---|---|---|---|---|
| python | 26/30 | 24/30 | **20/30** | 8/30 |
| npm | 28/30 | 15/30 | **15/30** | 14/30 |

The six Python oks still not strict carry `file-collision` (Deep-Live-Cam,
odysseus, autoresearch), `requirement-skipped` (TradingAgents,
gpt_academic), `unattested-index` (autoresearch) and
`artifact-not-provisioned` (django). npm gains one: ECC's only exceptions
were seven `skipped_optional` records from its `pyproject.toml`.

## Linux x86_64 — 2026-09-23 (m6-fedora, tog 4720e12, pinned 60)

Same command and method as 2026-09-11 below. Raw data:
`tools/hitrate/hitrate-linux-2026-09-23.csv`.

| ecosystem | permissive | company-policy | strict | 2026-09-11 permissive |
|---|---|---|---|---|
| python | **26/30** (27/30 after #213) | 24/30 | 8/30 | 26/30 |
| npm | **28/30** (29/30 after #213) | 15/30 | 14/30 | 20/30 |

npm moved 20 → 28: vite, playwright, mermaid, NextChat and the three
workspace repos fixed on 09-11 now sync. The npm work merged in between
(#172 Yarn `#sha1` read as integrity, #182 used-deps and fatal
provisioning, #192 pnpm links and patches) was not bisected per repo. NextChat's 09-11 cause below is wrong: it was a Yarn
`#sha1` fragment read as a git commit, not a shallow fetch (#172).

Six misses, three of them one cause: the Rust catalog shipped one release,
so any project pinning another Rust failed. #213 ships 43 releases
(1.70.0 to 1.98.1). A re-run of those three repos on main 68c6f03 (CSV not
kept, three rows): headroom and clash-verge-rev sync; tailwindcss gets past
Rust and fails on the next known row.

| repo | class | reason | tracked |
|---|---|---|---|
| AUTOMATIC1111/stable-diffusion-webui | py_sdist_build_failed | tokenizers 0.13.3 sdist needs Rust at build time | #215 |
| vllm-project/vllm | unreadable_manifest (misclassified) | `uv pip compile failed` | #216 |
| FoundationAgents/MetaGPT | py_uv_resolve_failed | `uv pip compile failed` | #216 |
| headroomlabs-ai/headroom | other | Rust 1.95.0 not in the catalog | **fixed by #213** (re-run ok) |
| clash-verge-rev/clash-verge-rev | other | Rust 1.98.0 not in the catalog | **fixed by #213** (re-run ok) |
| tailwindlabs/tailwindcss | other → npm_platform_required | Rust 1.95.0, then a required darwin-only devDependency | Rust fixed by #213; platform row is #214 |

**2026-10-03, one repo re-run (not a new column).** tailwindcss at its
pinned commit, on the branch that closes #214: `tog sync` exits 0 for both
of its ecosystems (node, 443 packages; cargo). It took two changes. The
required foreign-platform packages are placed and recorded
(`foreign-platform-package`, 10 of them). Three registry plugins
(`@tailwindcss/forms`, `typography`, `aspect-ratio`) have the workspace's own
`tailwindcss` as their peer, which used to be the next refusal ("would be
planted inside the package"); the tree is now projected as a copy and each
records `unattested-mutable-state`, so tailwindcss is a permissive ok and
not a company-policy ok. `bun`'s postinstall still fails in the sandbox
(`install-script-failed`, as before). The full 60 were not re-run.

## Linux x86_64 — 2026-09-11 (m6-fedora, tog fb8b1d6, pinned 60)

Command: `cargo build --release`, then `python3 tools/hitrate.py --repos
tools/hitrate/hitrate-repos.lock --work … --out … --timeout 600 --keep`,
followed by the same with `--strict`. Raw data:
`tools/hitrate/hitrate-linux-2026-09-11.csv` (permissive). The strict CSV
is derived: strict adds refusals only, so strict ok = permissive ok with zero
recorded exceptions; the literal `--strict` pass was run to confirm that.

Three numbers per ecosystem, all from the one permissive run (the harness
prints them; `COMPANY_DENY` in `tools/hitrate.py` defines "company-policy",
matching `docs/human/policy-company.toml`):

| ecosystem | permissive | company-policy | strict | 2026-09-05 permissive |
|---|---|---|---|---|
| python | **26/30** | 24/30 | 8/30 | 16/30 |
| npm | **20/30** (23/30 with the `plan_npm` fix below) | 13/30 (14/30) | 12/30 (13/30) | 21/30 |

### Python: 16 → 26

Ten repos flipped to ok: the five-pin CPython table (3.10–3.14) covers
fastapi and autoresearch; the greenlet `.data/headers` bug is gone (ComfyUI,
odysseus, crawl4ai, gpt_academic); Deep-Live-Cam, manim, sherlock,
LlamaFactory now build. Remaining four misses:

| repo | class | reason |
|---|---|---|
| AUTOMATIC1111/stable-diffusion-webui | py_sdist_build_failed | tokenizers 0.13.3 sdist needs Rust at build time |
| vllm-project/vllm | py_uv_resolve_failed | `uv pip compile` fails (dynamic metadata) |
| FoundationAgents/MetaGPT | py_uv_resolve_failed | `uv pip compile` fails |
| headroomlabs-ai/headroom | rust_toolchain_unpinned | `rust-toolchain.toml` pins 1.95.0; only 1.96.1 is pinned |

**Strict collapses to 8/30 because of `skipped_optional`** (1,104 records:
every optional-dependency group not requested). That is a user choice, not
a waiver, and `file-collision` (247) is not a security finding either. The
company-policy column ignores both; its two denials are autoresearch
(`unattested_index`) and django (`artifact_not_provisioned`, puppeteer).

### npm: 21 → 20, and what moved

Eight npm oks became misses since 2026-09-05 at the same pinned commits;
five of the eight are tog regressions, not repo changes:

| repo | class | reason | status |
|---|---|---|---|
| google-gemini/gemini-cli | npm_script_failed | `workspace-node_modules parent …/packages/a2a-server/node_modules is not a real directory` | **fixed in this branch** (`plan_npm` treated workspace-local packages as workspaces; on 09-05 they were silently not installed) |
| react/create-react-app | npm_script_failed | same, `docusaurus/website/node_modules` | **fixed in this branch** |
| earendil-works/pi | npm_script_failed | same, `packages/agent/node_modules` | **fixed in this branch** |
| vitejs/vite | npm_script_failed | `workspace-node_modules …/__tests__/plugins/fixtures/license/dep-license-mit/node_modules is a real file or directory; refusing to overwrite it` — a checked-in fixture `node_modules` inside a pnpm workspace member | regression from the no-overwrite check; FOLLOW-UPS |
| microsoft/playwright | npm_script_failed | `commit env: cache dependency sha256:6705a9… is unavailable` | regression, likely object-meta/2 cache-dependency tracking; FOLLOW-UPS |
| mermaid-js/mermaid | other | `pnpm patch fastdom has no package@version identity` | pnpm `patchedDependencies` keyed by bare name (new fail-closed row); FOLLOW-UPS |
| paperclipai/paperclip | fetch_failed | pnpm patch hash mismatch (expected base32 `fymct…`, computed sha256 hex) | **fixed** — pnpm 9 is base32 of **md5**, with lossy UTF-8/CRLF normalization; normalized matches bind raw bytes by SHA-256, raw SHA-256 matches keep their existing identity, and the verified bytes are snapshotted in a private `stage-*` directory before `patch` reads them  |
| ChatGPTNextWeb/NextChat | other | git source `aoai-realtime-audio-sdk` checkout of `abf2e9a8…` fails: `unable to read tree` (shallow/partial fetch) | git-dependency realization; FOLLOW-UPS |

Also new: tailwindcss now fails on `@parcel/watcher-darwin-arm64` being a
*required* dependency that does not support Linux (the pnpm lock marks it
required). This run's CSV records it as `py_no_wheel`; the classifier now has
an `npm_platform_required` class for it, and future runs will use that. The
CSV is a historical record and keeps the old label. hoppscotch and tabby,
which git-dependency support was expected to unblock, now sync (with `git-dependency`
exceptions, so they are company-policy misses).

Company-policy denials on npm: `artifact_not_provisioned` (vue, shadcn,
ant-design), `install-script-failed` (gstack, uptime-kuma, tabby),
`git-dependency` (hoppscotch, tabby), `weak-integrity` (tabby).

### Re-measurement of the three fixed repos

Re-run of gemini-cli, create-react-app and pi at their pinned commits with
a release build of this branch (`TOG_BIN=…/target-fixed/release/tog`,
throwaway store), permissive and `--strict`:

| repo | permissive | strict | note |
|---|---|---|---|
| google-gemini/gemini-cli | ok, 0 exceptions, 290 s | ok | workspace-local packages under `packages/a2a-server/node_modules` now present |
| react/create-react-app | ok, 163 s, 435 exceptions (434 `weak-integrity`: sha1 lock entries; 1 `artifact_not_provisioned`) | policy_denied (`weak-integrity`) | `docusaurus/website/node_modules` workspace-local packages now present; company-policy miss |
| earendil-works/pi | ok, 90 s, 2 exceptions (`built_from_source` canvas@3.2.3, `install-script-failed`) | policy_denied (`built_from_source`) | `packages/agent/node_modules` workspace-local packages now present; company-policy miss (`install-script-failed`) |

A second create-react-app sync with a fresh store confirmed that the 435
exceptions printed to stderr are exactly the 435 in `.tog/closures/node.json`:
the closure is a truthful record of what strict would refuse.

The literal `--strict` pass over all 60 with the unfixed binary: **python
8/30, exactly the derived number** (20 `policy_denied`, 4 the same misses as
permissive). The npm half was still running when this was written; it is
confirmation only.

### What the run says

- The developer number is good and rising: Python 87 percent, npm 67
  percent (77 percent once the workspace fix is in), on the same 60 repos.
- The strict number is not a product number. Quote the company-policy
  column. (`skipped_optional` stopped being an exception on 2026-10-05,
  #71.)
- Five npm regressions slipped past the acceptance suite between 09-06 and
  09-10 because the hit-rate harness is not a gate. It should be run before
  merging anything that touches npm projection or the store's real-directory
  checks; a 60-repo run is about 95 minutes on this box.

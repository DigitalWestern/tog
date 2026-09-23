# DESIGNS — work that is designed but not built

The one agent-facing design file. Everything here is **future work**: nothing
in it describes shipped behavior (for that, read `docs/human/ARCHITECTURE.md`).
Open decisions and the ordered to-do list live in `FOLLOW-UPS.md`; this file
holds the detail a session needs to pick an item up cold. When an item
ships, its description moves into `docs/human/` and its `FOLLOW-UPS.md`
entry is deleted.

Assembled 2026-09-16 from the archived implementation plan and the long-form
architecture document, both deleted in the documentation cleanup (recover
either with `git show 1ac2d23:docs/agent/PLAN-2026-09-09.md` or
`git show 1ac2d23:docs/agent/ARCHITECTURE-full.md`).

**Read paths with care.** The text predates the 2026-09-12 folder refactor.
Flat paths map to folders: `src/python.rs`, `src/pyselect.rs`, `src/pypi.rs`,
`src/build.rs` → `src/tailors/python/`; `src/npm.rs` → `src/tailors/node/`;
`src/cargo.rs` → `src/tailors/cargo/`; `src/golang.rs` → `src/tailors/go/`;
`src/ruby.rs`, `src/elixir.rs`, `src/dotnet.rs` → their tailor folders;
`src/platform.rs`, `src/policy.rs`, `src/store.rs`, `src/archive.rs`,
`src/supervise.rs`, `src/sandbox.rs`, `src/gitsrc.rs` → `src/kernel/`;
`src/project.rs` → `src/comforter/`; `src/main.rs`, `src/inspect.rs`,
`src/deps.rs`, `src/xrun.rs` → `src/commands/`; `src/cli.rs` → `src/cli/`.
Line numbers are stale; search for the symbol. "WP1…WP5" are the old plan's
work-package names (WP1 is `tog fmt`, shipped) and "GC Package A–D"
the shipped GC-safety work; both are kept because FOLLOW-UPS and commit
history use them.

## Contents

1. Toolchain lock and exact version selection (WP2)
2. Release catalog and publisher trust (WP3)
3. Daily-driver gaps (WP4 open items)
4. The company layer (WP5)
5. GC-safety leftovers (supervision exclusions, missing tests, per-operation signal sessions)
6. The resolution proxy (#68): delegated tools confined to a tog-owned registry proxy
7. Backlog

---

## 1. Toolchain lock and exact version selection (WP2)

### The contract

WP2 design, 2026-09-06; source/trust boundary reconciled in the owner's
2026-09-09 plan re-review. This section specifies
future behavior; it does not claim that the lock or WP3 authentication ships.
The lock is a small committed planning input, not a
second dependency lock. Today it wraps mostly static CPython/uv
(`src/python.rs:10-20`, `src/python.rs:108-129`), Node (`src/npm.rs:114-146`),
Rust (`src/cargo.rs:15-68`), and Go (`src/golang.rs:24-45`) tables, plus
Python's unconstrained default (`src/pyselect.rs:114-125`); it makes that
choice durable without changing any default version.

### File and schema

The file is `tog-toolchain.toml` at the project root, next to manifests and
outside ignored `.tog/`; workspaces use the same nearest root as their
planner. TOML is reviewable with strict unknown-field/type errors, and the
writer emits canonical key/array order so equivalent locks have identical bytes.

The schema is versioned and intentionally boring:

- root keys are `schema_version`, `tog_version`, and `toolchain`;
- each `toolchain.<ecosystem>` has `runtime`, a `release` key naming the catalog
  bundle the row was minted from — provenance and a uniqueness check, never a
  key tog looks up to honor the lock —
  `bundle_id`, its primary component (or BEAM pair), optional integer
  `revision`, a complete `components` list, component tables, `inputs` rows,
  and `platforms.<triple>.artifacts.<component>` rows;
- component tables have exact `version` and, when applicable, `embedded_in`;
  independent artifact rows have `provider`, `build`, stable `recipe`, `url`,
  and a verified, algorithm-qualified `digest` — `sha256:<hex>` or
  `sha512:<hex>`, the same shape `bundle_id` uses, so the row names the
  algorithm the verifier must use. `src/fetch.rs:93-102` already models that
  algorithm-qualified `Digest`, and the artifacts already verified under
  sha512 today (the .NET SDK at `src/dotnet.rs:95`, Hex and rebar3 at
  `src/elixir.rs:759-760`) keep their published digests instead of being
  re-pinned. `recipe` covers extraction, layout, and relocation;
- an embedded component has metadata and `embedded_in = "<parent>"` but no
  artifact row; `embedded_in` may chain, and the digest of the nearest
  independently fetched ancestor covers the whole chain (node-gyp sits inside
  bundled npm, which sits inside the Node artifact —
  `lib/node_modules/npm/node_modules/node-gyp/`, `src/npm.rs:166`).
  Independently fetched components get one row per platform, so npm/node-gyp
  and Go stdlib appear once; and
- `inputs` is the ecosystem's **whole consulted path list, in precedence
  order** — not just the file that won. A row always has `path` and `field`. It
  has `sha256` when the file exists, and `value` when discovery found a request
  at `field`; `absent = true` marks that it found none. The two facts are
  independent, so the three real states each have one spelling and none is a
  special case: file missing (`absent`, no `sha256`), file present without the
  field (`absent` with `sha256`), field found (`value` with `sha256`). `value`
  is the canonical parsed request; `sha256` is the digest of that source file's
  whole bytes as read through the held root descriptor, the same whole-file
  digest `status` already computes for recorded inputs (`sha256_file`,
  `src/inspect.rs:332-334`). Recording absence is what makes the list a
  complete statement about the project instead of a list of survivors: if the
  lock only recorded the winner, creating a *higher*-precedence file — no
  `.python-version`, so `requires-python` won; then someone adds
  `.python-version` — would change nothing the lock knows about, and tog
  would keep serving the old runtime while every other tool in the repo moved.
  With absence recorded, that file appearing is a row flipping from absent to
  present, which is the same comparison as any other change.
  **Staleness is one rule for every row: re-derive the row and compare. A row
  is stale when a `value` appears where the record has `absent`, when the record
  has a `value` and re-derivation finds none, or when both have a `value` and
  they differ.
  That rule decides staleness in ordinary sync, under `--frozen`, and in
  `status` alike, and the ecosystem is stale when any of its rows is.** The
  digest is a fast path, never a verdict: a matching digest proves the file is
  untouched and lets all three skip the re-parse, while a differing digest
  forces the re-parse and nothing else, so a comment, a whitespace edit, or a
  `tog add` that delegates a rewrite of `pyproject.toml`, `package.json`,
  or `go.mod` to uv, npm, or go leaves the lock fresh — the `field` key exists
  precisely because those sources are multi-purpose. A present file that no
  longer parses is stale: there is no `value` to compare.
  `changed_inputs` (`src/inspect.rs:337-352`) therefore cannot be reused
  verbatim — it reports "changed" on digest inequality alone, knows nothing
  about `field` or `value`, and never looks at a path that has no row — so the
  lock needs a presence- and value-aware sibling. The alternative, digesting
  only the extracted field for multi-purpose manifests, is rejected: it
  re-encodes `value`, which the row already records in readable form, and it
  buries a per-ecosystem extraction rule inside the digest definition instead
  of one `sha256_file` call for every source. Provider-native hashes are
  evidence only; Tog's own verified artifact digest is mandatory.

Both triples appear for every fetched component even when syncing on one host;
platform-neutral components repeat their digest. A lock records provider
builds, components, recipes, and per-platform bytes — never dependency entries,
credentials, store paths, object ids, or host facts. `tog_version` is
provenance, not staleness: `schema_version`, recipe support, source inputs, and
artifact rows decide compatibility, and trust fixes never rewrite old locks.
Because recipe ids are append-only, "recipe support" can only fail forward — a
lock written by a newer tog naming a recipe this one has never heard of —
never backward on recipe support. Current trust/endpoint policy can still
refuse a previously allowed artifact without changing its locked bytes.

The catalog unit is a complete **release bundle per ecosystem**. Its unique,
opaque `release` key is not a version selector: recipe revisions of one primary
version take distinct keys and `bundle_id`s, never duplicates. A lock copies
exactly one bundle, and rows mixing two releases are rejected as an
inconsistency inside the lock itself, which is a check the lock can do alone.
Only project `inputs` sit outside the bundle.

The immutable `bundle_id` is sha256 over the bundle's canonical serialization,
defined here so two implementations agree byte for byte. The serialization is a
sequence of records; each record is a sequence of fields; each field is emitted
as `<byte length in decimal>:<UTF-8 bytes>`, so no value can be mistaken for a
delimiter and no two distinct field sequences can serialize alike. The records,
in order, are: one `("bundle", "1")` version record; one
`("component", name, version, embedded_in-or-empty)` record per component,
sorted by name; and one
`("artifact", triple, component, provider, build, recipe, url, digest)` record
per platform artifact row, sorted by triple then component. Nothing else
enters the hash — not `release`, not `revision`, not `inputs`, not the
ecosystem name. The leading version record is how the definition grows without
an exception: a schema that adds a hashed field mints serialization `"2"`, new
bundles get `"2"` ids, and every bundle already minted keeps the id its own
recorded serialization produced.

The lock's own canonical bytes are defined just as tightly, because
byte-identical locks from both platforms is a tested claim: UTF-8, LF endings,
one trailing newline, no comments, tables emitted in the schema's declared
order, keys within a table in the schema's declared order, arrays in the order
the schema states (never in discovery order), basic double-quoted strings with
no unnecessary escapes, and integers with no leading zeros or sign. A writer
that follows it and a reader that re-serializes what it read produce the same
bytes, which is what lets publication compare bytes rather than parse trees.

This Node bundle uses shipped pins: npm is embedded in the Node artifact and
node-gyp inside that bundled npm, so the Node artifact's two platform rows are
the whole independently-fetched set. (The shipped catalog today lists only
the `node` component: the pin table records no verified npm or node-gyp
version, and the catalog invents none. The embedded rows appear once those
versions are verified at pin time.) Its `.node-version` holds `24.20.0\n`,
whose sha256 is that input row's digest, and its `package.json` carries no
`engines.node`, which the second row records rather than omits:

```toml
schema_version = 1
tog_version = "0.1.0"

[toolchain.node]
runtime = "node"
release = "node-24.20.0-r1"
bundle_id = "sha256:683bc7a0c5d38d3fcc9e73a6e55ab75bda308fb66204c4808942e750b5c1266b"
primary = "node"
revision = 1
components = ["node", "bundled-npm", "node-gyp"]
[toolchain.node.component.node]
version = "24.20.0"
[toolchain.node.component.bundled-npm]
version = "11.19.0"
embedded_in = "node"
[toolchain.node.component.node-gyp]
version = "12.4.0"
embedded_in = "bundled-npm"
[[toolchain.node.inputs]]
path = ".node-version"
field = "version"
value = "24.20.0"
sha256 = "5b9d0e73029969ae9000117cb877f17bb9841c1279bfe8024e294acfcf017800"
[[toolchain.node.inputs]]
path = "package.json"
field = "engines.node"
absent = true
sha256 = "9f2c1a7c8b0a5f4e6d3b2718c9a04e5f1d6b83c27a4e90f5b1c8d3a672e4f0b9"
[toolchain.node.platforms."aarch64-apple-darwin".artifacts.node]
provider = "nodejs.org"
build = "24.20.0"
recipe = "nodejs/legacy"
url = "https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz"
digest = "sha256:40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8"
[toolchain.node.platforms."x86_64-unknown-linux-gnu".artifacts.node]
provider = "nodejs.org"
build = "24.20.0"
recipe = "nodejs/legacy"
url = "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.gz"
digest = "sha256:855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec"
```

Real locks include every consulted field; missing rows, bad digests, or an
unknown schema invalidate the lock without host fallback.

**The refreshed catalog is not on the path that selects bytes for a locked
run.** A lock row carries component version, retrieval URL,
algorithm-qualified digest, and recipe id. Replay uses those fields rather
than looking up its old release key in today's catalog. Only creating a lock
or `tog update --toolchain` selects a new bundle. Removing a release from
a new catalog therefore does not invalidate a lock or change its artifact
bytes. Unknown forward schemas/recipes, unavailable bytes, or digest mismatch
can still fail; current endpoint/trust policy can also refuse use.

WP2 uses a typed source-policy interface with shipped upstream endpoint
defaults. These are configurable defaults, not an append-only compiled host
allowlist baked into lock validity. HTTPS retrieval validates each endpoint
and redirect against effective policy; `file://` and unauthorized destinations
fail before fetch. Credentials are endpoint/audience-scoped references and
never lock contents. A redirect to another origin receives no credentials
unless separately authorized. Recipe IDs remain append-only; permission to
contact an endpoint does not.

**Integrity is not publisher authentication.** A digest in an editable lock
proves a match to that lock, not that a trusted publisher vouched for the
artifact. WP3 adds authenticated payload/proof bound to the artifact digests,
versions, platforms/components, and recipe/bundle identity. It verifies the
proof and current publisher/endpoint policy on replay and cache hits, without
consulting a refreshed release catalog to choose versions. Offline replay
under authenticated policy requires cached artifacts **and** locally
verifiable proof. Old WP2 locks lacking proof are refused under that policy;
they are not silently certified or rewritten.

WP3 PR 1 owns unconditional protected-machine policy loading and the shared
source configuration model; WP5 extends it with ecosystem credentials and
package enforcement. User/project layers cannot widen a protected publisher
or endpoint set. Adding an authorized publisher is an explicit configuration
change, separate from package verification exceptions. Key removal/revocation
and tightened endpoint policy may intentionally refuse old locks. Report
that as a policy/trust refusal, not input staleness. The owner's key policy
must define rotation, expiry/rollback, and offline revocation freshness before
live authenticated refresh is activated. Transport failures may use a
still-valid last-good snapshot; invalid signatures, revoked keys, and detected
rollback never enter that fallback path.

Recipe ids are append-only for the same reason. `nodejs/legacy`,
`rust-toolchain/1`, `go-toolchain/1` and their successors are never removed and
never redefined; an output-affecting change mints a new id and leaves the old
one supported. A recipe id in a five-year-old lock still resolves, which preserves locked output semantics across upgrades.
This compatibility promise does not override a deliberate trust revocation
or tightened source policy.

Every lock implementation needs a reusable pre-materialization extractor in
`src/archive.rs`: list and validate every entry first (no absolute paths/`..`,
hard links, or special files; symlinks only when targets are contained), with
`TAR_OPTIONS` and `UNZIPOPT` unset for delegated tar/unzip; its PR below owns
the containment tests. Existing helpers are not this contract: `build_requires`
checks extracted links after materialization (`src/build_requires.rs:499-566`,
`src/build_requires.rs:579-619`), while `gitsrc` validates before *packing* and
its ustar helper only checks header capacity (`src/gitsrc.rs:924-981`,
`src/gitsrc.rs:1120-1132`).

The recipe is also an identity boundary. Implementations already use recipe
markers such as `rust-toolchain/1` (`src/cargo.rs:107-129`) and
`go-toolchain/1` (`src/golang.rs:59-68`), and the native set's identity version
is `native-libs/libset/3` (`src/nativelibs.rs:553-564`, version at
`src/nativelibs.rs:21`). CPython and Node identities keep their existing
artifact/platform inputs with no new schema input (`src/python.rs:131-152`,
`src/npm.rs:149-158`), so their legacy recipe mapping must preserve those ids.
Any output-affecting extraction, layout, or relocation revision gets a new
recipe identity and a new lock component row; the legacy mapping keeps existing
object ids, including the byte-identical Darwin goldens.

### Pre-planning security gate

The lock is not permission to read arbitrary project paths: each
`inputs.path` is project-relative, normalized, and free of `..`; the allowed
set comes from manifest discovery. To close TOCTOU, open the project root once
and every input descriptor-relative beneath that held descriptor with
`O_NOFOLLOW` at every component; a symlinked input or ancestor is an error.

Descriptor-anchored closure publication has landed in `src/project.rs`;
`src/store.rs` and `src/xrun.rs` also contain no-follow directory/deletion
helpers. The old claim that the tree contains no `openat`/`O_NOFOLLOW` was
stale. `src/kernel/fsroot.rs` (`ProjectRoot`) is now the shared helper:
WP2 PR 3 extends it for lock/input discovery. Keep the root
descriptor, walk components with `openat`/`O_NOFOLLOW`, create with `O_EXCL`,
and rename descriptor-relative. Path-based `fs::read`/`fs::write`/`fs::rename`
do not satisfy the refusal tests in this section.

The retained snapshot includes `tog-toolchain.toml`: its held descriptor,
identity metadata (including inode), and bytes, alongside source descriptors.
Ordinary sync opens the lock through the held project root and keeps the
per-project writer lock shared through planning, realization, and publication,
so `update --toolchain` cannot install L1 while sync plans from L0.
The toolchain-input lock is separate from C's short exclusive project
transaction lock: acquire activity → x-root (if any) → toolchain-input lock
→ project-transaction lock → cache lease → publication lock. Never upgrade
one shared file description to publish through it. Pure frozen input
validation precedes store bootstrap/maintenance, so a validation failure
still performs none of their writes. That lock
is an optimization, not the guarantee: immediately before publication, and
regardless of lock ownership, reopen `tog-toolchain.toml` through the held
root descriptor with descriptor-relative `openat` and `O_NOFOLLOW` and compare
its bytes to the snapshot. A mismatch aborts with `tog-toolchain.toml
changed during sync (update --toolchain race)`, leaving the old closure and
projection untouched.

The lock has exactly two writers — the first writable sync of a project with
no lock, and `tog update --toolchain` — and both publish by ONE rule, with
no weaker path for the first write: create the temp file descriptor-relative
in the held project-root directory with `O_EXCL` and `O_NOFOLLOW`, write it,
`fsync` that file descriptor, rename it descriptor-relative and without
following symlinks over `tog-toolchain.toml`, then `fsync` the held root
directory descriptor, mirroring closure publication. Both syncs carry weight
and neither is a nicety: the file `fsync` is what makes the rename publish
bytes instead of a filesystem-dependent window of zeros after a power loss,
and the directory `fsync` is what makes the rename itself durable. A `write`
that has only left the process is not on the disk.

The temp name is drawn from the operating system — 16 bytes read from
`/dev/urandom`, rendered hex, as `.tog-toolchain.toml.<hex>.tmp`. That is
the randomness source already in the tree (`src/sbom.rs:36-41`, the CycloneDX
`urn:uuid` v4), factored into one helper rather than added a second time, and
it reads identically on Linux and macOS. Process identity is deliberately not
the source. Pid-plus-sequence — the shape download temps use
(`src/fetch.rs:360-366`) — separates concurrent writers inside one machine,
which is all `src/fetch.rs` needs, but it has fixed points: a sequence
restarts at 0 in every process, and a pid is reused after wrap and starts from
the same small numbers in every PID namespace. So
`.tog-toolchain.toml.1.0.tmp` is the exact name the first write of a
containerized run picks, every run, on every machine; one leftover at that
name wedges every later run of that image permanently. A random name has no
fixed point to wedge, and it is one rule at every scale — a laptop, a CI
matrix, a build farm sharing a network filesystem — with no separate
collision case to reason about.

`O_EXCL` and `O_NOFOLLOW` keep their whole benefit: a symlink or any other
file at a name only this process chose still fails the create loudly instead
of being written through, in a fresh clone's very first sync as much as in an
update. A create that loses to an existing name retries on fresh randomness a
bounded number of times and then reports; it is never resolved by unlinking
what is in the way, because tog cannot know that file is its own.

A leftover temp is inert — never read, never an input, never a lock, and never
consulted for staleness; it is garbage the user (or a `.gitignore` rule) may
delete at any time. Tog unlinks its own temp on every exit path it
controls, success and error alike, and never scans for or deletes a temp it
did not create.

After dependency planning, on EVERY sync (including an existing-lock sync),
reopen the source inputs through the held root descriptor with `O_NOFOLLOW` and
recheck identity metadata and bytes before publishing the closure or
projection; a change aborts and leaves lock, closure, and projection untouched.

--frozen never modifies project inputs, tog-toolchain.toml, or the catalog
cache; it may realize store objects and write the projection after validation
succeeds; validation failure exits before any write. That sentence is
byte-identical in exactly two places — here and in CLI.md's "Planned (WP2
design ...)" section. It appears in neither CLI.md's help screen nor its
command grammar, and neither gains a `(planned:)` marker, because the help
screen is the spec for the bytes `tog --help` actually prints and the
grammar is the spec for what the parser actually accepts. A marker in either
would be a convention no other verb uses, an unimplemented flag advertised to
users, and one more thing to remember to delete the day WP2 lands. Design work
lives in the prose sections that say they are design work; the specs describe
what ships. The regression proving the boundary is
`tests/toolchain_lock.rs::frozen_validation_failure_precedes_all_writes`.
Frozen validation evaluates nothing at all: every reader below is
declarative-only, so the sandboxed probe described here is a planning-path
tool and never a validation one. `setup.py`-computed metadata and `mix.exs`
compatibility are therefore not frozen sources, exactly as the Gemfile's
`ruby` directive is not. Where the probe does run, on the ordinary planning
path, it is sandboxed: network denied, project read-only, and scratch-only
writes. The setup `BuildSpec` argv is
`["/bin/sh", "-c", "exec <build-env>/bin/python setup.py egg_info --egg-base
<scratch>/egg-info ><scratch>/egg-info.log 2>&1"]`, with the project root as
cwd and the build environment, CPython, and scratch declared as its roots
(`src/manifest.rs:162-178`). It is not `/bin/sh setup.py`.

The guarantee is therefore stated as a rule about reachability, not as a list
of functions not to call. **Treat every ecosystem's ordinary planning path as
an unsandboxed evaluator of project code, and give frozen toolchain-lock
validation no way to reach any of them.** The rule's scope is exactly the
phase it names, and what happens on either side of that phase is stated here
rather than left to inference. Validation reads its inputs, compares them to
the lock, and decides; it plans no dependencies, and a validation failure
exits before any evaluator runs at all. Once validation succeeds, `--frozen`
continues into ordinary sync, where dependency planning still delegates to
the native tools and those tools do evaluate project code: `plan_ruby`'s
Gate 1 (`src/ruby.rs:582-596`) evaluates the Gemfile on every call, lock
present or not. That is the delegated-resolver trust boundary this document
already accepts for dependencies, and the toolchain lock's whole purpose is
to stay off it — no toolchain version is ever learned from an evaluator.
That is the only form of the rule that stays true: counting today's
evaluators is the fragile version, and every count written so far has been
wrong. Round 7 named Elixir's plan gate (`src/elixir.rs:1097-1110`) as the
only one. Round 8 said two, adding Ruby — planning runs the store Ruby on a
helper that **evaluates the Gemfile** to check Gemfile/lock equivalence and
the `ruby` directive, through a `run_ruby` that is a plain `Command` with
neither sandbox nor network denial (`src/ruby.rs:311-317`,
`src/ruby.rs:333-352`, called at `src/ruby.rs:582-596`). Two was also wrong:
`plan_dotnet` shells out to `dotnet restore --use-lock-file` through
`run_dotnet` (`src/dotnet.rs:603-635`, `src/dotnet.rs:715-740`), another plain
`Command` in the project directory, and MSBuild evaluates the `.csproj` plus
any `Directory.Build.props`/`.targets` it finds, including `<Exec>` tasks
hooked to Restore. Ruby and Elixir each have a second such call site outside
the ranges already cited (`src/ruby.rs:560`, `src/elixir.rs:1089`). The count
is not the point and no count is recorded here. Because the rule is about
reachability rather than a catalogue, it also covers call sites that are not
planning at all: `tog add` and `tog update` run the store tool in the
project directory through `run_checked` (`src/ruby.rs:290-297`,
`src/elixir.rs:896-904`), and frozen invokes neither verb.

What frozen calls instead is named, owned, and tested like every other
guarantee in this design. `src/toolchain_input.rs`, owned by PR 3 below
exactly as `src/kernel/fsroot.rs` is, exposes one reader per ecosystem that returns
the toolchain request from declarative sources only — the `path`/`field` pairs
the precedence table lists — and nothing in it calls a planner. Its unit tests
assert per ecosystem that the reader spawns no process at all, which is a
property a test can check directly and a call graph cannot quietly drift past.
A Gemfile is a Ruby program — `ruby "3.3.4"` sits beside arbitrary code that
runs to produce it — so Ruby's reader takes `.ruby-version` and the Ruby entry
in `.tool-versions`, and frozen refuses rather than evaluate a Gemfile to
learn a version. That treatment is uniform rather than a Ruby special case:
Python's reader takes `.python-version` and a `requires-python` declared in
`pyproject.toml`, and Elixir's takes the OTP and Elixir entries in
`.tool-versions`. A project whose only statement of its version is computed —
`setup.py` metadata, `mix.exs`, a Gemfile directive — fails frozen closed with
a message naming the declarative file to add. No reader has an evaluating
fallback, so there is no per-ecosystem exception to remember and the
`path`/`field` rows every input requires are always real files and real
fields. The end-to-end regression is a frozen run against a project
whose Gemfile writes a marker file when evaluated: validation completes and
the marker does not exist.

### Lifecycle and concurrency

On the first writable sync with no lock, selection runs against the
shipped catalog, stderr names the selected runtimes and the created
`tog-toolchain.toml`, and the file is published by the shared publication
rule above — descriptor-relative `O_EXCL`/`O_NOFOLLOW` temp in the held project
root, flushed, then renamed without following symlinks; the committed file
remains for review.

The lock gate runs before dependency planning. Missing or stale under
`--frozen`, strict policy, or a read-only project is an error naming `tog
update --toolchain [<ecosystem>]`, and ordinary sync also refuses stale locks.
Permissive mode cannot change a runtime silently: that is a correctness error,
not a hidden exception; other gaps still record one (`src/policy.rs:187-204`).

Writers take the per-project lock exclusively around read/compare/rename.
Byte-identical candidates keep the first file and let the second sync succeed
as a cache hit; different candidates leave the existing file, discard the
loser, and fail naming both selections, inputs, and `tog update
--toolchain`. Ordinary sync creates a lock when there is none but never
rewrites one; only `tog update --toolchain` replaces an existing lock.
That rule is per file, and the per-ecosystem case follows from it: a lock with
no section for an ecosystem newly present in the project — `[toolchain.python]`
committed, then a `package.json` appears — is stale, not absent, so ordinary
sync refuses and names `tog update --toolchain`, which adds the section.

`tog update --toolchain` updates every ecosystem present in the project —
present as source discovery finds it, not as the lock's existing sections list
it, which is how a newly added ecosystem gains one — or only the named one; it
is separate from dependency update and cannot take package names. It
re-reads sources, chooses the release selection describes below (the
catalog's default when the sources admit it, else the newest compatible
stable/LTS release), verifies every platform row, writes one lock
atomically, then runs ordinary sync; it never updates a dependency lock.
`--frozen` instead validates the committed lock with no catalog fallback and no
resolver-generated dependency-lock write, exiting before realization on a
missing, stale, or unresolvable input.

### Selection sources and precedence

Source discovery is explicit rather than an abstract "read the ecosystem" step.

It is also **anchored at the project root, not at the current directory.** The
root is the one tog already resolves — the nearest manifest/workspace root
walking up from cwd — and it is where `tog-toolchain.toml` sits once there
is one, so the anchor is defined identically before the first lock exists and
after, with no separate rule for the creating sync. The table below describes
where each ecosystem's own tools look, which is cwd-relative for most of them;
tog's toolchain discovery starts at that root instead, so the consulted
path list is a property of the project and every developer, every CI job, and
every subdirectory produces the same list, the same lock, and the same
staleness verdict. A cwd-relative walk would make `tog status` answer differently
depending on which directory the person was standing in, which is not a
property a committed lock can have. The cost is real and must be recorded in
`docs/human/LIMITATIONS.md` when the lock ships: a toolchain source file in a subdirectory — `web/.node-version`
under a root-level lock — is not a toolchain source for tog, though uv or
`nvm` would honor it. One toolchain per lock root is the rule; per-subproject
toolchains would need per-subproject sections and are not in this design.


| ecosystem | native tools walk from | walk boundary | source precedence (tog reads these from the lock root) | compatibility intersection and conflict |
|---|---|---|---|---|
| Python | cwd | parents through the uv project/workspace root; [uv documents this walk](https://docs.astral.sh/uv/reference/cli/) | `.python-version`, then a `requires-python` declared in `pyproject.toml`, including Poetry's `tool.poetry.dependencies.python`; `setup.py`-computed metadata is deliberately not a source, because reading it means running a build hook | use the supported request grammar below; intersect with metadata; current code parses at `src/pyselect.rs:309-362` but reads one supplied directory at `src/pyselect.rs:368-404` |
| Node | cwd | nearest package/workspace root | exact `.node-version`, then `engines.node` | intersect exact/range; empty intersection or conflicting same-level declarations is a hard error; current code only has platform rows (`src/npm.rs:114-146`) |
| Cargo | cwd | Cargo workspace root | nearest `rust-toolchain`, then `rust-toolchain.toml`, then shipped default | channel, targets, and supported components must intersect the catalog; an unsupported or conflicting request is a hard error; current nearest-file walk is `src/cargo.rs:246-264` |
| Go | module/project root | no workspace expansion; an ancestor `go.work` is refused | `go` is the minimum; non-`default` `toolchain goX.Y.Z` is exact; absent or `toolchain default` means the default when compatible, else newest compatible, once | exact toolchain must be a catalog release and satisfy the minimum; otherwise fail closed; platform filtering is `go_pins` (`src/golang.rs:72-83`) and directive parsing is `src/golang.rs:243-269` |
| Ruby | cwd | parents through the project root | exact `.ruby-version`, then a Ruby entry in `.tool-versions`; the Gemfile's `ruby` directive is deliberately not a source, because reading it means evaluating a Ruby program | intersect exact declarations; disagreement is a hard error; current code has only platform rows (`src/ruby.rs:47-67`) |
| Elixir | cwd | parents through the Mix workspace root | exact `.tool-versions` OTP/Elixir; `mix.exs` compatibility is deliberately not a source, because reading it means evaluating an Elixir program | intersect OTP/Elixir requirements and OTP-qualified Hex/rebar rows; empty intersection is a hard error; current plan checks `mix.exs`/`mix.lock` at `src/elixir.rs:1075-1110` and pins OTP at `src/elixir.rs:26-31` |
| .NET | project directory | inspect ancestors only to reject inherited SDK inputs | exact project `global.json` with `rollForward = "disable"` | no roll-forward or second source; a mismatch is a hard error; current ancestor rejection and exact gate are `src/dotnet.rs:542-593` |

Python requests use a supported subset of uv's grammar: exact `X.Y.Z`, minor
`X.Y` (the default if it is on that minor, else the newest compatible catalog
release, once, then locked), or a PEP 440-style specifier set restricted to
`>=`, `<`, `==`, `~=`, and `!=`, comma-joined (the default if it satisfies,
else the newest satisfying release, once, then locked). An explicit CPython prefix is a
supported spelling of the same request, not a second implementation:
`python3.12`, `cpython-3.12`, `cpython@3.12` and their `Python`/`CPython`
casings are stripped today (`src/pyselect.rs:334-341`), and the unit test
`python_version_formats_and_unsupported_interpreters` asserts they parse
(`src/pyselect.rs:718-753`); the lock keeps them and records the canonical
`X.Y[.Z]` in `value`. The refusals stay exactly where they are today
(`src/pyselect.rs:321-333`): non-CPython implementations (`pypy`, miniconda),
variants (`-dev`, a trailing `t`, free-threaded) and `system` fail as
`unsupported Python interpreter request`, while paths, executables, and other
free-form text that is neither a version nor a supported specifier fail as
`invalid .python-version request`. Either message's next step is to put an
`X.Y`, `X.Y.Z`, or supported specifier in `.python-version`, then run
`tog update --toolchain`.

The lock then supplies the exact artifact. A matching source request is stable;
a changed source stops sync with both values and `tog update --toolchain`.
An exact request with no matching catalog row is a hard error in every
ecosystem, a range is selected once at lock creation or explicit update and
never reselected on sync, and dependency lockfiles stay delegated to native
tools. Every sentence in this section describes choosing a version, which
happens only at lock creation and `tog update --toolchain`; a sync that
honors an existing lock runs none of it and reads no catalog. The exact-selection fixes landed as two PRs — CPython
(`src/pyselect.rs:170-188`, `src/python.rs:87-93`) in #21
`wp2/python-exact-selection`, and Go (`src/golang.rs:140-157`) in #22
`wp2/go-selected-version` — which together are ordered item 0 below.
For Go the original resolver treated non-default `toolchain` as a lower bound;
the landed exact-selection fix must continue to fail closed when exact
`toolchain goX.Y.Z` is absent, while `default`/absent selects newest once.
Regression: with a newer row present, `go 1.22` plus exact `toolchain
go1.24.2` still locks 1.24.2, never 1.25.

Current selectors filter candidates by the passed platform: Python while
collecting pins (`src/pyselect.rs:129-136`), Go in `go_pins`
(`src/golang.rs:72-83`), npm by taking the platform's Node row
(`src/npm.rs:767-770`). The lock selector is different: with `C_p` the complete
releases for platform `p`, it selects only from the intersection of `C_p` over
every `p` in `Platform::ALL` (`src/platform.rs:83-86`) — complete meaning each
required component has one valid row per platform, embedded ones via a parent.

Each ecosystem declares a primary component — `node`, `cpython`, `go`; BEAM
uses the `(otp, elixir)` pair compared lexicographically, OTP first and Elixir
second. Exact/range matching and ordering use that primary version, never
`release`. The global order is primary version descending, highest explicit
`revision` (otherwise newest catalog order), then the provider/build/recipe
tuple, canonical artifact tuple, and `bundle_id`; `release` keys are unique and
duplicates are catalog errors. Channel is deliberately not an ordering key:
two bundles that tie on primary version are the same upstream release and so
the same channel, so an LTS-before-stable tie-break could never fire. Channel
is an admission property instead — only stable/LTS builds enter the catalog,
and a range takes the newest admitted release.
Exact requests filter by primary version and ranges take the first satisfying
candidate, so recipe revisions of one upstream version coexist. One rule
comes first: a catalog names its **default** release (what a project with no
pin gets), and whenever the request admits the default, the default wins.
Availability and default are separate facts (#187): a catalog can list every
patch of every maintained line without moving any unpinned or range-pinned
project, and the default moves only by an explicit, reviewed change. The selector
never uses the host: an asymmetric catalog (Darwin-only A, Linux-only B,
complete C) chooses C and produces byte-identical locks from both platform
values, and tests compare those bytes, not only the selected version.

### Carrying the runtime through every operation

The closure records one selected toolchain object reference per ecosystem,
alongside the lock digest and source-input rows. Python records environment,
version, and inputs (`src/project.rs:612-637`); the other closures record
direct refs and plans (`src/cargo.rs:1121-1129`, `src/golang.rs:907-915`,
`src/ruby.rs:852-860`, `src/elixir.rs:1428-1439`, `src/dotnet.rs:995-1003`).
Node records environment/version/projection and inputs
(`src/npm.rs:2418-2443`); add direct runtime refs and normalize all seven.

`tog run` resolves every runtime through that closure id using
`project::closure_object` (`src/project.rs:197-234`). Today Node calls the
global platform pin after sync (`src/main.rs:1404-1412`) while Cargo/Go use
closure ids (`src/main.rs:1416-1433`); later refreshes must not alter a run.

The cached `x` key becomes `x/3`: store root, ecosystem, package request,
platform, primary runtime version, selected `bundle_id`, and runtime object id.
The store root stays in the key exactly as `x/2` hashes it today
(`src/xrun.rs:326-334`), because every other input is store-independent —
`cpython_identity`/`node_identity` take no store root (`src/python.rs:131-152`,
`src/npm.rs:149-158`), unlike the env identities (`src/project.rs:279-282`,
`src/npm.rs:1241-1244`). Dropping it would make `TOG_STORE=/a tog x
ruff` and `TOG_STORE=/b tog x ruff` share one `~/.tog/x/`
directory, and the second store would fail in `check_cached_projection` with
`cached environment object is missing or outside the active store; run the
command again` (`src/xrun.rs:269-273`) — a permanent failure that re-running
cannot clear, where today the key differs and the miss is clean. Because
`bundle_id` covers every component and artifact row, a changed uv, recipe, or
any other bundle component yields a fresh x environment even when the runtime
object's id is unchanged. Current `x/2` omits runtime identity
(`src/xrun.rs:325-340`), and Node x also calls global `ensure_node_for`
(`src/xrun.rs:375`, `src/xrun.rs:456-505`). New `x/3` dirs never reuse `x/2`;
old ones remain GC roots until collected. Project `x` reads the lock and
outside-project `x` uses shipped selection; both key on the store root, bundle,
and runtime ids.

The lock digest, bundle id, runtime id, and dependency plan are written before
projection; unchanged rows resolve the old object, while any bundle-component
change through `update --toolchain` creates a new lock and forces a fresh
native plan and closure. `status` compares the committed lock digest and then
re-derives every input row from the lock root — including the rows recorded
`absent`, which is how it notices a newly added higher-precedence file — using
the recorded `sha256` to skip re-parsing files whose bytes are untouched, and
compares presence and `value` by the one staleness rule above, so a digest
mismatch alone never reports stale, before reporting `toolchain lock
stale/missing` (`src/inspect.rs:336-373`, `src/inspect.rs:480-572`). Without
that re-parse `status` would exit 1 after every `tog add` that rewrites a
multi-purpose manifest, breaking its documented CI gate; without re-deriving
the absent rows it would exit 0 while tog and the rest of the repo
disagreed about the runtime.

### Identity, migration, and GC

Writing the lock does not write or mutate a store object. Rows map to the
existing identity mapping for the selected recipe and verified artifact
hashes; a recipe change creates a new identity input rather than changing an
old object's semantics. The existing Darwin identity tests, including the
CPython goldens (`src/python.rs:271-295`) and Rust golden
(`src/cargo.rs:1293-1301`), remain byte-identical.

Legacy seeding is an evidence conversion, not a reconstruction: it validates
every closure object id/path through the active store, then reads identity
metadata; recorded paths never authorize a read. Old closures prove only:

| ecosystem | recoverable from verified closure/object | incomplete fields that refuse seeding |
|---|---|---|
| Python | CPython version and artifact/platform from the env identity; the plan and, when present, input records | the current closure has no separate uv reference, so a complete companion row needs an unambiguous shipped mapping |
| Node | Node version and artifact/platform from the env identity; bundled npm/node-gyp are inside that artifact | embedded component metadata or source inputs absent from the old closure |
| Rust | rust object, vendor object, lock digest, and `CargoPlan`'s `rust_version`, crates, and members (`src/cargo.rs:402-406`, `src/cargo.rs:1121-1129`) | channel, requested components, and targets are not recorded; never claim those fields can be recovered |
| Go | Go object, module-cache object, `go_version` in the plan, and go.sum digest (`src/golang.rs:907-915`) | the consulted go.mod directives and their old snapshot are absent |
| Ruby | Ruby/gems objects, versions, and gem plan (`src/ruby.rs:852-860`) | an old `.ruby-version` or compatibility input not recorded in the closure |
| Elixir | BEAM object and the plan's OTP, Elixir, Hex, and rebar metadata (`src/elixir.rs:1428-1439`) | mix.exs compatibility evidence and any missing source snapshot |
| .NET | SDK object and SDK version in the plan (`src/dotnet.rs:995-1003`) | global.json evidence or other compatibility fields not recorded |

Seeding succeeds only if every required lock field, including its source
snapshot and both platform rows, is proved by that evidence or by a unique
shipped-table mapping. Otherwise the mapping is unrecoverable and sync refuses
with `tog update --toolchain`; it never guesses from the current default,
and a same-platform closure is not foreign-platform evidence. With an existing
lock, realize the current platform from its row.

If a recorded input now differs, the old closure is not a migration authority:
keep the old lock and closure, report both values, and require `tog update
--toolchain` to snapshot the changed source and write a new lock. Legacy
closures with no snapshot for a consulted field take the same refusal. This
preserves rollback and stops changed source pairing with old dependencies.
Closure object refs keep toolchains alive through the existing root/GC walk;
the lock itself is not a GC root.

### Interaction with WP3

The lock needs provider build, component recipe, URL, and a verified,
algorithm-qualified digest for both triples. Sync downloads only the current
row and never rewrites the other.
Until WP3, the shipped catalog is the generated documents embedded in the
binary (`src/tailors/<eco>/catalog.toml`,
`src/kernel/provider/cpython.catalog.toml`; Rust's rows are still the table
in `src/kernel/provider/rust.rs`), so locks are writable offline.
`src/kernel/platform.rs` is only the supported-platform enumeration. WP3 must
retain the rows existing locks need, and an unrelated refresh cannot alter an
Identity or a lock.

The documents are WP3's starting point, not a stopgap. Their schema
(`src/kernel/toolchain/document.rs`: release key, optional revision,
components, one artifact row per platform, and a separate `default`) is the
shape a refreshed snapshot takes, and the embedded documents are the
"shipped catalog only" mode. `tools/catalog.py` holds, per ecosystem, the
upstream reading WP3's providers need: which listing names the releases,
which lines are maintained, which checksum is authoritative and which second
source cross-checks it (Node's `SHASUMS256.txt` is also verified against
Node's release keys). The generator's rules are the ones a refresh must keep:
append-only, rows already shipped re-verified byte for byte, the default
moved only explicitly, and every skipped release reported.

### Acceptance and ordered implementation

Acceptance is: different catalog snapshots replay the same lock in two stores,
including a snapshot that no longer contains the lock's `release` key at all,
which is the upgrade case and must succeed rather than report stale; a no-pin
project writes it on writable sync and refuses under `--frozen`; exact
selection, asymmetric-catalog, byte-identical BEAM, Linux-to-Mac, and
`file://`/unauthorized-endpoint/hash/link rejection fixtures all pass; a source
file appearing at a path recorded `absent` reports stale, and one appearing at
a path with no row at all is impossible because every consulted path has a row;
frozen validation against a project whose Gemfile writes a marker when
evaluated completes with no marker, and every `src/toolchain_input.rs` reader spawns no
process; and the project-side `src/kernel/fsroot.rs` refusals all
fail closed — a symlinked `tog-toolchain.toml`, a symlinked input file, a
symlinked ancestor directory of either, and an occupied temp name. The shipped behavior of that list is
described in `docs/human/ARCHITECTURE.md` "Toolchain lock"; what stays here
is the reasoning behind it.

0. **Exact selection fixes (landed as two PRs)** — #21 `wp2/python-exact-selection` (`src/pyselect.rs`, `src/python.rs`) and #22 `wp2/go-selected-version` (`src/golang.rs`), each with its own unit tests: exact patches, duplicate rows, selected-Go realization, unchanged defaults, Darwin goldens.
1. **Shipped-table adapter and source selection (landed)** — pin modules, `src/platform.rs`, typed source-policy interface with configurable endpoint defaults, selector tests: complete bundles, matrix intersections, carrying the existing verified digests (including the sha512s .NET/Hex/rebar already use) into catalog rows, and legacy seeding (evidence-based success plus the refusal when evidence is missing). No lock-byte or replay tests before the format exists.
2. **Secure archive extractor (landed)** — `src/archive.rs` and unit tests for absolute paths, `..`, hard links, special files, symlink escape, and an outside sentinel under GNU tar and (asymmetric until the Mac gate) bsdtar.
3. **Lock core (landed 2026-09-21)** — parser/writer plus `src/cli.rs`, `src/main.rs`, and project input handling: canonical bytes as defined above, the consulted-path input list with its absent rows, and the concurrent writer/reader lock. This PR also owns `src/toolchain_input.rs`, the per-ecosystem declarative readers, with a unit test per ecosystem asserting the reader spawns no process. It extends `src/kernel/fsroot.rs` for lock/input-specific rules (`openat`/`O_NOFOLLOW` walk, `O_EXCL` create on an `/dev/urandom` name, file `fsync`, `renameat`, directory `fsync`), and moves `src/sbom.rs`'s `/dev/urandom` read into the shared helper it calls rather than adding a second randomness path. Unit tests refuse a symlinked `tog-toolchain.toml`, a symlinked input file, a symlinked ancestor directory, and an occupied temp name; `fs::read`/`fs::write`/`fs::rename` do not pass them. Activation stays off; stale/frozen/replay/exit-status tests wait for it.
4. **Runtime propagation (landed 2026-09-21)** — `src/main.rs`, `src/xrun.rs`, `src/inspect.rs`, `src/project.rs`, and closure writers: closure-selected runtimes, refresh isolation, old-`x/2` non-reuse; this permits activation.
5. **Activation and update (landed 2026-09-21)** — `src/cli.rs`, `src/main.rs`, lock core, integration tests: update, two-store replay including the dropped-`release` upgrade replay, no-pin creation, stale/frozen refusal (with `frozen_validation_failure_precedes_all_writes` and the Gemfile-marker regression), added-higher-precedence-source staleness, unchanged dependency locks, foreign-platform refusal, exact statuses, Linux/Mac diff.


### Implementation status and remaining PRs

**Objective.** A committed toolchain lock outside the ignored `.tog/`
records, per ecosystem, the exact provider build, components, and per-platform
algorithm-qualified digests. Honoring a lock chooses no new version and consults no refreshed catalog.
It still validates local source/trust policy and, once WP3 enables publisher
authentication, the required proof. A catalog or binary upgrade alone cannot
change the locked bytes; explicit revocation or tightened policy can refuse
their use without rewriting the lock.

**Prerequisites.** None outstanding. The old plan held PR 3 (the lock core)
until GC safety Packages C and D had rewritten `write_closure` and its
callers; both have shipped. PR 1 below landed on 2026-09-18
(`src/kernel/toolchain/`, described in `docs/human/ARCHITECTURE.md`
"Toolchain lock"); its entry is kept so the numbering the later PRs cite
stays intact.

**Design.** "The contract" above is the design after ten adversarial rounds.
When an implementation PR changes the contract, it updates the contract here
in the same PR, and moves the shipped part into `docs/human/ARCHITECTURE.md`. The design's load-bearing conclusions, in one paragraph each,
so this file does not drift from it:

- **The shipped catalog is off the reproducibility path.** A lock row carries
  version, URL, algorithm-qualified digest, and recipe id — everything
  realization needs to select the artifact. The catalog is consulted only
  when *choosing* a version, at lock creation and `update --toolchain`.
  Retrieval checks the digest and the effective configured endpoint policy,
  including every redirect. Shipped upstream endpoints are defaults, not an
  unchangeable allowlist. Recipe ids remain append-only. Authentication is a
  separate predicate from matching a lock-supplied checksum; WP3 adds that
  predicate and its locally replayable proof.
- **Publication uses OS randomness and real durability.** A `/dev/urandom`
  temp name (the source already in `src/sbom.rs`, factored into one shared
  helper), `O_EXCL`, `fsync` the file, `renameat`, `fsync` the directory.
  Pid-plus-sequence was dropped because it has fixed points (a sequence
  restarts at 0; PID namespaces reissue small pids), so one leftover temp
  would wedge every later run of a container image.
- **Staleness compares the whole consulted path list, including absence.** A
  source appearing where the lock recorded `absent` is stale. Discovery is
  anchored at the project root, never at cwd. Only a re-parsed `value`
  decides; a digest mismatch alone is never stale, so `tog add` rewriting
  a multi-purpose manifest cannot wedge the lock.
- **`bundle_id` and the lock's canonical bytes are defined** as
  length-prefixed records with a leading serialization-version record.
- **Frozen toolchain-lock validation evaluates no project code.** The rule is
  scoped to *validation*: a passing frozen run then continues into ordinary
  dependency planning, which does delegate to native tools that evaluate
  project code — the delegated-resolver boundary the design already accepts.
  Every toolchain-input reader is declarative-only and lives in a named module
  `src/toolchain_input.rs`, with a per-ecosystem test that the reader spawns
  no process. A project whose only statement of its version is *computed*
  (`setup.py` metadata, `mix.exs` compatibility) fails frozen closed with a
  message naming the declarative file to add.

**Remaining ordered PRs** (numbering matches the ordered list at the end of the contract):

**PR 1 — shipped-table adapter and source selection (landed 2026-09-18).**
- *Files:* `src/python.rs:22-85`, `src/npm.rs:122-135`, `src/cargo.rs:25-68`,
  `src/golang.rs:32-45`, `src/ruby.rs`, `src/elixir.rs`, `src/dotnet.rs`,
  `src/platform.rs:83-86`, plus a new selector module.
- *Data model:* the compiled pin rows become catalog rows carrying version,
  URL, algorithm-qualified digest (carrying the existing sha512 rows .NET/Hex/
  rebar already use), recipe id, and platform.
- *Behaviour:* selection uses the **intersection of complete releases across
  both supported platforms**, so asymmetric catalogs produce identical lock
  bytes from either platform value.
- *Also in this PR:* define a typed source-policy interface with shipped
  endpoint defaults and explicit publisher/endpoint/credential-reference
  fields. WP3 supplies protected policy loading and authentication; WP2 must
  not embed an append-only host list into lock validity. Never put secrets in
  catalog rows or locks. Provider-specific credentials are not needed for
  this interface/fixture work.
- *Also in this PR:* legacy seeding — evidence-based success plus the refusal
  when evidence is missing, per the per-ecosystem table at
  the "Selection sources and precedence" section of the contract.
- *Not in this PR:* lock-byte or replay tests; the format does not exist yet.
- *Today's gap this fixes:* Node, Ruby and Elixir select nothing and .NET
  accepts one fixed SDK (`npm::node_pin`, `src/npm.rs:137`; `ruby::ruby_pin`,
  `src/ruby.rs:57`; `dotnet::SDK_VERSION`, `src/dotnet.rs:27`, enforced at
  `src/dotnet.rs:132` and `src/dotnet.rs:338`).

**PR 3 — lock core (landed 2026-09-21).**
- *Files:* new `src/toolchain_input.rs` (per-ecosystem declarative readers),
  extend `src/kernel/fsroot.rs` (`ProjectRoot`: `openat`/`O_NOFOLLOW`
  walk, `O_EXCL` create on a `/dev/urandom` name, file `fsync`, `renameat`,
  directory `fsync`), plus `src/cli.rs`, `src/main.rs`, project input
  handling; move `src/sbom.rs`'s `/dev/urandom` read into the shared helper
  rather than adding a second randomness path.
- *Tests:* one per ecosystem asserting the reader spawns no process; `fsroot`
  refusals for a symlinked `tog-toolchain.toml`, a symlinked input file, a
  symlinked ancestor directory, and an occupied temp name — and a test that
  `fs::read`/`fs::write`/`fs::rename` do **not** pass those refusals.
- *Concurrency integration:* the toolchain-input lock is distinct from C's
  project transaction lock. Acquire activity → x-root (if any) → toolchain
  input lock → project transaction → cache → publication. Do not repurpose a
  shared input lock as an exclusive publication lock. Pure frozen input
  validation must complete before any store bootstrap or automatic metadata
  maintenance writes; preserve the frozen no-writes regression.
- *As built:* `primary` is written as a bare string when an ecosystem has
  one primary component and as a TOML array for the BEAM pair, and the
  parser accepts either.

**PR 4 — runtime propagation (landed 2026-09-21).**
- *Files:* `src/main.rs:1598` (Node `run` takes the global pin via
  `npm::ensure_node_for`; likewise `src/main.rs:1008` and `src/xrun.rs:1546`,
  `src/xrun.rs:1827`), `src/xrun.rs:98` and `src/xrun.rs:1582` (the `x/2`
  cache keys omit runtime identity — the design's `x/3` key is
  store-root-scoped and bundle-complete), `src/inspect.rs` (`status` must compare toolchain inputs),
  `src/project.rs` and every closure writer (closure-selected runtimes,
  refresh isolation, old-`x/2` non-reuse).
- *Security requirement:* a catalog refresh must never pair old dependencies
  with a new runtime silently.

**PR 5 — activation and `update --toolchain` (landed 2026-09-21).**
- *Files:* `src/cli.rs`, `src/main.rs`, the lock core, integration tests.
- *Behaviour:* first writable sync of a project with no pin creates the lock
  visibly and atomically; `--frozen` or strict policy refuses a missing or
  stale lock; concurrent writers must agree; upgrades are only
  `tog update --toolchain`, never a side effect.
- *Named tests from the design:* two-store replay including the dropped-
  `release` upgrade replay; no-pin creation; stale/frozen refusal with
  `frozen_validation_failure_precedes_all_writes` and the Gemfile-marker
  regression; added-higher-precedence-source staleness; unchanged dependency
  locks; foreign-platform refusal; exact statuses; the Linux/Mac lock diff.

**Migration and compatibility.** Legacy closures seed a lock only from proved
evidence; an unrecoverable mapping refuses with `tog update --toolchain`
and never guesses from the current default. A same-platform closure is not
foreign-platform evidence. Writing a lock does not write or mutate a store
object; darwin goldens stay byte-identical.

**Linux verification.** `cargo fmt --check`, `cargo test`, and the selection
`--ignored` tests (`tests/python_select.rs`, `tests/go_e2e.rs`) with a
disposable store and `TOG_SANDBOX_TESTS=required`.

**Mac before merge.** The lock carries a hash per platform, so a lock written
on Linux must sync on the Mac without rewriting itself, and vice versa. Sync
the same project on both machines and diff the lock file (must be byte
identical) and `tog status` (both "synced"). Run `cargo test` and the
selection `--ignored` tests on the Mac.

**Independent review.** The design has had 10 rounds; round 10's fixes are
unreviewed. Every implementation PR needs its own round.

**Completion criteria.** Ordered items 0–5 and the extractor follow-up below are merged and
the acceptance list at the end of the contract passes on Linux, as of 2026-09-21;
`LIMITATIONS.md` has lost the "Node/Ruby/Elixir select nothing" and "one fixed
.NET SDK" rows. **The two-machine lock diff is the one item outstanding:** a
lock written on Linux must sync on an arm64 Mac without rewriting itself, with
both `tog status` answers identical. It is proven by test, not by two machines.

---

## 2. Release catalog and publisher trust (WP3)

Needs WP2.

**Objective.** One binary discovers a newly published upstream release without
a code change.

**Prerequisites.** WP2 PRs 1, 3, 4, 5. Default versions do not move until WP2
has merged.

**Scope.**
- **Catalog, not just a release list.** Per ecosystem: usable distributions
  (python-build-standalone builds, nodejs.org, static.rust-lang, go.dev,
  portable-ruby, erlef otp_builds plus tog-toolchains for Linux OTP,
  Microsoft release metadata), provider build revisions, platform requirements
  (glibc floor), extraction recipes, and companion tools that must move
  together: uv, bundled npm, Bundler, OTP-qualified Hex and rebar3,
  Elixir-per-OTP compatibility.
- **Trust is a configured list, not a compiled-in constant** (owner direction,
  2026-09-09). "Which publishers count as real" must be data the user or the
  company sets, because an enterprise mirrors its toolchains internally and
  will want tog pulling from its own repository, signed by its own key.
  Do not hardcode a fixed set of upstream publishers and bolt private
  registries on later; the internal publisher is a first-class case from the
  first PR. See the trust-configuration rules below: this shares the source
  policy mechanism with WP5 private-registry work.
  Keep endpoint permission, publisher authentication, and credential handling
  distinct within that mechanism; a registry login does not prove authorship.
- **Refresh and trust protocol.** Immutable catalog snapshots in the store;
  atomic refresh with timeout and last-good fallback; historical retention so
  old locks stay realizable; trusted publisher keys with rotation and
  revocation; an invalid signature is a hard failure, never a warning. Two
  distinct modes: `--offline` (no network at all) and "shipped catalog only"
  (the tables compiled into this binary, for zero-surprise installs).
- **Rebuild the Linux OTP artifact** on an older declared baseline with static
  OpenSSL and a runtime check on the supported distros. Static OpenSSL alone
  does not lower the glibc floor (see the Elixir rows and the shared-store note in
  `docs/human/LIMITATIONS.md`).

**Security and failure modes.** A tampered catalog is rejected. A transport
failure or timeout
may fall back to a still-valid last-good snapshot and says so. A present but
invalid signature, revoked signer, malformed signed payload, or detected
rollback fails hard; it must not enter the network-failure fallback path.
Offline replay with cached artifacts and required proof succeeds with the
network denied. TOFU sources are named as TOFU in
the catalog entry and in `LIMITATIONS.md` (tog is TOFU today for
python-build-standalone — the pins carry checksums verified at pin time, not
signatures, `src/python.rs:10-13`).

**What this repository does *not* contain.** No publisher keys, no captured
signature, no attestation bundle, and no verification code. **Every claim
about which upstream publishes what signing material is unverified.** The plan
therefore starts WP3 with an evidence step, not with an implementation.

**Trust configuration rules.** These follow the existing policy model
(`src/policy.rs`), which tightens through ancestors and never loosens silently:

- The trusted-publisher set is **configuration**, expressed through shared
  project/home/protected-machine policy loading. **WP3 PR 1 owns the protected
  loading prerequisite**; WP5 later extends it. It is not a constant in
  `src/*.rs`. The shipped upstream publishers are the *default
  contents* of that list, not a privileged category.
- **Adding a publisher is an explicit, recorded configuration change at an
  authorized user/machine scope.** Lower-precedence/project layers may only
  intersect/restrict an allowed set, not union in a new publisher. A company
  may authorize only its own key. Trusted use of an explicitly authorized
  publisher is not automatically an exception that strict mode then rejects;
  log the configuration change and retain provenance separately from package
  verification exceptions.
- **A project can never widen the set beyond what home or machine policy
  allows.** A company can pin the set to its own internal publisher and a
  checked-out repo cannot add to it. WP3 PR 1 owns unconditional protected
  machine-policy loading; environment overrides cannot suppress it.
- **An invalid signature is a hard failure under every configuration.** Making
  the publisher list configurable must not create a spelling of "trust
  anything"; an empty or unparseable list fails closed.
- **Each catalog row records which publisher vouched for it,** so
  `tog ls`, `tog sbom`, and an audit can answer "where did this
  toolchain come from and who signed it" without re-fetching.
- **Locked replay and cache hits recheck current policy.** A checksum copied
  into an attacker-editable lock is integrity data, not proof that an allowed
  publisher signed it. Authenticated rows carry/reference a signed payload
  binding artifact digests, versions, platform/components, and recipe/bundle
  identity. Cache the verifiable proof with immutable provenance; offline
  replay needs that proof locally as well as the artifacts. Refuse missing
  proof under authenticated policy, including old WP2-only locks; do not
  silently relabel them signed or rewrite their locked bytes.
- A revoked/removed key or endpoint can intentionally make an old lock
  unusable. Report a policy/trust refusal distinctly from stale project inputs.
  Catalog refresh alone never changes the result for locked artifact bytes.
  Define expiry/rollback and offline revocation freshness in the owner-approved
  key policy before activation; an unreachable revocation service is not
  permission to bypass the configured freshness requirement.
- Keep three typed concepts: permitted endpoints (including redirects),
  publisher trust/proof, and credential references scoped to endpoint/audience.
  Never forward credentials to a different redirect origin by default. A
  successful private-registry login is not artifact signature verification.
  Implement an internal-publisher fixture with a test key and authenticated
  local test endpoint; real production credentials are not needed for that.


**Ordered PRs.**

**PR 0 — provider evidence spike (docs + fixtures only).** For each of the
seven providers, fetch and record: the exact URL of any checksum file,
signature, or attestation; its format; the key or trust root it chains to; and
whether it covers the artifact tog actually downloads. Commit the captured
material as test fixtures under `tests/fixtures/catalog/<provider>/` and a
table in this section. Providers with nothing verifiable are recorded as
TOFU by construction with a `LIMITATIONS.md` row. **No provider is described
as "signed" anywhere in the repo until this PR lands its evidence.**

**PR 1 — shared trust foundation and one authenticated provider.** Start with
unconditional protected policy loading, typed endpoint/trust/credential
configuration, effective-set intersection, and a fixture internal publisher.
Then implement catalog rows, signed-payload verification, refresh, snapshot
storage, valid last-good fallback, and the two offline modes. Choose a provider
with evidence-backed authentication from PR 0; checksum-only/TOFU support does
not satisfy this milestone. If no production provider qualifies yet, finish
and test the machinery with the fixture publisher and leave live-provider
activation explicitly open; do not invent a trust root. *Recommended provider below.*

**PRs 2–7 — one provider each**, reusing PR 1's machinery.

**PR 8 — Linux OTP artifact rebuild** on the older baseline, with the runtime
distro check.

**Acceptance.** One binary discovers a newly published upstream release
without a code change; a transport failure falls back to a still-valid
last-good snapshot and says so; offline replay with cached artifacts and proof
succeeds with the network denied; tampered/invalidly signed catalogs fail
without fallback. Also test: internal publisher, project attempts to widen
machine policy, environment attempts to suppress machine policy, revoked key
on a cache hit and locked replay, missing offline proof, unauthorized redirect,
credential non-forwarding, expired snapshot, and rollback rejection. Record
TOFU evidence honestly; it cannot satisfy authenticated-provider acceptance.

**Mac before merge.** Every catalog provider must produce darwin-arm64 rows,
and the Mac must realize a toolchain from the catalog rather than the
compiled-in table (verify with `-v` that the catalog was the source). Offline
replay is run on the Mac with the network off. `--offline` and "shipped
catalog only" are tested on both.

**Completion criteria.** PR 0's evidence table exists; PR 1's provider passes
all four acceptance gates on Linux and the Mac; each later provider PR repeats
them; `LIMITATIONS.md` carries one honest row per TOFU source.

#### Recommended decision (owner approval required for the trust root)

- **Do PR 0 before choosing the first provider.** Choosing on assumed
  signature availability is exactly the mistake this plan must not make.
- **Provisional first provider: Go or Rust**, decided by PR 0's evidence —
  both have the smallest surface and already have toolchain-file resolution
  (`go.mod` `toolchain`, `rust-toolchain.toml`). Pick whichever PR 0 shows has
  verifiable signing material covering the exact artifact tog downloads.
- **Trusted key management needs the owner.** Where keys live, who rotates
  them, and what revocation means operationally are policy decisions, not
  implementation details. *Do not invent a key policy.* The owner's standing
  direction (2026-09-09) is that the mechanism must accommodate a company's own
  internal publisher, so design the storage and rotation story for "one
  enterprise key alongside or instead of the upstream ones" from the start,
  rather than for upstream publishers only.
- **WP3 owns shared policy/trust infrastructure; WP5 owns the remaining
  ecosystem credential adapters and enforcement coverage.** Keep one source
  configuration model, with distinct authentication and authorization checks.
  Move the mandatory-loading prerequisite here rather than creating a cycle
  in which WP3 waits for WP5 and WP5 waits for WP3.


---

## 3. Daily-driver gaps (WP4 open items)

Shipped from this package: the `x` lifecycle (`tog x --clean`, per-root
locks) and pnpm `add`/`remove`/`update`.

Each of the following gets the full treatment when taken; the sketch here
names the files and the shape so the next engineer does not start from zero.

**4b-1. Python editable installs and dependency groups.**
- *Objective:* `-e .` (the project itself) as a declared mutable overlay, and
  dev/optional dependency groups installable by flag.
- *Files:* `src/project.rs` (`environment_identity`, `project_env_inner`,
  `clone_tree`), `src/pypi.rs`, `src/manifest.rs` (group discovery),
  `src/cli.rs` (the flag), `src/main.rs::run_sync`.
- *Data model:* the mutable overlay must be an identity input — an env with an
  editable overlay is not the same object as one without. Follow the npm
  `mutable_packages` / `mutable_scope` precedent (`src/npm.rs:2423`, `src/npm.rs:2433`),
  including its honest `mutable_scope: "whole-tree-clone"` wording.
- *Security:* an editable install makes part of the projection writable;
  record it as an exception, never silently.
- *Tests:* `tests/linux_python.rs` unit coverage plus an `--ignored` e2e that
  edits the project source and proves the change is visible without a
  re-sync, and that a second project with the same lock but no editable
  overlay gets a **different** object id.
- *Mac gate:* exercises `clonefile` projection — run the Python `--ignored`
  tests on the Mac.

**4b-2. Yarn classic and Berry dependency edits.**
- *Current state:* both refuse with the conversion command
  (`src/deps.rs`, `LIMITATIONS.md`).
- *Why it is hard:* Yarn classic has no lockfile-only edit mode, so a
  workspace-faithful scratch edit is required — the same class of problem the
  pnpm work solved with `enable-modules-dir=false` and a redirected
  modules-dir, which Yarn classic has no equivalent for.
- *Recommended decision:* **leave as a refusal.** Berry (`yarn 2+`) has
  `--mode=update-lockfile` and is the cheaper target if the owner wants one;
  Yarn classic should stay a documented refusal until a real project demands
  it. *Owner may overrule.*

**4b-3. Poetry and PDM dependency edits.** Both refuse with instructions
today. Each is its own PR following the pnpm shape: delegate to the store's
pinned tool, never read the tool's own workspace-settings file as authority,
and redirect any install-side state into a per-run store stage.

**4b-4. `x` for cargo, go, gems, hex, nuget tools.** Take this **after** WP1
has proven a model for compiled tools. Cargo today stores vendored sources;
`cargo install` output is unmanaged (`docs/human/LIMITATIONS.md`, Rust / cargo).

**4b-5. `fmt` for the remaining ecosystems** under the WP1 contract: Python
(ruff format via `x`), Go (gofmt is already in the toolchain), then the rest.
Each keeps the WP1 rules: named command, script precedence, `--eco` escape
hatch, own store object with a closure/GC reference, exit-status pass-through.

**4b-6. One real project per fixture-only ecosystem** (Cargo, Go, Ruby,
Elixir, .NET), recorded in `docs/agent/HITRATE.md`. Extend `tests/hitrate.py` to measure
a build/test/format command, not only `sync`. Measured on both machines and
recorded as two columns.

**4b-7. Re-run the 60-repo hit rate** after WP1 and after WP3; dated columns,
never an overwrite.

**4b-8. Carry-overs from older roadmaps:** SBOM `vcs` external
references for Git components; standalone vendoring of workspace-inherited
Cargo Git crates; artifact provisioning entries (sharp <0.33, node-sass,
sentry-cli) only when a real project needs them; SPDX SBOM and dependency
graph.

**Mac before merge (per item).** Editable installs and dev groups exercise
clonefile projection, so run the Python `--ignored` tests on the Mac. The
`add`/`remove`/`update` delegates run unsandboxed and are platform-neutral, so
the ten `deps_e2e` round trips on the Mac suffice — including all four pnpm
cases: `pnpm_add_update_remove_roundtrip`,
`pnpm_workspace_member_and_root_roundtrip`,
`pnpm_edits_leave_an_installed_project_untouched` (runs the store pnpm's real
`install` first), and
`nested_independent_npm_project_does_not_use_ancestor_pnpm_lock`. `x`
lifecycle and any compiled-tool model for cargo/go tools need a Mac cold/warm
run because the binaries are per-platform artifacts.


---

## 4. The company layer (WP5)

**Objective.** Enforcement knobs for companies, entirely inside
`.tog/policy.toml` and the machine-wide policy. Permissive stays the
default; nothing is ever loosened silently.

**Prerequisites.** WP1, WP2, the authenticated WP3 foundation, GC safety,
and the selected daily-driver WP4 milestones. Open-ended WP4 breadth (for
example Yarn classic kept as a refusal) is not an impossible completion gate.
WP3 has already delivered mandatory source-policy loading. Remaining company
features follow daily-driver readiness: the tool
must be a daily driver first.

**Items.**
- **Package-level rules.** Today `deny` names exception *categories* (`policy::KINDS`,
  `src/policy.rs:42`) and strict rejects even `built_from_source`. Add
  name/version allow and deny lists, with a defined story for what the user
  sees when each fires.
- **Protected machine-wide policy — foundation delivered by WP3 PR 1.**
  The current `TOG_POLICY` override can replace home-policy selection
  (`policy::load`); WP3 must correct the source/trust path before activation.
  WP5 extends the same unconditional loader to package/category rules and
  adds tests proving neither project nor environment can weaken them.
- **Enforcement must cover every door:** delegated planners (uv/npm/cargo/go/
  bundler/mix run unsandboxed with network), toolchain acquisition, cache
  hits, `run`, and `x`. State in `docs/human/ARCHITECTURE.md` which doors are covered and
  which are not.
- **Private registry configuration and authentication — before any allowlist
  claim.** **Design this jointly with WP3's trusted-publisher list** (owner
  direction, 2026-09-09). WP3 owns the shared implementation; WP5 extends it
  with ecosystem-specific credentials while keeping endpoint permission and
  publisher authentication separate. Python forces public PyPI (`--index-url https://pypi.org/simple` with the
  user's index environment removed, `src/main.rs:843-850`) and Go forces the
  public proxy while clearing private-module settings (`GOPRIVATE`/`GOFLAGS`/
  `GONOSUMDB` blanked at `src/golang.rs:190-193`, `GOPROXY` pinned at
  `src/golang.rs:198-207`).
  Cover delegates, redirects, Git sources, and cached decisions.
- **Age and license rules only once package records carry publication dates
  and licenses.** They carry neither today (`types::LockedPackage`, `src/types.rs:46`;
  `npm::NpmPackage`, `src/npm.rs:217`). Define the metadata source and the missing-data
  behaviour first.
- **Shared store / binary cache across machines: only on real demand.**

**Mac before merge.** Policy loading, registry configuration, and
authentication are pure logic and need only `cargo test` on the Mac, except
that any enforcement inside a build goes through Seatbelt and must be shown to
deny on the Mac too — extend the existing network-denied sandbox acceptance
check (`tests/sandbox_deny.rs`) rather than adding a new one.

**External gate.** Production private-registry verification needs owner
credentials/test accounts. Configuration, token scoping, redirect tests,
and a local authenticated fixture are implementable before those arrive.


---

## 5. GC-safety leftovers

### Supervision exclusions (token threading shipped, #56)

Every child process that reads or writes a store path runs through
`src/kernel/supervise.rs` with the caller's `&StoreActivity`. There is no
`status_owned`/`output_owned` and no sandbox `*_for_store` wrapper any more:
the helpers that spawn (archive extraction, clone, git, the tailors' tool
runners, the sandboxed builds) take the token as a parameter, and the
operation that owns the work holds one lease across its stage directory, its
children and its commit. Command-level callers pass `Context::activity`.
The realization and projection entry points (`realize_runtime`,
`realize_env`, `realize_node_env*`, the `ensure_*` toolchain helpers,
`RegistryTool::realize`/`launch_env`), node lifecycle scripts, `setup.py
egg_info`, build-requirement resolution and the verified-download cache
(`fetch::download_verified*`, `cache_verified*`, `cache_insert`) all take
the caller's lease too, so a caller holding the exclusive lease never hits
a nested acquisition. The `x` cache check borrows the lease its caller
holds, so nothing takes the activity lock underneath the x-root lock (GC
takes activity first, then x-root). The `Store::has`, `stage`,
`commit_with_deps` and `policy::check_cached` wrappers that minted their own
lease are test-only now.

Two checks pin this. The primary one is the compiler's: `clippy.toml`
disallows `std::process::Command::{spawn,status,output}`, `Store::activity`,
`Store::try_activity_exclusive` and `StoreActivity::{acquire,try_exclusive}`,
and CI runs `cargo clippy --locked --all-targets -- -D
clippy::disallowed_methods`. Clippy resolves the call, so aliases, path
calls and raw identifiers cannot hide one. Each reviewed site carries
`#[allow(clippy::disallowed_methods)]` with its reason; test code allows
the lint wholesale. The second check,
`tests/architecture.rs::store_children_borrow_the_callers_lease`, runs in
plain `cargo test`. It tokenizes production code (comments, strings and
`#[cfg(test)]` items removed, `r#` identifiers normalized, `use … as`
aliases followed, path calls counted, with adversarial fixtures for each) and
checks two per-function inventories with exact counts. `LEASE_BOUNDARIES`
lists every function allowed to take a lease: the store primitives, the
command entry points (`Context`, `doctor`, `ls`, `gc`, `x clean`),
automatic maintenance and `gc::collect`, the public root-registry calls
for lease-free callers, and the test-only `detached_lease`. Any other
`.activity(`, `try_activity_exclusive` or `StoreActivity::acquire` fails
the test. `RAW_CHILD_SITES` lists the only production functions outside
`supervise.rs` that still call `.status()`, `.output()` or `.spawn()`
directly. The list and the reason for each row:

| Function | What it runs | Why it takes no token |
|---|---|---|
| `pypi.rs` `detect_host_glibc` | `/usr/bin/getconf GNU_LIBC_VERSION` | Host probe; touches no store path. |
| `dotnet/mod.rs` `invoking_uid` | `/usr/bin/id -u` | Host probe. |
| `selfupdate.rs` `smoke_test` | the downloaded tog with `--version` | Runs a download outside the store. |
| `gitsrc.rs` `run_git` | `git ls-remote` for `resolve_ref` | Network query with no working directory. Git against a tree uses `run_git_with_activity`. |
| `sandbox.rs` `run_bwrap_with_stdout`, `run_seatbelt_status` | unmanaged sandbox entry | For callers that consume no store; store callers use the `*_with_activity` siblings. |
| `sandbox.rs` `bwrap_preflight_with_activity` | `--version` and classification probes | `None` arm of `Option<&StoreActivity>`. |
| `archive.rs` `list_names`, `status_for`; `build_requires.rs` `status_for`, `output_for`; `comforter/mod.rs` `clone_tree_for` | listing, extraction, copy | `None` arm of `Option<&StoreActivity>`: no store is involved. |

Test modules and `#[cfg(test)]` helpers are outside the scan.

### Missing named tests

The GC design named 26 tests for durable project records. None is missing
now. Four behaviors are covered under other names, so no test carries the
design's name:

- `register_imports_every_shipped_closure_schema`: each producer's
  `closure_refs_name_every_object_this_producer_created` re-imports the
  closure it really wrote and compares the record, and
  `kernel::store::tests::register_imports_legacy_closure_bodies_of_every_ecosystem_together`
  covers legacy body shapes. Re-importing a current Node closure adds one
  `legacy-forests` reference the publisher never records (the importer
  still follows the `node-forest/1` `projection_id` route). That namespace
  is never swept, so it retains nothing; the Node test pins it.
- `symlinked_registry_entry_is_a_malformed_record`:
  `kernel::store::tests::unreadable_records_are_reported_not_skipped` and
  `tests/gc_roots.rs::unreadable_records_block_the_sweep_instead_of_disappearing`.
- `moved_project_keeps_its_tools_and_forests`:
  `kernel::gc::tests::root2_keeps_objects_after_the_project_disappears` and
  `kernel::gc::tests::forest_retention_works_with_the_project_directory_absent`.
- `forget_corrupt_record_works_with_an_unrelated_corrupt_record`:
  `tests/gc_roots.rs::a_corrupt_record_never_blocks_forgetting_a_key` and
  `kernel::store::tests::exact_key_recovery_ignores_every_other_record`.

### Per-operation signal sessions (#57)

**Problem.** `src/kernel/supervise.rs` keeps one process-wide session. The
self-pipe fd, the child-pid slot, and the TERM/INT/HUP/QUIT/CHLD counters
are statics that `Session::new` installs and `teardown` resets. A second
concurrent session would overwrite them, so `Session::new` refuses it with
a `WouldBlock` busy error. No production path supervises two children at
once. The unit-test harness does, and that is the whole cost today: about
50 test sites hold `SUPERVISION_TEST_LOCK`, which also sits in the crate's
test lock order (env -> supervision -> store -> attribution); `cargo test
-- --ignored` needs `--test-threads=1`; and 47d484e had to chase a missed
guard that failed about 20% of parallel runs. Any future parallel
realization hits the same wall.

**What a session guarantees today, and must keep guaranteeing.**
1. A parent-directed TERM is forwarded to the live direct child once per
   TERM received. A group-directed TERM reaches the child directly and by
   forwarding (at-least-once).
2. A TERM across the spawn boundary is never lost. Before spawn it becomes
   an `Interrupted` error. Between spawn and pid publication it stays
   pending and is forwarded at publication.
3. A reaped (possibly recycled) pid is never signalled, because the thread
   that reaps the child is the thread that forwards to it.
4. INT/HUP/QUIT are caught and only reject a pending spawn; they are not
   forwarded. Children stay in tog's process group (production has no
   `setpgid`/`setsid`), so the tty driver delivers `^C`/`^Z` to tog and to
   every live child directly, however many there are. The redesign must not
   give children their own groups: that cuts them off from `^C` and breaks
   `terminal_stop_and_continue_covers_the_whole_group`.
5. Outside a session tog behaves as its inherited dispositions say, so a
   TERM kills it (`spawn_failure_restores_dispositions`). Children exec
   with the inherited dispositions and the spawning thread's mask
   (`prepare_child`).
6. SIGCHLD makes the wait event-driven for a lone supervisor.

**Mechanism: handlers installed once, one packed counter, a bounded
wait.** `sigaction` is process-wide and can only be shared, so sessions
become registrations instead of owners of the dispositions. Three review
rounds shaped this. A dispatcher thread with per-session wake pipes failed
open when the thread died, leaked wake fds into concurrent forks, and
needed a spawn gate that could wait unboundedly. Restoring dispositions
when the last session ends left a window: a handler already running on
another thread could count a TERM after the final check, and preemption
makes that window unbounded. This design has neither. Correctness never
depends on a wakeup, and the handlers never come off.

- *`SESSION_TERM`*, one `AtomicU64`: the high 32 bits count live
  sessions, and the low 32 bits count TERMs received (wrapping; only
  differences are used). The handler's TERM path does one `fetch_add(1)`
  and gets back, in the same atomic step, whether any session was live.
  Registering is `fetch_add(1 << 32)`, and deregistering is `fetch_sub(1 <<
  32)`, and each returns the TERM count at that exact instant. So every
  TERM is linearized either before the last deregistration, where a
  session accounts for it, or after it, where the handler itself handles
  it. There is no window. `INT_RECEIVED`, `HUP_RECEIVED`,
  `QUIT_RECEIVED`, and `CHLD_RECEIVED` stay plain monotonic counters,
  because none of them is re-raised by a session.
- *Handlers, installed once.* The first `Session::new` in the process
  records each signal's inherited `sigaction` in a static and installs the
  handler for TERM/INT/HUP/QUIT/CHLD with `SA_RESTART`. The handler stays
  for the life of the process. A signal inherited as `SIG_IGN` is left
  alone, as today, except SIGCHLD (next bullet). With no live session, the
  handler emulates the inherited disposition for TERM/INT/HUP/QUIT. For
  `SIG_DFL` it resets that signal to `SIG_DFL` with `sigaction` and calls
  `raise`, and the signal is delivered with its default action when the
  handler returns. For an inherited function handler it calls the saved
  function, passing `siginfo` through when the saved action had
  `SA_SIGINFO`; other saved flags are not emulated. `sigaction`, `raise`,
  and atomics are async-signal-safe. Because nothing is ever uninstalled,
  there is no restore, no rollback, and no replay. If one `sigaction` of
  the first install fails, the handlers already installed are harmless
  with no session live, so `Session::new` returns the named error and the
  next call installs the rest.
- *SIGCHLD is always handled while tog supervises.* An inherited
  `SIG_IGN` (or `SA_NOCLDWAIT`) makes the kernel auto-reap children, so
  `try_wait` gets `ECHILD` and the exit status is lost. The per-session
  install already replaces an ignored SIGCHLD for the session's lifetime
  (#178, with `inherited_sigchld_ignore_still_reports_the_exit_status` and
  its `SA_NOCLDWAIT` twin in `tests/supervise_signals.rs`). The
  install-once handler keeps doing so, and those two cases carry over
  unchanged. The child still gets the inherited `SIG_IGN` back
  in `prepare_child`, so what the tool sees is unchanged. Tog's
  unsupervised `Command::status` sites benefit the same way.
- *Global pipe.* One self-pipe, both ends nonblocking, created at the
  first install and never closed. The handler writes one byte after
  counting, so it never writes into a reused descriptor. Linux creates it
  with `pipe2(O_CLOEXEC | O_NONBLOCK)`. macOS has no `pipe2`, so it uses
  `pipe` then `fcntl`, once per process, and a child forked by another
  thread in that window can inherit both ends. With the read end it can
  drain wake bytes, which costs a session one tick. With the write end it
  can send spurious wakes, which cost one `try_wait` each. Neither can
  lose or forge a signal, because signals live in the counters. The
  window is accepted and documented, not gated.
- *Registry* (`Mutex<Registry>`): the first-install state and
  `term_orphaned: bool`. It is held only for the first install and for
  deregistration bookkeeping. It is never held across a child's lifetime,
  a `poll`, or a blocking syscall, which separates it from the rejected
  blocking lock. The handler never touches it.
- *Slot*, owned by its session's thread: `child_pid`; one cursor per
  signal (the TERM cursor comes from the registering `fetch_add`);
  `unconsumed_terms`; and `old_mask` (`pthread_sigmask` query), used only
  for its child.
- *Waiting and reconciling.* The loop keeps its shape: `try_wait`, then
  reconcile the counters against the cursors, then forward, then `poll`
  the global pipe plus the session's output fds with a 20 ms timeout, and
  drain the pipe on wake. INT/HUP/QUIT deltas only feed the pre-spawn
  rejection. Each signal has its own cursor, so an old INT is never
  reported twice. A TERM delta goes into `unconsumed_terms`. It is
  consumed by forwarding that many TERMs to the unreaped `child_pid`, or
  by `reject_pending_before_spawn` turning it into `Interrupted`. After
  `clear_child`, it stays unconsumed. With two or more sessions, one can
  drain a byte meant for another, and the loser notices on its next tick.
  A lone session is woken at once, as today.

**Ordering and races.**
- *Signal before a session registers.* The session's cursors come from the
  registering `fetch_add`, with the other counters read just after it, so
  that signal is not the new session's. It belongs to sessions that were
  already live, or it was handled as inherited if none were. An
  INT/HUP/QUIT counted in the gap between those two reads is attributed to
  the new session, which errs toward rejecting a spawn.
- *Registered but not spawned, or spawned but not published.* Unchanged.
  `reject_pending_before_spawn` reconciles and rejects. A TERM counted
  after that check stays unconsumed with `child_pid == -1`, and
  `publish_child` reconciles and forwards it.
- *Session drop and the re-raise rule.* The leaving session reconciles,
  then under the registry lock sets `term_orphaned` if `unconsumed_terms >
  0`, which no other session can clear. Then it deregisters with the
  `fetch_sub`. Suppose that `fetch_sub` returns a live count of one (it was
  the last), and either `term_orphaned` is set or the returned TERM count
  has passed its cursor (a TERM no session saw). It then clears the flag
  and sends itself one TERM, which meets the handler with no session live
  and so gets the inherited behavior. Order does not matter: if A was
  already reaped and draining when TERM 1 arrived, TERM 1 is orphaned
  even when B forwards it to its own child. A TERM every session consumed
  does not re-raise, so the parent-TERM case still exits 45. This closes
  an edge the current code has: a TERM between reap and teardown (for
  example `output` still draining after `clear_child`) is zeroed today,
  and tog carries on. An INT/HUP/QUIT that arrives during a session is
  caught and not forwarded, as documented today.
- *Panics and poison.* The lock is recovered with `into_inner`. A
  panicking session still runs `Drop`, which deregisters.
- *fork.* `pre_exec` touches only copied signal values, never shared
  state, so forking while another thread holds the lock is safe.

**Other code that installs handlers.** Tog installs no other handlers.
Code that calls `sigaction` for one of these signals before tog's first
session is recorded as inherited. Tog chains to it with no session live
and supersedes it while a session is live, the same precedence as today.
Code that installs its own handler after that replaces tog's for good, and
supervision then silently stops forwarding that signal. Today's code
reinstalls on every session. The implementation adds a debug assertion at
each registration that the TERM disposition still points at tog's
handler, so a test that installs its own handler fails loudly. The
harness scenarios install nothing but the job-control shell's
`SIGTTOU` ignore, which is outside this set.

**Latency and CPU trade-off.** A lone session keeps today's event-driven
reaping, but also wakes every 20 ms while its child runs. Each tick is one
`poll` return, one `waitpid(WNOHANG)`, and five atomic loads: a few
microseconds, about 180,000 no-op wakeups per build-hour. With concurrent
sessions, a reap or a forward can lag by up to one tick. The tick only
bounds latency when sessions compete for a wake byte, so it can be raised
without affecting correctness.

**macOS vs Linux.** One implementation. `sigaction`, `raise`, `poll`,
`pthread_sigmask`, and `waitpid` behave the same on both. There are two
splits: the existing `__errno_location`/`__error`, and `pipe2` versus
`pipe` + `fcntl` for the one global pipe, covered above. `signalfd`
(Linux) and `sigwait` need the signals blocked in every thread, including
libtest's threads, which exist before tog's code runs. They were rejected.
kqueue `EVFILT_SIGNAL` (macOS) adds a platform split for no gain.

**What changes for callers.** The busy error disappears. `Session::new`
fails only on the first pipe creation or a failed `sigaction`, each as a
named `io::Error`. No caller matches the busy error: the only other
`WouldBlock` users are the activity and policy locks. Public signatures do
not change. `SUPERVISION_TEST_LOCK` is deleted from all 17 files, and the
lock-order comments in `commands/sync.rs`, `commands/inspect.rs`, and
`kernel/policy.rs` drop "supervision". The `--test-threads=1` row leaves
`docs/human/LIMITATIONS.md`, after the implementation PR checks which
`--ignored` targets still need single threading for another reason and
names those. ARCHITECTURE.md's "Each process supervises at most one
awaited store-consuming child" becomes "each operation supervises its own
awaited child". The LIMITATIONS "three edges" row gains the reap-boundary
re-raise and the SIGCHLD change.

**Tests for the implementation PR.** Each new integration case goes in
`tests/supervise_signals.rs` with its own harness scenario, so it owns its
process's dispositions. Cases synchronize on FIFOs and markers, not
sleeps. Test-only knobs are read from `TOG_SUPERVISE_FAILPOINT` and
`TOG_SUPERVISE_TICK_MS`, and only under `cfg(debug_assertions)`.
- `concurrent_sessions_each_supervise_their_own_child`: two threads, both
  children provably running at once, both exit codes right. Replaces
  `a_second_supervisory_session_is_refused_rather_than_queued`, which is
  deleted.
- `parent_term_reaches_every_live_child`: two live sessions, one TERM; both
  trapping children exit 45, and the harness exits 45 (no re-raise).
- `terminal_interrupt_reaches_every_concurrent_child` (PTY, `^C`): each of
  two trapping children sees INT exactly once.
- `a_session_registered_after_term_does_not_inherit_it`: A's child is in
  its TERM trap, then B starts, and B's child exits 0.
- `an_old_int_is_not_reported_to_a_later_session`, plus the HUP and QUIT
  variants: after A has seen the signal and ended, B registers, an
  unrelated SIGCHLD wakes it, and B still spawns normally.
- `dispositions_act_as_inherited_whenever_no_session_is_live`: for each of
  TERM/INT/HUP/QUIT, once with an inherited `SIG_DFL` (the harness dies of
  that signal) and once with an inherited recording handler (the handler
  runs once, and the harness continues). Run after a session has ended.
- `a_term_during_first_install_acts_as_inherited`: a `pause-after-sigaction-k`
  failpoint blocks on a FIFO for k = 1..5. TERM is sent, then released.
  The harness dies of SIGTERM, because no session was live yet.
- `a_failed_first_install_leaves_signals_behaving_as_inherited`: fail
  `sigaction` k for each k, then check inherited behavior as above, and
  that the next session installs the rest and supervises normally.
- `term_after_reap_but_before_the_pipes_close_is_not_swallowed`: an
  `output` child writes its pid to a file, leaves a grandchild holding
  stdout open on a FIFO read, and exits. The case waits until the child is
  reaped (`kill(pid, 0)` fails), sends TERM, and releases the FIFO. The
  harness must die of SIGTERM. Under the current code it returns normally.
- `a_term_orphaned_by_one_session_reraises_though_another_consumed_it`: A
  and B both registered, A's child reaped while A drains, B's child live.
  One TERM. Both end, in each order across two runs, and the harness dies
  of SIGTERM both times.
- `inherited_sigchld_ignore_still_reports_the_exit_status` (Linux and
  macOS): the harness sets SIGCHLD to `SIG_IGN`, and separately to a
  handler with `SA_NOCLDWAIT`, before its first session. A child's `exit
  42` comes back as 42, and the child itself sees SIGCHLD ignored.
- `a_lone_session_is_woken_by_the_signal_not_the_tick`: with
  `TOG_SUPERVISE_TICK_MS=60000`, 15 children of 105 ms finish in under
  2.4 s, which only a pipe wake can do. The existing
  `a_child_exit_wakes_the_supervisor_without_waiting_for_a_poll_tick`
  adopts this knob.
- `concurrent_reap_latency_is_bounded_by_the_tick`: two threads, default
  tick, 15 children each, each thread under 2.4 s.
- `session_churn_loses_no_exit_and_leaks_no_descriptor` (Linux): 8 threads
  x 50 short children with distinct exit codes. Every code comes back, and
  `/proc/self/fd` has the same count before and after. The baseline is
  taken after one warm-up session.
- `the_global_pipe_reaches_no_child_spawned_after_install` (both OSes, via
  `/proc/self/fd` or `lsof -p`): children spawned during session churn
  hold no end of the pipe. The one-time macOS creation window is
  documented, not tested.
- **macOS gate.** `tests/supervise_signals.rs` must pass on macOS before
  the implementation merges. Everything except the `/proc` assertions
  runs there. The PR records the run and its pass count.
- Every existing case stays and must pass unchanged. The exception is
  `spawn_failure_restores_dispositions`, whose "handler outlived its
  session" check now means "TERM behaves as inherited". The offline suite
  must pass 20 consecutive runs with `SUPERVISION_TEST_LOCK` gone.

**Rejected, and why they stay rejected.**
- *Hard rejection enforced in tests* (treat any concurrent session as a
  test failure). Parallel test threads legitimately supervise at once, so
  it turned a green suite red. The fault is the shared statics, not the
  concurrency, and this design removes the statics.
- *A blocking session lock* (queue the second session behind the first).
  It is held for a child's whole lifetime, so it is an unbounded silent
  wait with no error and no timeout. Two threads whose children wait on
  each other (a FIFO pair, a pipeline) deadlock with nothing named, which
  is the same shape as a helper waiting for a lease its caller holds. The
  registry mutex here is held only for bounded bookkeeping, never across
  a wait, so it cannot form that cycle.
- *A dispatcher thread with a wake pipe per session* (this design's first
  draft). Review found that it could fail open when the thread died, that
  wake pipes leak into concurrent forks unless every fork path joins a
  gate, and that the only portable gate (an `RwLock` around `spawn`) can
  wait unboundedly on a stalled `pre_exec`. The bounded wait above has
  none of those parts.
- *Restoring dispositions when the last session ends* (this design's
  second draft). A handler already running on another thread can count a
  TERM after the last session's final check, so the TERM is lost. Once
  handlers are uninstalled, nothing can see that late count. Installing
  once and emulating the inherited disposition in the handler removes the
  window, the rollback, and the replay.

---

## 6. The resolution proxy (#68)

Decided 2026-09-23 (owner, #68 option 1): the delegated-tool doors get a
tog-owned registry proxy. No refusal behavior changes until the
implementation PRs below land. This section is the design; #61 (the
`Tailor::edit_manifest` trait method) and #169 (moving the Corepack/pnpm
delegate path into the Node tailor) are built from it.

### In plain words

tog verifies every byte it downloads itself. But in a handful of places it
hands the job to the ecosystem's own tool: `tog add lodash` runs npm, a
project with no `Cargo.lock` runs `cargo generate-lockfile`, and so on.
Those tools go to the internet on their own, with the user's full
permissions, and tog sees none of it. Some of them also run project code
while they work (Bundler evaluates the Gemfile, uv may build a package to
read its metadata, `dotnet restore` evaluates MSBuild). `tog audit` cannot
see any of it.

The fix has two halves, and both are needed:

1. **A fence.** The tool runs in the same kind of sandbox tog already uses
   for builds, except that instead of "no network" it gets exactly one
   network destination: a small web server inside the tog process (the
   proxy). Anything else it tries to reach fails.
2. **A gatekeeper with a notebook.** The proxy fetches what the tool asks
   for from the real registry, checks it against policy, checks its
   integrity where the registry published a digest, keeps a copy in tog's
   cache, and writes one line per fetch into a ledger. The ledger's summary
   and any exceptions it found travel into the closure file, which is what
   `tog audit` reads.

The fence without the notebook stops leaks but proves nothing. The notebook
without the fence records only the traffic that chose to be recorded.

### The contract

When this section is fully built:

1. Every child process tog starts that resolves dependencies with network
   access (the census below) starts through one kernel type, the
   **resolution door**. No other code path can start one; a tripwire
   refuses it at run time (see "Every door goes through the door").
2. The door runs the tool **confined**: network reaches only the proxy;
   filesystem writes reach only the lock root (minus `.git` and `.tog`) and
   a per-run scratch directory; reads reach the lock root, declared extra
   roots, the store, and the system runtime; the environment is built from
   empty, not scrubbed from the user's.
3. The proxy forwards only to **permitted endpoints**, never to loopback,
   private, or link-local addresses, and never forwards a credential the
   tool sent.
4. Every request the proxy answers or refuses is one **ledger entry**: URL,
   method, class (index, metadata, artifact, git, sumdb, connect), status,
   sha256 and size of the bytes served, the registry's claimed digest when
   one exists, whether the claim was verified, cache disposition, and the
   refusal reason if refused.
5. Policy is applied **per request, in real time**, with the same
   `policy::Policy` the rest of the run uses. A denied kind is a refused
   request, and a refused request fails the door even when the tool exits
   0.
6. Exceptions the proxy sees reach the closure and therefore `tog audit`
   through the existing exception machinery. Audit gains no new mechanism,
   only two new kinds.
7. The lock the tool writes is **byte-identical** to what the same tool
   writes when it talks to the registry directly. The proxy is invisible in
   every file the user commits.
8. When confinement is unavailable on a host, the door either refuses or
   runs unconfined and records `unconfined-resolution`, by policy. It never
   runs unconfined silently.

**What this does not claim.** It governs tog's doors. A lock produced
outside tog (the developer ran `npm install` themselves) is judged by its
contents at sync, as today; the proxy cannot vouch for a resolution it did
not see. It is cooperative hermeticity plus provenance, the same claim the
build sandbox makes (`docs/human/LIMITATIONS.md`, "Tog's security claim is
provenance"): sandboxed code can still encode data in request paths sent
to a permitted registry. That residual channel is documented, not closed.

### The doors (census, 2026-09-23)

Every place tog runs an ecosystem tool that resolves with the network or
evaluates project code today. "Kind" is the door kind recorded in the
ledger. Code execution is what the tool runs besides itself.

| Site | Tool invocation | Network | Runs code | Kind |
|---|---|---|---|---|
| `tailors/python/inputs.rs` (requirements lock) | `uv pip compile --generate-hashes` | yes | sdist builds for metadata | missing-lock |
| `tailors/python/pypi.rs` (build requirements) | `uv pip compile --no-build` | yes | no | planner |
| `commands/deps.rs` `python_uv` | `uv add` / `remove` / `lock` | yes | sdist and project builds | edit |
| `commands/deps.rs` `uv_compile` | `uv pip compile` (requirements.in edits) | yes | sdist builds | edit |
| `tailors/python/registry_tool.rs` | `uv pip compile` for `tog x` | yes | sdist builds | x |
| `tailors/node/inputs.rs` | `npm install --package-lock-only --ignore-scripts` | yes | no | missing-lock |
| `commands/deps.rs` `node` | npm `install`/`uninstall`/`update --package-lock-only` | yes | no | edit |
| `commands/deps.rs` `node` | pinned pnpm edit (scripts off) | yes | no | edit |
| `tailors/node/registry_tool.rs` | npm lock-only for `tog x` (also realizes pnpm for edits) | yes | no | x |
| `tailors/cargo/inputs.rs` `ensure_cargo_lock` | `cargo generate-lockfile` | yes | no | missing-lock |
| `commands/deps.rs` `cargo_delegate` | `cargo add` / `remove` / `update` | yes | no | edit |
| `tailors/go/mod.rs` | `go mod tidy -diff`, `go mod tidy`, `go mod download -json all` | yes | no | planner / missing-lock |
| `commands/deps.rs` `go_delegate` | `go get` | yes | no | edit |
| `tailors/ruby/mod.rs` `plan_ruby` | `bundle lock` | yes | Gemfile eval | missing-lock |
| `tailors/ruby/mod.rs` `plan_ruby` gate 1 | Bundler helper | PR 0 confirms none | Gemfile eval | planner |
| `commands/deps.rs` `ruby_delegate` | `bundle add` / `remove` / `update` | yes | Gemfile eval | edit |
| `tailors/elixir/mod.rs` `plan_elixir` | `mix deps.get`, `mix deps.get --check-locked` | yes | mix.exs eval (git deps' too) | missing-lock / planner |
| `commands/deps.rs` `elixir_delegate` | `mix deps.update` | yes | mix.exs eval | edit |
| `tailors/dotnet/mod.rs` `plan_dotnet` | `dotnet restore --use-lock-file` | yes | MSBuild eval | missing-lock |

Not doors: tog's own downloads (`kernel::fetch`, `kernel::gitsrc`, the
`registry_lookup` existence check in `deps`) are tog code with tog
verification; host-local helpers (`tar`, `getconf`, `id`,
`cargo locate-project --offline`) need no network. A planner row that needs
no network (Ruby gate 1, if PR 0 confirms it) still goes through the door
with **no routes**, which is full network denial. That also closes the
LIMITATIONS row "Delegated planning runs unsandboxed with user privileges"
for code-evaluating planners.

### Per-ecosystem traffic and how each tool is pointed at the proxy

The proxy speaks two dialects on one listener:

- **Forward proxy with TLS interception** ("CONNECT-MITM"). The tool is
  told to use an HTTP proxy (`HTTPS_PROXY` or the tool's own flag). For an
  `https://` URL it sends `CONNECT host:443`. The proxy answers the CONNECT,
  terminates TLS with a leaf certificate for `host` signed by a per-process
  tog CA, reads the plain HTTP request inside, and fetches it upstream
  itself over real TLS. The tool trusts the tog CA through an environment
  variable naming a file that holds **only** that CA.
- **Registry mirror** (plain HTTP). The tool's registry base URL is set to
  a proxy route (`http://127.0.0.1:<port>/<token>/<route>/`). The proxy
  maps the route to its upstream base and fetches over real TLS.

Per ecosystem (claims marked † are verified by PR 0 before anything is
built on them):

| Ecosystem | Upstream traffic | Mechanism | Wiring | Lock effect |
|---|---|---|---|---|
| Python (uv) | `pypi.org/simple` (PEP 691 JSON / 503 HTML), `files.pythonhosted.org` (wheels, sdists, `.metadata`), git remotes, direct-URL requirements, any `[[tool.uv.index]]` | CONNECT-MITM | `HTTPS_PROXY`/`HTTP_PROXY` = proxy with token credentials, `NO_PROXY` empty, `ALL_PROXY` removed, `SSL_CERT_FILE` = tog CA file† (uv reads it for rustls roots), `--index-url https://pypi.org/simple` kept where it is passed today | none: uv sees real URLs, so `uv.lock` and `requirements.lock.txt` record them |
| Node (npm) | `registry.npmjs.org` packuments (abbreviated `application/vnd.npm.install-v1+json`) and tarballs, scoped registries from `.npmrc`, `https:` tarball deps, git deps (git CLI) | CONNECT-MITM | CLI flags (beat project `.npmrc`): `--proxy`, `--https-proxy`, `--noproxy=`, `--registry=https://registry.npmjs.org/`, `--strict-ssl=true`; `NODE_EXTRA_CA_CERTS` = tog CA†; `npm_config_*` stripped as today | none: `resolved` URLs are upstream |
| Node (pnpm) | same as npm | CONNECT-MITM | pnpm settings via env and flags (`--config.proxy`, `--config.https-proxy`, `--config.noproxy`)†, `NODE_EXTRA_CA_CERTS`; the per-run HOME/XDG stage stays | none |
| Rust (cargo) | `index.crates.io` sparse index (`config.json`, index files), `static.crates.io` crate downloads (via 302 from `crates.io/api/v1/.../download`), alternative registries in `.cargo/config.toml`, git deps | CONNECT-MITM | `--config http.proxy=...`, `--config http.cainfo=<tog CA>`†, `--config net.git-fetch-with-cli=true` (so git goes through the git row), `CARGO_HOME` = scratch, `CARGO_NET_OFFLINE=false` | none: `Cargo.lock` records `registry+https://github.com/rust-lang/crates.io-index` whatever the transport |
| Go | `proxy.golang.org` (`/@v/list`, `.info`, `.mod`, `.zip`, `/@latest`), `sum.golang.org` lookups and tiles | Registry mirror | `GOPROXY=http://127.0.0.1:<port>/<token>/go/` (no `,direct`), `GOSUMDB=sum.golang.org` with the proxy serving `/sumdb/sum.golang.org/...`† (the go command asks `<proxy>/sumdb/<name>/supported` first and then fetches the signed tree through the proxy; go verifies the note signature itself), `GOVCS=*:off`, `GOTOOLCHAIN=local`, `GOPRIVATE`/`GONOPROXY`/`GONOSUMDB`/`GOINSECURE` empty as today | none: `go.sum` holds hashes only |
| Ruby (Bundler) | `index.rubygems.org` compact index (`/versions`, `/info/<gem>`), `rubygems.org/gems/<name>-<ver>.gem`, other `source` blocks, git gems | Registry mirror for rubygems.org, forward proxy (no interception) for everything else | Bundler config file in `BUNDLE_APP_CONFIG` = scratch: `BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: http://127.0.0.1:<port>/<token>/rubygems/`†; `https_proxy`/`http_proxy` = proxy | none: `Gemfile.lock` keeps `remote: https://rubygems.org/` (mirrors are transparent by design) |
| Elixir (Hex, mix) | `repo.hex.pm` (`/names`, `/versions`, `/packages/<name>` signed protobuf, `/tarballs/<name>-<ver>.tar`), git deps | Registry mirror for Hex, CONNECT-MITM for git | `HEX_MIRROR=http://127.0.0.1:<port>/<token>/hex/`†, `HEX_UNSAFE_REGISTRY` removed (Hex keeps verifying the registry signature with its public key), `HEX_HTTP_PROXY`/`HEX_HTTPS_PROXY` = proxy†, `HEX_OFFLINE` as today | none: `mix.lock` records the repo name `hexpm` |
| .NET (NuGet) | `api.nuget.org/v3/index.json` service index, registration pages, flat container (`.nupkg`), certificate revocation checks | Registry mirror (the service index and registration JSON are rewritten so resource URLs point at proxy routes), forward proxy without interception for anything else | tog-written `nuget.config`: `<clear/>` plus one source `http://127.0.0.1:<port>/<token>/nuget/v3/index.json` with `allowInsecureConnections="true"`†; `NUGET_CERT_REVOCATION_MODE=offline`†; `HTTPS_PROXY` = proxy; `DOTNET_CLI_TELEMETRY_OPTOUT=1`, `DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1`, `DOTNET_NOLOGO=1` | none: `packages.lock.json` holds content hashes only; `obj/project.assets.json` may name the proxy source (build scratch, rewritten by the next restore; `tog build` restores fresh) |
| git (any ecosystem) | `https://` remotes (smart HTTP: `info/refs?service=git-upload-pack`, `POST git-upload-pack`), `ssh://` and scp-style remotes, `git://` | CONNECT-MITM for https; ssh rewritten to https; `git://` refused | `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_COUNT`/`KEY`/`VALUE` for `http.proxy`, `http.sslCAInfo`, and `url.https://<host>/.insteadOf` for `ssh://git@<host>/` and `git@<host>:`; `GIT_TERMINAL_PROMPT=0` | the commit id the tool locks |

#### Which tools cannot be fully proxied, and what happens then

"Fully proxied" means the proxy can see and record every byte. Each gap
has a concrete answer:

- **Go and .NET on macOS cannot be taught a private CA.** Go on darwin
  verifies through the platform verifier and ignores `SSL_CERT_FILE`; .NET
  on macOS uses the Keychain. tog will not modify the user's Keychain.
  Answer: both use the registry-mirror dialect, which needs no TLS between
  tool and proxy, on both platforms (one mechanism per ecosystem, not per
  platform). Their only registry traffic is the mirror. Any other traffic
  (a .NET workload advertising-manifest check, telemetry) goes to the
  proxy as a `CONNECT`, because `HTTPS_PROXY` is set. The proxy refuses it
  with a ledger entry naming the host instead of letting it hang on a
  denied socket. If the tool fails because of that refusal, tog's error
  names the host and the reason.
- **Ruby sources other than rubygems.org.** Sync already fails closed on
  them (LIMITATIONS, Ruby). The proxy agrees: Bundler reaches them through
  `CONNECT`, the proxy refuses without interception and records
  `unattested-index` for the host, and the edit fails with the same
  sentence sync uses. When WP5 private-registry support arrives, a
  permitted Ruby source becomes a second mirror route and needs no new
  mechanism.
- **Hex beyond `repo.hex.pm`** (private organizations at
  `repo.hex.pm/repos/<org>`, other repos): the same `CONNECT` visible
  refusal until WP5 adds credentials. Hex organization access is a
  credentialed route, not a TLS problem.
- **`git://` remotes** (unencrypted, unauthenticated, port 9418): refused
  under every policy with "git:// is unauthenticated; use https://". The
  ledger records the refusal with kind `git-dependency`.
- **SSH git remotes with private keys.** The sandbox has no `~/.ssh` and no
  agent socket, on purpose. The `insteadOf` rewrite serves public
  repositories over https. A private repository needs a WP5 credential
  reference that the proxy attaches upstream; until then the fetch fails
  with the host named. The tool never holds the credential.
- **Direct-URL dependencies** (npm `https:` tarball specs, PEP 508
  `name @ https://...`): fully proxied for npm and uv by interception,
  recorded as `unattested-index` when the host is not a permitted
  endpoint (see policy mapping). Cargo, Go, Bundler, Hex, and NuGet have no
  arbitrary-URL dependency form.
- **Tools that ignore proxy settings for some traffic.** Whatever is not
  routed fails against the sandbox, which is the fail-closed outcome. PR 0
  records which requests those are. The fix is always to route them, never
  to open the fence.

### TLS: which of the three designs, per ecosystem

The three options:

1. **HTTP CONNECT tunnel, no interception.** The proxy sees only
   `host:port` and an encrypted byte stream. It can allow or deny a host
   but cannot record a URL, a digest, or a package. Rejected as the
   recording mechanism: it cannot answer "what did the tool fetch". Kept
   as the **refusal detector** for traffic an ecosystem should not produce
   (row ".NET", "Ruby" above): the tool announces the host, and the proxy
   says no with a reason.
2. **Local HTTPS with a tog-generated CA (interception).** The proxy sees
   full requests. The tool must trust the CA. Chosen for **uv, npm, pnpm,
   cargo, and git**. Their locks record upstream URLs (`resolved` in
   `package-lock.json`, `source`/`url` in `uv.lock`), and a mirror would
   put `http://127.0.0.1:...` into them. Undoing that means rewriting
   registry responses on the way in and lock files on the way out: two
   format-specific transforms on security-relevant files, each a place for
   a mistake. With interception the tool talks to the real URLs and the
   lock comes out byte-identical (contract 7), which is also a directly
   testable property. All five tools take a CA file through an environment
   variable or flag on both platforms (Node bundles its own OpenSSL, uv and
   cargo use their own TLS stacks, git uses `http.sslCAInfo`).†
3. **Registry-API mirror.** The tool is pointed at the proxy as its
   registry over plain HTTP on loopback. The proxy sees full requests and
   needs no certificate. Chosen for **Go, Bundler, Hex, and NuGet**. Their
   mirror settings are first-class upstream features (`GOPROXY` is the
   protocol, Bundler mirrors and `HEX_MIRROR` are documented
   substitutions), their locks never record transport URLs, and for Go
   and .NET it is the only option that works on macOS. Hex's registry is
   signed and Go's checksum database is signed. Both are forwarded
   byte-for-byte, so the tool's own signature check stays intact. Only
   NuGet needs response rewriting (the service index and registration
   JSON carry absolute URLs), and those responses are unsigned JSON that
   never reaches a committed file.

**The CA.** One per tog process, generated when the proxy starts (ECDSA
P-256 through `ring`, which tog already links). The private key never
leaves memory. The certificate is written 0600 into the session
directory and bound read-only into the sandbox. Leaf certificates are
minted per SNI host on demand and cached in memory for the process. The
system and user trust stores are never touched. Each tool's CA variable
names a file holding **only** the tog CA, so the confined tool cannot
complete a TLS handshake with anything but the proxy, even in the
unconfined fallback. New dependencies: `rcgen` (certificate building,
`ring` backend) and the server half of `rustls`, which `ureq` already
pulls in at 0.23. The proxy PR pins rustls's `ring` provider explicitly.
Upstream TLS (proxy to registry) is tog's existing `ureq`/rustls client
with webpki roots, plus WP3's company roots when WP3 PR 1 lands.

**ALPN.** The interception server offers only `http/1.1`. Tools that
prefer HTTP/2 (cargo's sparse index, uv) fall back to parallel HTTP/1.1
connections. The cost is in "Performance".

### Confinement: network limited to the proxy

The door is a third sandbox mode beside "no network" builds: network =
`Proxy`. It uses the same `kernel::sandbox` engines and their existing
rules (canonical roots, the host-socket scan of writable roots,
`--clearenv`).

**Linux (bubblewrap).** `--unshare-net` as for builds gives the tool a
network namespace whose only interface is its own loopback, which bwrap
brings up†. The host proxy is not reachable there, so the bridge is a Unix
socket:

1. The proxy listens on a Unix socket in a 0700 session directory under
   `$XDG_RUNTIME_DIR` (else the temp dir). The path is kept short, under
   the 108-byte `sun_path` limit.
2. bwrap binds that one socket file at `/run/tog/proxy.sock` (read-only;
   `connect(2)` needs no write access on a read-only mount for a socket
   inode†, else a single-file `--bind`), and binds the running tog
   executable (`/proc/self/exe`, resolved before the sandbox starts)
   read-only at `/run/tog/tog`.
3. The sandbox's first process is `tog __resolution-relay /run/tog/proxy.sock
   127.0.0.1:8119 -- <tool argv>`, a hidden subcommand. It listens on the
   fixed port inside the private namespace, splices each accepted
   connection to the Unix socket, spawns the tool, and exits with the
   tool's status. The fixed port keeps every proxy URL identical from run
   to run. `--die-with-parent` and the PID namespace end every descendant
   when the relay exits, so nothing outlives the door on Linux.
4. No DNS exists in the namespace (`/etc/resolv.conf` is not bound, and no
   resolver is reachable). The tool never needs one because every proxy
   URL uses a literal IP.

**macOS (Seatbelt).** There is no network namespace. The proxy listens on
`127.0.0.1:<ephemeral>`, bound by tog before the tool starts so nothing
else can hold the port. The profile keeps `(deny network*)` and adds
`(allow network-outbound (remote ip "localhost:<port>"))`†. It also closes
the DNS side channel the current profile leaves open, because the build
profile allows `mach-lookup` wholesale: the door profile appends
`(deny mach-lookup (global-name "com.apple.dnssd.service")
(global-name "com.apple.mDNSResponder"))` after the blanket allow (SBPL:
the last matching rule wins†). The TCP port is reachable by other local
processes during the run, so every request must carry the per-session
token (Proxy-Authorization basic credentials for the forward proxy, a
path prefix for mirror routes); requests without it get 407/403 and a
ledger entry. Seatbelt applies to every descendant. The process-tree
quiescence gap (a daemon surviving the tool's exit, Backlog "Sol review 3
leftovers") remains on macOS, and the rules keep children in tog's
process group (§5, guarantee 4). Such a straggler stays inside Seatbelt,
so it can write only the lock root. Anything it writes after tog has read
the outputs changes the lock digest, and the next sync drops the
resolution record (see "Recording").

**Filesystem, both engines.** Writable: the lock root, the per-run
scratch (HOME, TMPDIR, the tool's caches), and nothing else. Read-only on
top of the writable lock root: `.git` and `.tog` (bwrap `--ro-bind` over
the bind when they exist, Seatbelt `deny file-write*` subpaths). A
hostile build that plants `.git/hooks/pre-commit` would get code
execution outside any sandbox at the user's next commit, so this matters.
When `.git` or `.tog` does not exist, bwrap cannot pre-mount it. The door
then checks after the run that neither appeared and fails closed if one
did. Readable: the lock root, the tool's store objects, the store paths
the tailor declares, and extra roots the tailor declares (an out-of-root
`path =` Cargo dependency, an npm `file:` target outside the root, a uv
path source). A missed root shows up as a permission error naming the
path, which is fail-closed.

**No confinement available** (Linux without unprivileged user
namespaces, `bwrap` missing, `sandbox-exec` missing): the door runs the
tool unconfined, but still wired to the proxy with the tog-only CA file,
so cooperative traffic is still recorded. It records
`unconfined-resolution` before starting. A policy that denies that kind
(the company template will) refuses the door before the tool starts, and
the message says which engine is missing. Contract 8.

### Recording: the ledger, the resolution record, and the join

**The ledger** (`resolution-ledger/1`) is one per door run. The proxy
appends entries as it serves. At the end the door serializes it
canonically (keys in byte order, compact, the same canonicalization as
`kernel/signing.rs`; entries sorted by `(class, url, method)` so parallel
fetch order does not change the bytes) and commits it as a store object
whose identity is the sha256 of those bytes. Header fields:

- `door`: `edit` | `missing-lock` | `planner` | `x`
- `ecosystem`, `tool` (name, version, store object id)
- `command`: the tog verb and its operands (`["add", "lodash@^4"]`) and the
  tool argv with the proxy token redacted
- `lock_root` relative to the project, `outputs` (declared output files)
  with their sha256 after the run
- `confinement`: `bwrap` | `seatbelt` | `none`
- `policy`: the effective `strict` and `deny` set the proxy judged with

Entries: `{class, method, url, status, sha256, bytes, claimed, verified,
cache, redirects, decision, reason}`. `url` is always the upstream URL:
for mirror routes the proxy writes the URL it fetched, not the route path.
Header values (cookies, `Authorization`) are never recorded.

**The resolution record** (`.tog/resolution/<ecosystem>.json`, written
through `ProjectRoot` like every other `.tog` write) is the part that
travels. It is written by the door when the tool succeeded and the outputs
passed the checks:

```json
{"schema":"resolution/1","ecosystem":"node","door":"edit",
 "tool":{"name":"npm","version":"10.9.2","object":"<id>"},
 "command":["add","lodash@^4"],
 "outputs":{"package-lock.json":"<sha256>","package.json":"<sha256>"},
 "ledger":{"sha256":"<hex>","entries":412,"artifacts":3,
           "endpoints":["registry.npmjs.org"],"refused":0,"stale":0},
 "confinement":"bwrap",
 "exceptions":[{"kind":"unattested-index","subject":"npm.example.com","detail":"..."}]}
```

It carries no timestamps, token, or port, so the same resolution on two
machines writes the same bytes. It is committed. The README's `.gitignore`
stanza gains `!**/.tog/resolution/` in the PR that introduces the file.

**The join.** It happens in one ecosystem-neutral place,
`comforter::write_closure_inner`, before it claims the attribution: it
reads `.tog/resolution/<ecosystem>.json` from the closure's project
directory (the lock root, which is also the sync root for Cargo
workspaces and pnpm workspaces). If every `outputs` digest matches the
files on disk, the closure body gains `"resolution": <the record>`, and
the record's `exceptions` are re-recorded into the attribution on the
writer's thread (the owner), skipping any `(kind, subject)` the frame
already holds. A denied kind makes that record fail, so the closure is
not published and the sync fails: this is how a CI sync under company
policy stops a lock that a laptop resolved unconfined. The closure is signed
over its whole body, so the signature covers the resolution summary. If
any digest differs (the lock was edited by hand, or regenerated outside
tog), the record describes a lock that no longer exists: it is deleted,
and the closure has no `resolution` field. That is the honest state
"this lock was not resolved through tog's door". It is not an exception,
because a lock made outside tog is judged by its contents, like any lock
today. The closure field is additive; closure identity is not an object
identity, so no golden moves. PR 4 adds a test that no closure reader
uses `deny_unknown_fields` on the body.

**Where exceptions come from, with no double counting.** Facts the proxy
sees split in two:

- **Re-derivable from the lock** (`git-dependency`, `weak-integrity`): the
  tailor already records these from the lock during sync. The proxy uses
  them only for real-time denial (a denied kind refuses the request and
  fails the door early, before a lock is written). It does not put them
  in the record, so the closure never carries the same finding twice.
- **Only the proxy can know** (`unattested-index` for an endpoint the
  resolution consulted, `resolution-build`, `unconfined-resolution`):
  these go into the record's `exceptions` and reach the closure through
  the join.

`tog audit` needs no change beyond knowing the two new kinds. Audit
already fails on a kind it does not know ("no recorded exception is
denied or unknown"), so an older binary judging a newer closure fails
closed.

**Threading.** `policy::record_with` refuses a record from a thread that
does not own the frame. The proxy runs on its own threads, so it never
records. It holds a clone of the effective `Policy`, calls the pure
`policy::denied` per request, and collects facts in the ledger. The door,
on the thread that opened the attribution, records after the tool exits.

### Policy checks: how proxy facts map to exception kinds

| What the proxy sees | Kind | Real-time action when denied | Otherwise |
|---|---|---|---|
| Any git fetch (smart HTTP through interception, or a refused `git://`) | `git-dependency` (existing) | refuse the request with the policy refusal text | ledger only (sync re-derives from the lock) |
| An artifact whose registry claim is SHA-1 or MD5 only (npm `shasum` without `integrity`, a PyPI `md5` fragment), or has no claim at all where the protocol provides one | `weak-integrity` (existing) | refuse | ledger only |
| A request to an endpoint outside the permitted set: an intercepted host (uv extra index, `.npmrc` scoped registry, direct-URL dependency) or a refused `CONNECT` | `unattested-index` (existing; the policy text already covers "index-like options") | refuse | intercepted tools (uv, npm, pnpm, cargo): forward and put it in the resolution record; mirror tools (Go, Bundler, Hex, NuGet): refuse visibly and put it in the record |
| uv fetched an sdist or a source tree it must build for metadata: a third party's build backend ran during resolution, confined | `resolution-build` (**new**) | before starting, pass `--no-build` to uv so it refuses to build (tool-native, deterministic); the proxy refuses sdist fetches as a backstop | record |
| The door ran without confinement | `unconfined-resolution` (**new**) | refuse before the tool starts | record |
| Lifecycle scripts | none | `--ignore-scripts` and `npm_config_ignore_scripts=true` stay as today; a script that ran anyway would be confined | `install-script-failed` stays a realize-time kind |
| Integrity mismatch (bytes differ from the claimed digest) | not an exception | always a hard failure: 502 to the tool, door fails, nothing cached | no permissive path |

The two new kinds go into `policy::KINDS`. `docs/human/policy-company.toml`
adds `unconfined-resolution` to `deny`. `resolution-build` stays
permitted in the template, with a comment explaining why: the build was
confined, and the resulting lock is verified at sync like any other lock.

**Permitted endpoints.** Until WP3 PR 1 lands, the permitted set is
compiled in and is exactly today's forced public set: `pypi.org`,
`files.pythonhosted.org`, `registry.npmjs.org`, `index.crates.io`,
`static.crates.io`, `crates.io` (the download redirect), `proxy.golang.org`,
`sum.golang.org`, `rubygems.org`, `index.rubygems.org`, `repo.hex.pm`,
`api.nuget.org`, plus each ecosystem's documented CDN redirect targets
(PR 0 lists them). Git hosts are not endpoints: any https host is allowed
for git and every git fetch is `git-dependency`. WP3 PR 1 turns the set
into the typed endpoint configuration (machine policy may add, project
policy may only intersect). The proxy is where WP5 credential references
are used: attached upstream per endpoint, never forwarded across a
redirect to another origin, never visible to the tool. The proxy strips
`Authorization`, `Proxy-Authorization` (after checking the token), and
`Cookie` from every tool request.

**SSRF.** Sandboxed code can send the proxy any request. Routes accept
only paths that parse in their protocol's grammar (no `..`, no
percent-encoded `/`, no absolute-form URLs inside a route). The upstream
host is fixed by the route, or by `CONNECT` for interception. Every
upstream address is resolved by the proxy and refused if it is loopback,
private (RFC 1918, ULA), link-local (including `169.254.169.254`),
multicast, or unspecified. The check runs after resolution, so DNS
rebinding cannot defeat it. Redirects are rechecked hop by hop against the
permitted set, as WP3 requires.

### Offline behavior

Two situations, handled the WP3 way ("a transport failure may fall back
to last-good; an integrity failure never does"):

- **Upstream unreachable while online** (DNS, connect, TLS, timeout, HTTP
  5xx): metadata requests are served from the proxy's last-good copy if one
  exists, marked `stale` in the ledger and summarized in one note ("npm:
  12 metadata responses served from cache; registry unreachable"). With no
  copy, the answer is 504 with a body naming the URL. Artifacts are served
  only from the verified cache (below), never from anything unverified. A
  4xx is passed through, not converted to stale.
- **`--offline`** (WP3's mode; the flag does not exist yet, and until it
  does this mode is exercised by tests): the proxy makes no upstream
  connection. Metadata comes from last-good, artifacts from the cache, and
  every miss is 504 plus a ledger `offline-miss`. The door's error names the
  first miss, which is the thing to fetch online. A project whose lock
  already exists reaches no edit or missing-lock door offline, but two
  planner doors run on ordinary syncs: Go's `mod tidy -diff` and
  `mod download` on a plan-cache miss (served from the persistent planner
  module cache, so they need the proxy only for modules not yet seen) and
  mix `deps.get --check-locked` (Hex registry metadata, served from
  last-good). Offline, both succeed when the project was synced online
  once on this machine, and fail naming the first miss otherwise.

`--frozen` is unchanged: sync never calls `prepare`, so no missing-lock
door runs, and dependency edits are not frozen operations.

### Missing-lock generation through the door

`commands::sync::run_in` calls `tailor.prepare` for each detected
ecosystem when not frozen. With the door:

1. `run_in` opens the ecosystem's `Attribution` as today and passes it
   into a `ResolutionDoor` for `prepare`.
2. The tailor decides a lock is missing and builds a `DelegateSpec` (tool,
   args, outputs = the lock file, routes, read roots).
3. The door runs it confined through the proxy, checks outputs (below),
   writes the ledger object and the resolution record, and records
   ledger-only exceptions into the same attribution. For a missing-lock
   door the attribution is already the ecosystem's own scope, so no
   hand-off is needed.
4. The tailor plans from the new lock exactly as today: every artifact is
   fetched and verified by tog at realize time.
5. The closure writer joins the record, whose output digests match because
   the lock was just written.

Planner doors inside `Tailor::sync` (Go's `mod tidy -diff` and
`mod download -json all`, mix `deps.get --check-locked`) open a door from
the same attribution. They write a ledger but no resolution record (they
did not produce the lock). A refusal still fails the sync. Go's closure
download keeps its "re-verify every artifact" rule. The proxy's cache and
tog's `cache/sha256` are the same store, so the second copy costs
nothing.

### `Tailor::edit_manifest` and the door API (#61, #169)

The kernel owns the door (`src/kernel/resolve/`: proxy server, CA,
routes, ledger, cache, the relay subcommand's body). Tailors own protocol
knowledge through a kernel trait. Commands own nothing ecosystem-specific.

```rust
// src/kernel/resolve/mod.rs
pub enum DoorKind { Edit, MissingLock, Planner, X }

/// The only way to run a dependency tool that may use the network or
/// evaluate project code. Borrowing the attribution ties every fact the
/// run produces to the scope that will publish (or discard) it.
pub struct ResolutionDoor<'a> { /* store, activity, platform, kind,
                                    attribution: &'a mut Attribution, policy */ }

impl<'a> ResolutionDoor<'a> {
    pub fn open(store: &'a Store, activity: &'a StoreActivity, platform: Platform,
                kind: DoorKind, attribution: &'a mut Attribution) -> io::Result<Self>;
    /// Run one tool invocation confined to the proxy. Fails when the tool
    /// fails, when any request was refused by policy, or when an output
    /// check fails; on failure the declared outputs are restored.
    pub fn run(&mut self, spec: DelegateSpec<'_>) -> io::Result<DelegateReport>;
    pub fn attribution(&mut self) -> &mut Attribution;
}

pub struct DelegateSpec<'s> {
    pub ecosystem: &'static str,
    pub tool: ToolId,                     // name, version, store object id
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub lock_root: &'s Path,              // cwd and the one writable project root
    pub outputs: Vec<PathBuf>,            // relative to lock_root; backed up, checked, digested
    pub read: Vec<PathBuf>,               // store objects and declared extra roots
    pub env: Vec<(String, String)>,       // tog-forced values; the environment starts empty
    pub routes: Vec<Route>,               // mirror routes: (&'static dyn RegistryProtocol, Endpoint)
    pub intercept: Intercept,             // Intercept::{Tls, RefuseVisibly}
    pub wire: &'s dyn Fn(&ProxyAddress) -> io::Result<Wiring>, // proxy URL/CA path -> args, env, config files
}

/// Implemented in tailor folders; the kernel never names an ecosystem.
pub trait RegistryProtocol: Sync {
    fn route_id(&self) -> &'static str;                       // "go", "rubygems", "hex", "nuget"
    fn upstream(&self, endpoint: &Endpoint, path: &str) -> io::Result<Url>; // grammar-checked
    fn classify(&self, url: &Url) -> RequestClass;            // index | metadata | artifact | sumdb
    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)>; // digests this metadata promises
    fn rewrite(&self, _url: &Url, body: Vec<u8>, _base: &ProxyAddress) -> io::Result<Vec<u8>> { Ok(body) }
}
```

Interception needs no `RegistryProtocol` to forward. Registering one for a
host still gives classification and claims, so npm packuments feed the
tarball `integrity` claims and PyPI JSON feeds the wheel `sha256` claims.

The trait method #61 asked for:

```rust
// src/tailors/mod.rs
pub struct ManifestEdit<'a> {
    pub verb: EditVerb,              // Add | Remove | Update, moved out of commands/deps.rs
    pub project: &'a Path,
    pub specs: &'a [DepSpec],        // { name, text }, already validated by commands::deps::validate_spec
    pub dev: bool,
    pub toolchain: &'a Selected,
}

pub struct EditOutcome {
    pub files: Vec<String>,          // what the user is told changed
    pub sync_root: PathBuf,          // where the following sync runs (pnpm workspace root)
}

/// `tog add` / `remove` / `update` for this ecosystem: edit the manifest
/// and lock with the ecosystem's pinned tool. The tool runs only through
/// `door`: network limited to tog's resolution proxy, writes limited to
/// the lock root, every fetch in the ledger. A tailor that cannot make an
/// edit refuses with the exact command to run; the default refuses.
fn edit_manifest(
    &self,
    ctx: &Context,
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    Err(unsupported(self.id(), "add, remove, and update"))
}
```

`Tailor::prepare` changes the same way: its `attribution` parameter
becomes `door: &mut ResolutionDoor<'_>` (the door lends the attribution
back through `door.attribution()`). `RegistryTool::realize` takes a door
in place of its attribution too. An `x` door's lock root is the
`~/.tog/x` cache root, and it writes a ledger but no resolution record,
since there is no project. Its npm/uv resolution is a door, and
`realize_node_tool`, which realizes the pinned pnpm, becomes a Node tailor
function used by the Node `edit_manifest` (#169, option 2). After this,
`commands/deps.rs` keeps only what is ecosystem-neutral: spec validation
(the `cli/parse.rs` allow-list row stays), the choice ladder, dispatch
through the registry, the report lines, and the follow-up sync.
`grep -n 'tailors::' src/commands/deps.rs` is empty (#61's "done when").
`registry_lookup` moves behind a `Tailor::registry_exists(name)` method so
the URLs live with their ecosystems.

The refusals (.NET, Elixir add/remove, Yarn, Poetry/PDM) move into each
tailor's `edit_manifest` unchanged. `.NET` keeps refusing edits: MSBuild
evaluation is now confined, but `dotnet add package` restores and edits
the project file, and that decision is not part of this design.

### Every door goes through the door

Rule 1 of the contract needs enforcement, not review alone:

- **Runtime tripwire.** `kernel::supervise` gains `local_status` and
  `local_output` for host-local helpers. Their contract is "this child
  needs no network". They refuse to spawn a program whose file name is in
  `RESOLVERS` (`uv`, `npm`, `npx`, `pnpm`, `cargo`, `go`, `bundle`, `gem`,
  `ruby`, `mix`, `elixir`, `erl`, `dotnet`, `git`) unless the argv matches
  a row of a small reviewed table of offline forms
  (`cargo locate-project ... --offline`, `go` with `GOPROXY=off`, `tar`
  never matches). Helpers that evaluate project files without needing the
  network (the Ruby gate-1 helper, the Elixir `mix.lock` parser) go
  through a door with no routes, which is full network denial. The door
  calls the unrestricted primitive, and so do `sandbox` builds. Every
  other supervise caller moves to `local_*`.
- **Compile-time.** `clippy.toml` adds `tog::kernel::supervise::status` and
  `tog::kernel::supervise::output` to `disallowed-methods`, allowed only in
  `kernel::resolve`, `kernel::sandbox`, and `kernel::supervise` itself,
  each with its reason. That is three kernel sites, not an allow-list row
  per tailor.
- **Named test.** `every_resolver_invocation_goes_through_the_door` runs the
  tripwire table against the argv of every census row and fails if a
  census tool can start through `local_*`.

### Failure modes and fail-closed rules

| Failure | Behavior |
|---|---|
| Proxy cannot start (bind, CA generation) | door fails before the tool starts; no direct-network fallback |
| Confinement unavailable | `unconfined-resolution`: refuse if denied, else run wired-but-unconfined and record |
| Request matches no route and is not interceptable | 403 with a tog body, ledger `refused`; the door fails if the refusal was a policy denial, even when the tool exits 0 (npm tolerates failed optional fetches) |
| Missing or wrong session token | 407/403, ledger entry; never forwarded |
| Upstream bytes do not match the claimed digest | 502 to the tool, nothing cached, the door fails with both digests named; no stale fallback |
| Redirect to a non-permitted origin | refused; credentials never follow a redirect to another origin |
| Upstream address is loopback, private, or link-local | refused (SSRF rule) |
| Transport failure | last-good metadata marked `stale`; otherwise 504 |
| Relay or proxy thread dies | the tool sees connection refused and fails; the door reports the proxy error first |
| Tool exits non-zero | outputs restored from the pre-run backup; the tool's stderr is shown after any proxy refusal, which is usually the real cause |
| An output contains the session token or the proxy address | the door fails and restores the outputs. Byte search for the token (128 random bits) and for `127.0.0.1:<port>`; belt and braces on contract 7 |
| `.git` or `.tog` appeared during the run (Linux, absent before) | door fails; tog does not delete it (the user decides) and names it |
| Ledger or resolution-record write fails | door fails; the outputs are kept, since the tool succeeded, but the error says the resolution is unrecorded and the next sync will not join it |
| tog is killed mid-run | backups stay in a `stage-` directory that `tog gc` sweeps; outputs may be half-written, as today |

Backups: before `run`, the door copies each declared output that exists
into its stage. On failure it restores them through `ProjectRoot` with an
atomic rename, and it removes outputs that did not exist before.

### Performance and caching

- **One proxy per tog process**, started lazily on the first door
  (`OnceLock` in `kernel::resolve`). Startup cost: bind, P-256 keygen and
  a self-signed CA, well under 10 ms. Sessions are per door run, each with
  its own token and ledger, so concurrent doors in one process stay
  separate.
- **Threads, not async.** tog has no async runtime and this does not add
  one. Each accepted connection gets a thread from a bounded pool (64);
  connections beyond that wait in the accept backlog rather than being
  refused, because uv opens up to 50 concurrent downloads by default.
  Upstream uses one shared `ureq` agent with per-host keep-alive. HTTP/1.1
  only, in a strict hand-written subset in `kernel/resolve/http.rs`:
  request line and headers up to 64 KiB, `Content-Length` or chunked but
  never both, no obs-fold, no pipelining.
- **Artifact cache = the existing `cache/sha256`.** When a request has a
  claimed digest (npm `integrity`, PyPI `sha256`, crates `cksum`,
  rubygems compact-index `checksum`, Hex outer checksum), the proxy
  answers from cache on a hit without contacting upstream. On a miss it
  downloads to a stage, verifies, inserts, and then serves: buffer then
  verify, never stream unverified claimed bytes. Artifacts without a claim
  stream through while being hashed, and the hash is recorded.
  Resolution fetches few artifacts (cargo, npm, and Bundler lock without
  downloading), so buffering costs little.
- **Metadata cache** (`<store>/resolve/meta/`, keyed by
  `sha256(method, url, normalized Accept)`, because npm's abbreviated and
  full packuments share a URL): each stored with its ETag or Last-Modified
  and sha256. Online, every metadata request revalidates with a
  conditional GET, which is a 304 when nothing changed. It is a cache
  under the store's GC rules (age-based sweep); losing it costs only
  refetches.
- **No persistent tool caches in the sandbox.** Each run's uv, npm, pnpm,
  cargo, and Bundler caches live in the run's scratch. A writable cache
  shared across projects is a poisoning path (uv caches wheels it built
  from sdists, and a hostile build could plant one), and the proxy cache
  is tog-verified and makes cold tool caches cheap anyway. Go's
  `planner` module cache stays persistent as today: no third-party code
  runs in Go resolution, and tog re-verifies every module it keeps.
- **Budget.** A warm `tog add` through the proxy within 1.2x of today's
  wall time, cold within 1.5x, measured in PR 4 onward on the hit-rate
  projects and reported in each PR. HTTP/1.1 fallback is the likely
  cost for cargo's sparse index. If a PR misses the budget, the fix goes
  in the proxy (connection count, cache hits), never in widening the
  fence.

### Test plan

Offline tests use a fixture upstream: a local HTTP(S) server in
`kernel/testutil` serving a miniature registry per ecosystem from
`tests/fixtures/resolve/<ecosystem>/`, with its own test CA passed as the
proxy's upstream root. Endpoint configuration accepts a loopback upstream
only under `cfg(test)`.

Kernel unit tests (`src/kernel/resolve/`):
- `proxy_refuses_requests_without_the_session_token`
- `proxy_routes_only_to_permitted_endpoints`
- `proxy_refuses_loopback_private_and_link_local_upstreams`
- `proxy_rechecks_every_redirect_hop_and_drops_credentials_across_origins`
- `proxy_strips_tool_authorization_and_cookies`
- `claimed_digest_mismatch_is_a_hard_failure_and_caches_nothing`
- `transport_failure_serves_last_good_metadata_marked_stale`
- `http_4xx_is_passed_through_not_served_stale`
- `offline_mode_serves_cache_only_and_names_the_first_miss`
- `metadata_cache_key_includes_accept`
- `ledger_canonical_bytes_are_stable` (golden)
- `ledger_order_is_independent_of_fetch_order`
- `http_parser_rejects_ambiguous_framing` (CL+TE, obs-fold, oversize headers)
- `interception_mints_leaf_for_sni_host_signed_by_session_ca`
- `connect_without_interception_is_a_visible_refusal`
- `git_scheme_is_refused_as_git_dependency`

Door tests (`src/kernel/resolve/door.rs`):
- `denied_kind_fails_the_door_even_when_the_tool_exits_zero`
- `ledger_only_exceptions_are_recorded_on_the_owner_thread`
- `failed_tool_restores_declared_outputs`
- `output_containing_the_token_fails_and_restores`
- `resolution_record_has_no_timestamps_token_or_port`
- `unconfined_resolution_is_refused_when_denied_and_recorded_otherwise`
- `every_resolver_invocation_goes_through_the_door` (tripwire table vs census)
- `local_supervise_refuses_resolver_programs`

Sandbox tests (`tests/sandbox_deny.rs`, extended, not a new file, per §4):
- `linux_door_reaches_only_the_proxy` (curl to a host-side listener fails,
  to the relay succeeds)
- `linux_door_has_no_dns`
- `linux_door_cannot_write_git_or_tog`
- `linux_door_descendants_die_with_the_relay`
- `macos_door_reaches_only_the_proxy_port`
- `macos_door_cannot_resolve_names` (the mDNSResponder deny)
- `macos_door_cannot_write_git_or_tog`

Join and audit (`tests/cli.rs` and `src/comforter/`):
- `resolution_record_joins_closure_when_outputs_match`
- `stale_resolution_record_is_dropped_not_joined`
- `joined_exceptions_are_not_duplicated_by_sync`
- `audit_denies_unconfined_resolution_under_company_policy`
- `audit_fails_closed_on_an_unknown_resolution_kind`
- `closure_readers_accept_the_resolution_field`

Per ecosystem, offline against fixtures (one per migration PR):
- `go_get_through_mirror_uses_proxied_sumdb`
- `cargo_add_through_interception_keeps_crates_io_source_in_lock`
- `npm_add_through_interception_lock_matches_direct_run` (byte-identical
  lock versus the same npm run against the fixture directly)
- `pnpm_add_through_interception_lock_matches_direct_run`
- `uv_add_through_interception_lock_matches_direct_run`
- `uv_resolution_build_is_recorded_and_no_build_when_denied`
- `bundle_add_through_mirror_keeps_rubygems_remote`
- `bundle_other_source_is_refused_as_unattested_index`
- `mix_deps_update_through_hex_mirror_keeps_signature_check`
- `dotnet_missing_lock_restore_through_nuget_mirror`
- `git_dependency_through_interception_records_commit`
- `npm_url_dependency_is_intercepted_and_recorded`

Network (`--ignored`, run on Linux and the Mac): the ten existing
`deps_e2e` round trips, unchanged in expectations, now running through the
door, plus one live missing-lock generation per ecosystem.

### Implementation plan (PRs, in order)

**PR 0: evidence spike (docs and fixtures only).** For each tool, run the
census invocations through a logging interception proxy and record every
request (host, path, method, redirect chain) in a table in this section.
Confirm each † claim. Capture fixture registries for the offline tests.
Nothing is built on an unconfirmed claim. A † claim that fails changes
that ecosystem's row here first, and a finding that only a mirror works
for an intercept-planned tool means that tool gets response and lock
rewriting designed here before its PR.

**PR 1: the door type, #61 and #169 (moves only, no behavior change).**
Add `kernel::resolve::ResolutionDoor` with a single `Legacy` mode that
runs exactly today's command, unsandboxed and inheriting the environment,
and records nothing new. Route every census row through `door.run`. Add
`Tailor::edit_manifest`, move each delegate from `commands/deps.rs` into
its tailor, move `realize_node_tool` and `verify_corepack_hash` into
`src/tailors/node/`, change `prepare` and `RegistryTool::realize` to take
the door, and add `Tailor::registry_exists`. Add the `local_*` supervise
split, the tripwire, and the clippy entries. This is layering rule 7
("moves are not rewrites"): every golden and every test output stays
identical. After it, #61's grep is empty and every door is in one place.

**PR 2: proxy core.** The HTTP subset, routes and `RegistryProtocol`,
the forward proxy with visible refusal, the ledger, the metadata cache,
the artifact-cache integration, SSRF and redirect rules, the token, and
offline mode. Kernel unit tests against the fixture upstream. No tool
uses it yet.

**PR 3: confinement.** The `Proxy` network mode for both sandbox engines,
the `__resolution-relay` subcommand, the `.git`/`.tog` protection, the
`unconfined-resolution` kind, and the sandbox tests. On the Mac: the
Seatbelt rules and the DNS deny.

**PR 4: Go end to end, and the join.** Switch the Go rows to `Proxied`
mode (mirror plus sumdb). Add the resolution record, the closure join,
the resolution summary in the closure, and the join and audit tests.
Go goes first because it has no code execution, no TLS, and no lock
URLs.

**PR 5: interception.** The session CA, leaf minting, TLS termination
(`rcgen` and rustls server, `ring` provider pinned), and the git row.
Switch cargo (interception plus git).

**PR 6: Node.** npm and pnpm (edit, missing lock, `x`), with the
byte-identical-lock tests.

**PR 7: Python.** uv (edit, missing lock, build requirements, `x`), the
`resolution-build` kind, and `--no-build` under denial.

**PR 8: Ruby and Elixir.** Bundler mirror and Hex mirror, the visible
refusals, and the Ruby gate-1 planner behind a no-route door.

**PR 9: .NET.** The `nuget.config` mirror with service-index rewriting.
Missing-lock restore confined, which closes the LIMITATIONS row
"Restore-time MSBuild evaluation runs unsandboxed".

**PR 10: remove `Legacy`.** Delete the mode. The company template denies
`unconfined-resolution`. ARCHITECTURE gains a "Resolution doors" section
with the census as a covered/not-covered table (WP5's "state which doors
are covered"). LIMITATIONS rows are rewritten: the `add`/`remove`/`update`
row, "Delegated planning runs unsandboxed", the audit paragraph's "does
not cover the doors" sentence, and the .NET restore row. CLI.md documents
the new notes and errors. FOLLOW-UPS "Delegated-tool doors" is deleted
and #68 closed.

Each PR from 3 on runs its ecosystem's `--ignored` tests on the Mac
before merge, and PR 3 also runs `tests/sandbox_deny.rs` there.

### Adversarial self-check

Holes found in the first draft, and where the design above closes each:

1. *"Scrub the user's environment" misses variables nobody listed*
   (`CARGO_REGISTRIES_*`, `UV_*` added in a newer uv, `NODE_OPTIONS`
   `--require`). Fixed: the door's environment starts empty (contract 2).
   Under confinement a leaked setting can only fail to connect. Under the
   unconfined fallback it could open a side door, which is why the company
   template denies that kind.
2. *Project config files re-point the tool* (`.npmrc registry=`,
   `[tool.uv] index-url`, `.cargo/config.toml` `[source]`,
   `.bundle/config`). Under confinement they can only make resolution
   fail, never reach another host. The forced flags exist for correct
   routing, not for security. Parent-directory configs outside the project
   (cargo walks up to `~/.cargo/config.toml`) are not readable in the
   sandbox.
3. *A mirror leaks `127.0.0.1:<port>` into committed locks.* Fixed by
   choosing interception for every tool whose lock records URLs, plus the
   token and address scan of outputs (contract 7).
4. *Sandboxed code uses the proxy as an SSRF pivot* to cloud metadata or
   localhost services. Fixed by the post-resolution address check.
5. *Another local user or process on macOS uses the proxy* (and, after
   WP5, its credentials). Fixed by the per-session token on every request.
6. *Double-counted exceptions* between the proxy and sync's lock-derived
   records. Fixed by the ledger-only split.
7. *The proxy thread records into an attribution it does not own*, which
   `policy::record_with` would refuse at run time. Fixed: the proxy only
   calls `policy::denied`, and the owner thread records.
8. *A tool treats a refused optional fetch as success*, so a policy denial
   is silently swallowed. Fixed: any policy refusal fails the door
   regardless of exit status.
9. *A hostile resolution-time build plants git hooks* for later
   unsandboxed execution. Fixed by read-only `.git` and `.tog`, plus the
   appeared-during-run check on Linux.
10. *DNS as an exfiltration channel.* Linux has no resolver in the
    namespace. On macOS, the blanket `mach-lookup` allow would permit it;
    fixed by the mDNSResponder deny and its named test.
11. *The committed resolution record is forgeable*, since it is a project
    file. It only ever adds exceptions or describes a lock whose digest
    must match. A forged record can at worst make a closure claim a
    resolution happened. Audit makes no admission decision on that claim;
    it judges only the exceptions, and forging can only add those. Stated
    in "What this does not claim".
12. *Stale metadata masks a yanked or security release.* Stale serving
    happens only on transport failure, is recorded per entry, and is
    announced. The bytes are still verified. A company that wants
    "no stale resolution" is an open question below, not silently
    permitted.
13. *Buffering large artifacts stalls resolution.* Few artifacts are
    fetched during resolution; see Performance.
14. *Cross-project poisoning through a shared tool cache.* Fixed: tool
    caches are per run.
15. *A lingering macOS descendant rewrites the lock after tog's checks.*
    It stays inside Seatbelt. A later change breaks the record's output
    digests, so the join drops it. The quiescence gap stays a Backlog item
    and is not claimed closed.
16. *#61 lands before the proxy and bakes in an unconfined signature.*
    Fixed by ordering: PR 1 introduces the door type in the signature from
    day one, in `Legacy` mode, so no later PR changes the trait.
17. *`--no-sync` edits never join.* The record persists in `.tog/resolution/`
    and joins at the next sync if the outputs are unchanged.
18. *Credentials in the project `.npmrc` (`//registry.npmjs.org/:_authToken`)
    reach the proxy.* They are stripped and never forwarded or recorded.
    Private registries use WP5 credential references held by tog.

### Open questions for the owner

- **Stale metadata under company policy.** Should a company be able to
  deny a resolution that used stale metadata (a new kind, say
  `stale-resolution`), or is the ledger note enough? Recommended: the note
  only. Artifacts are verified either way, and a stale lock is an older
  lock, not a less honest one.
- **An admission rule on the resolution record.** A future
  `tog audit` knob could require every lock to carry a joined resolution
  record, which would refuse locks made outside tog. That is #68's option
  2 by another route and changes the agent story. Recommended: not now.
  Revisit after PR 10, with real closures to look at.


---

## 7. Backlog

Unranked. "GC Package B/C/D" means the shipped GC-safety work.

Reviewed 2026-09-09. Items that the GC track or WP2 now subsume are marked;
the rest stand.

| Item | Status after this review |
|---|---|
| M5 hardening: RECORD verification and rewrite, Mach-service allowlist, deployment-target tags, streaming extractors | stands. Streaming extractors connect to the WP2 extractor's architectural finding (read tar headers directly instead of parsing `tar -tv`); do them together |
| Sol review 3 leftovers: dependency-order lifecycle execution and ancestor `.bin` paths; true npm optional-failure parity; planner subprocess sandboxing; process-tree quiescence after install scripts; Xcode/SDK fingerprint in build identity | stands. **Process-tree quiescence overlaps GC Package B**: B's supervisor bounds the awaited direct child; descendants surviving its exit remain outside the guarantee. Do not claim B closes this |
| Store-object content verification on use (same-user replacement is undetected), or an explicitly narrower documented trust boundary | stands, and GC Package D's replacement recheck is *not* this — D checks the deletion candidate, not the object a job is about to use |
| Per-package store objects with copy-on-write assembly | stands; deferred by the "env-level granularity" MVP decision |
| Reproducibility spot-checks (rebuild twice, compare, quarantine mismatches) | stands |
| Bytecode precompilation at realize time | stands |
| Pinned C toolchain as a store object (closes the unpinned host gcc/glibc and Xcode inputs on both platforms) | stands. Recording the current host Xcode/SDK fingerprint can land earlier; a managed C toolchain is the stronger reproducibility follow-up, not a prerequisite to honest fingerprinting |
| Breadth: system packages (CLI tools and libraries first; GUI apps and services are a different product) | stands |
| JVM | deliberately deprioritized |
| Health metric: lines of code per tailor must keep falling, or stop and fix the kernel | stands; measure it again after GC Package C, which adds per-producer code |

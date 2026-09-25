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
delegate path into the Node tailor) are built from it. Revised after Codex
review round 1 (ten findings, all addressed in the design below; the
review is summarized in "Review round 1").

### In plain words

tog verifies every byte it downloads itself. But in a handful of places it
hands the job to the ecosystem's own tool: `tog add lodash` runs npm, a
project with no `Cargo.lock` runs `cargo generate-lockfile`, and so on.
Those tools go to the internet on their own, with the user's full
permissions, and tog sees none of it. Some of them also run project code
while they work (Bundler evaluates the Gemfile, uv may build a package to
read its metadata, `dotnet restore` evaluates MSBuild). `tog audit` cannot
see any of it.

The fix has three parts, and all three are needed:

1. **A fence.** The tool runs in a sandbox, on a private copy of the
   project, and its only network destination is a small web server inside
   the tog process (the proxy). Anything else it tries to reach fails, and
   nothing it writes reaches the real project until tog has checked it.
2. **A gatekeeper with a notebook.** The proxy fetches what the tool asks
   for from the real registry, checks it against policy, checks its
   integrity where the registry published a digest, keeps a copy in tog's
   cache, and writes one line per fetch into a ledger.
3. **A signed receipt.** When the run passes, tog publishes the new
   manifest and lock together with a small record of what happened,
   signed with the same key that signs closures. The next sync copies the
   receipt into the closure, so `tog audit` sees it. A lock without a
   valid receipt is itself a finding a company can deny.

### The contract

When this section is fully built:

1. Every child process tog starts that resolves dependencies with network
   access, or evaluates project code to resolve (the census below), starts
   through one kernel type, the **resolution door**. No other code path can
   start one: a runtime tripwire and a clippy rule refuse it (see "Every
   door goes through the door").
2. The door runs the tool **confined**, on a **socket-free staged snapshot**
   of the lock root. Network reaches only the proxy. The real project is
   read-only to the tool. Nothing the tool writes reaches the project
   except the spec's declared outputs, and only after every check has
   passed. The environment is built from empty, not scrubbed from the
   user's.
3. The proxy forwards only to **permitted endpoints**. It connects only to
   the exact address it validated (never loopback, private, or link-local)
   and never forwards a credential the tool sent.
4. Every request the proxy answers or refuses becomes a **ledger entry**
   with credentials redacted. The ledger is a store object with its own
   identity and kind contract, kept alive by the closure that joins it.
5. Policy is applied **per request, in real time**, with the same
   `policy::Policy` the rest of the run uses. A denied kind is a refused
   request, and a refused request fails the door even when the tool exits
   0.
6. **One transaction.** The door publishes its outputs, the ledger object,
   and the signed resolution record together or not at all. If any step
   fails, the project is left byte-for-byte as it was.
7. **Only attested records enforce.** A resolution record reaches the
   closure only when its signature verifies against the machine policy's
   trusted keys and it matches the files on disk. A lock without such a
   record gets `unrecorded-resolution`, which policy can deny. Deleting,
   replacing, or editing a record therefore cannot remove a finding.
8. The lock the tool writes is **byte-identical** to what the same tool
   writes when it talks to the registry directly. The proxy is invisible in
   every file the user commits, apart from the resolution record itself.
9. **No resolver ever runs without isolation.** Every delegated tool runs
   in the `confined` or `isolated` tier: the native sandbox, a container
   or VM backend, or (Linux) a per-run ephemeral identity. Where none
   exists the command fails naming the missing capability. There is no
   unisolated tier, because even a "resolve-only" tool can be made to run
   a project-chosen program (npm's `git` and `script-shell` settings,
   cargo's `build.rustc-wrapper` and credential providers), so no tool
   class is safe to run as the developer. The door also forces every
   program-naming setting of each tool to a fixed value (see "Forced
   program settings"). Runs without a network fence record
   `unconfined-resolution`, which policy can deny. See "Isolation tiers".
10. **Nothing that outlives the tool is trusted.** The whole tool process
   tree is stopped before validation, and the outputs are validated,
   signed, and published from an immutable copy in the store, never from
   the stage a straggler could still write.

**What this does not claim.** It is cooperative hermeticity plus
provenance, the same claim the build sandbox makes
(`docs/human/LIMITATIONS.md`, "Tog's security claim is provenance").
Sandboxed code can still encode data in the request paths it sends to a
permitted registry. No enforceable design closes that channel while the
tool is allowed to name packages (a package name is attacker-chosen
text), so it is documented. The proxy bounds it: the channel is
only the permitted endpoints, and every such request is in the ledger.

### The doors (census, 2026-09-23)

Every place tog runs an ecosystem tool that resolves with the network or
evaluates project code today. "Kind" is the door kind recorded in the
ledger. "Runs code" is what the tool executes besides itself.

| Site | Tool invocation | Network | Runs code | Kind |
|---|---|---|---|---|
| `tailors/python/inputs.rs` (requirements lock) | `uv pip compile --generate-hashes` | yes | sdist builds for metadata | missing-lock |
| `tailors/python/pypi.rs` (build requirements) | `uv pip compile --no-build` | yes | no | planner |
| `tailors/python/build.rs` `generate_cargo_lock` | `cargo generate-lockfile --manifest-path` for an sdist's Rust extension that ships no `Cargo.lock` (cached by sdist sha256 and Rust id) | yes | no | missing-lock (dependency) |
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
| `tailors/ruby/mod.rs` `plan_ruby` gate 1 | Bundler helper | none (PR 0 confirmed) | Gemfile eval | planner |
| `commands/deps.rs` `ruby_delegate` | `bundle add` / `remove` / `update` | yes | Gemfile eval | edit |
| `tailors/elixir/mod.rs` `plan_elixir` | `mix deps.get`, `mix deps.get --check-locked` | yes | mix.exs eval (git deps' too) | missing-lock / planner |
| `tailors/elixir/mod.rs` lock helper | `elixir` AST parse of `mix.lock` | no | no (never evaluates) | planner (no routes) |
| `commands/deps.rs` `elixir_delegate` | `mix deps.update` | yes | mix.exs eval | edit |
| `tailors/dotnet/mod.rs` `plan_dotnet` | `dotnet restore --use-lock-file` | yes | MSBuild eval | missing-lock |

Not doors: tog's own downloads (`kernel::fetch`, `kernel::gitsrc`, the
`registry_lookup` existence check in `deps`) are tog code with tog
verification. Host-local helpers (`tar`, `getconf`, `id`,
`cargo locate-project --offline`) need no network. A planner row that needs
no network (Ruby gate 1, confirmed by PR 0, and the Elixir lock parser)
still goes through the door with **no routes**, which means full network
denial. That also closes the LIMITATIONS row "Delegated planning runs
unsandboxed with user privileges" for code-evaluating planners.

The sdist `cargo generate-lockfile` row differs from the others: its lock
root is the extracted sdist source in a store stage, not a project, and
its output is the cached generated `Cargo.lock`. It writes a ledger and
no resolution record (there is no project to commit one to). The ledger
object id is retained through the `ClosureRefs` of the Python closure
whose sync ran it, like the other planner doors.

### Per-ecosystem traffic and how each tool is pointed at the proxy

The proxy speaks two dialects on one listener:

- **Forward proxy with TLS interception** ("CONNECT-MITM"). The tool is
  told to use an HTTP proxy. For an `https://` URL it sends
  `CONNECT host:443` carrying `Proxy-Authorization` with the session token.
  The proxy checks the token **once per tunnel**, binds the tunnel to that
  session, answers `200`, terminates TLS with a leaf certificate for
  `host` signed by a per-process tog CA, reads the plain HTTP requests
  inside, and fetches each one upstream itself over real TLS. Requests
  inside an authenticated tunnel carry no token and need none (standard
  clients never add proxy credentials to inner requests). A `CONNECT`
  without a valid token gets `407` and a ledger entry.
- **Registry mirror** (plain HTTP). The tool's registry base URL is set to
  a proxy route (`http://127.0.0.1:<port>/<token>/<route>/`). The token in
  the path authenticates every request. The proxy maps the route to its
  upstream base and fetches over real TLS.

Per ecosystem. PR 0 measured every row on Linux, and the rows carry its
corrections (see "PR 0 evidence" below):

| Ecosystem | Upstream traffic | Mechanism | Wiring | Lock effect |
|---|---|---|---|---|
| Python (uv) | `pypi.org/simple` (PEP 691 JSON / 503 HTML), `files.pythonhosted.org` (`.metadata` for resolution, wheels only for builds), git remotes plus GitHub's `api.github.com` commit lookup and `raw.githubusercontent.com` metadata read, direct-URL requirements, any `[[tool.uv.index]]` | CONNECT-MITM | `HTTPS_PROXY`/`HTTP_PROXY` = `http://tog:<token>@<proxy>`, `NO_PROXY` empty, `ALL_PROXY` removed, `SSL_CERT_FILE` = tog CA file (uv takes it as its whole root set, confirmed by PR 0), default index forced to `https://pypi.org/simple` on every uv invocation (`--index-url` for `pip compile`, `--default-index` for `add`/`remove`/`lock`, a behavior change scheduled in PR 7), and `--python <store python>` on every `uv pip compile` (PR 0: `pip compile` ignores `UV_PYTHON` and builds sdists with the first `python3` on `PATH`) | none: uv sees real URLs, so `uv.lock` and `requirements.lock.txt` record them |
| Node (npm) | `registry.npmjs.org` packuments (full `application/json` in lock-only runs, measured) and tarballs, scoped registries from `.npmrc`, `https:` tarball deps, git deps (git CLI) | CONNECT-MITM | CLI flags (beat project `.npmrc`): `--proxy`, `--https-proxy`, `--noproxy=`, `--registry=https://registry.npmjs.org/`, `--strict-ssl=true`, `--cafile=<tog CA>` (replaces the roots for npm's own requests, confirmed by PR 0), `--update-notifier=false` (PR 0: otherwise npm fetches the 2.4 MB `/npm` packument), `--no-audit` (PR 0: otherwise every install, update, and uninstall POSTs the resolved tree to `/-/npm/v1/security/advisories/bulk`, which is not resolution. The flag is npm's documented switch. PR 0 did not measure it, so the npm door's PR adds a fixture proving no audit request); `NODE_EXTRA_CA_CERTS` = tog CA for any other Node code (this **adds** to Node's built-in roots); `npm_config_*` stripped as today | none: `resolved` URLs are upstream |
| Node (pnpm) | `registry.npmjs.org` abbreviated packuments (no audit, no tarballs in lock-only mode, measured), scoped registries, git deps | CONNECT-MITM | `--config.proxy`, `--config.https-proxy`, and `--config.noproxy=` (PR 0: pnpm 9.15.4 has no `--http-proxy` option, `pnpm remove` rejects `--proxy`, and the `--config.*` spelling works on every verb), `--config.cafile=<tog CA>` (replaces the roots, measured; a `cafile=` line in the XDG config is not read), `NODE_EXTRA_CA_CERTS`; the per-run HOME/XDG stage stays | none |
| Rust (cargo) | `index.crates.io` sparse index (`config.json`, index files), `static.crates.io` crate downloads (the URL comes from `config.json`'s `dl`, so no `crates.io` redirect, measured), alternative registries in `.cargo/config.toml`, git deps plus GitHub's `api.github.com` commit lookup | CONNECT-MITM | `--config http.proxy=...`, `--config http.cainfo=<tog CA>` (PR 0: this **adds** to curl's roots, because curl keeps its default `CApath`; see "What the CA file does and does not prevent"), `--config net.git-fetch-with-cli=true` (so git goes through the git row), `CARGO_HOME` = scratch, `CARGO_NET_OFFLINE=false` | none: `Cargo.lock` records `registry+https://github.com/rust-lang/crates.io-index` whatever the transport |
| Go | `proxy.golang.org` (`/@v/list`, `.info`, `.mod`, `.zip`, `/@latest`, and 404s for the import-path prefixes `go get` probes), `sum.golang.org` lookups and tiles | Registry mirror | `GOPROXY=http://127.0.0.1:<port>/<token>/go/` (no `,direct`), `GOSUMDB=sum.golang.org`. The go command asks `<proxy>/sumdb/sum.golang.org/supported` first. PR 0 found that both `proxy.golang.org` and `sum.golang.org` answer that path with 404, which sends go straight to `sum.golang.org` outside the proxy, so the proxy answers `supported` with 200 itself and forwards `/sumdb/sum.golang.org/<rest>` to `https://sum.golang.org/<rest>` byte-for-byte (go verifies the note signature itself). Also `GOVCS=*:off`, `GOTOOLCHAIN=local`, `GOENV=off`, `GOAUTH=off`, `GOPRIVATE`/`GONOPROXY`/`GONOSUMDB`/`GOINSECURE` empty as today | none: `go.sum` holds hashes only |
| Ruby (Bundler) | `index.rubygems.org` compact index (`/versions`, `/info/<gem>`), `rubygems.org/gems/<name>-<ver>.gem` (only when Bundler installs), other `source` blocks, git gems | Registry mirror for rubygems.org (the route sends `/versions`, `/names`, and `/info/*` to `index.rubygems.org` and the rest to `rubygems.org`); forward proxy without interception (visible refusal) for everything else | the environment variable `BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/=http://127.0.0.1:<port>/<token>/rubygems/` (PR 0: a config file in `BUNDLE_APP_CONFIG` is ignored under tog's `BUNDLE_IGNORE_CONFIG=1`, which stays); `https_proxy`/`http_proxy` = proxy with token. Edits run lock-only: `bundle add <gem> --skip-install` and `bundle lock --update [<gems>]` replace today's `bundle add` and `bundle update`, which install every resolved gem (PR 0 saw the `.gem` downloads; an install builds native extensions, which is third-party code). Measured: both lock-only forms exit 0, download no `.gem`, and install nothing | none: `Gemfile.lock` keeps `remote: https://rubygems.org/` (mirrors are transparent by design, confirmed) |
| Elixir (Hex, mix) | `repo.hex.pm` (`/packages/<name>` signed protobuf, `/tarballs/<name>-<ver>.tar`; `/names` and `/versions` were not fetched), Hex's update check (`/installs/hex-1.x.csv`, a 301 to `builds.hex.pm`), git deps | Registry mirror for Hex; CONNECT-MITM for git | `HEX_MIRROR=http://127.0.0.1:<port>/<token>/hex/`, `HEX_UNSAFE_REGISTRY` removed (Hex keeps verifying the registry signature with its public key), lowercase `http_proxy`/`https_proxy` = proxy with token (PR 0: Hex 2.5.1 has no `HEX_HTTP_PROXY`/`HEX_HTTPS_PROXY`), `MIX_DEPS_PATH` in scratch as today, `HEX_OFFLINE` as today. The update check's `CONNECT builds.hex.pm` is refused visibly, and Hex continues (measured) | none: `mix.lock` records the repo name `hexpm` |
| .NET (NuGet) | `api.nuget.org/v3/index.json` service index, flat container (`index.json`, `.nupkg`), the NuGetAudit vulnerability files (`/v3/vulnerabilities/index.json`, `/v3-vulnerabilities/...`); registration pages exist in the protocol but restore did not read them; no revocation traffic on Linux | Registry mirror (the service index and any registration JSON are rewritten so resource URLs point at proxy routes, and the `RepositorySignatures/*` resources are dropped from the service index, because NuGet requires them over HTTPS and otherwise fails with NU1301); forward proxy without interception (visible refusal) for anything else | tog-written `nuget.config`: `<clear/>` plus one source `http://127.0.0.1:<port>/<token>/nuget/v3/index.json` with `allowInsecureConnections="true"` (confirmed; without it restore fails with NU1302); `NUGET_CERT_REVOCATION_MODE=offline` (harmless, kept for macOS); `HTTPS_PROXY` = proxy with token; `DOTNET_CLI_TELEMETRY_OPTOUT=1`, `DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1`, `DOTNET_NOLOGO=1`, `DOTNET_EnableDiagnostics=0`, `MSBUILDDISABLENODEREUSE=1`, `--disable-build-servers`, `-maxcpucount:1` (no MSBuild worker nodes, so no Unix-socket IPC; confirmed, see "Unix sockets") | none: `packages.lock.json` holds content hashes only. `obj/` output lands in the snapshot and is discarded (declared scratch) |
| git (any ecosystem) | `https://` remotes (smart HTTP: `info/refs?service=git-upload-pack`, `POST git-upload-pack`), `ssh://` and scp-style remotes, `git://` | CONNECT-MITM for https; ssh rewritten to https; `git://` and `ext::` refused | `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`, and every forced git setting (see "Forced program settings") carried in `GIT_CONFIG_COUNT`/`KEY`/`VALUE`, because the tools, not tog, start git: `http.proxy`, `http.sslCAInfo`, `url.https://<host>/.insteadOf` for `ssh://git@<host>/` and `git@<host>:` (confirmed), and the `protocol.*.allow` set with `protocol.file.allow=always` (uv clones git dependencies from its own local database with `file://`). git sends its first `CONNECT` without credentials, so the proxy's 407 carries `Proxy-Authenticate: Basic` | the commit id the tool locks |

#### Which tools cannot be fully proxied, and what happens then

"Fully proxied" means the proxy can see and record every byte. Each gap
has a concrete answer:

- **Go and .NET on macOS cannot be taught a private CA.** Go on darwin
  verifies through the platform verifier and ignores `SSL_CERT_FILE`, and
  .NET on macOS uses the Keychain. tog will not modify the user's Keychain.
  Answer: both use the registry-mirror dialect, which needs no TLS between
  tool and proxy, on both platforms (one mechanism per ecosystem, not per
  platform). Their only registry traffic goes through the mirror. Any
  other traffic (a .NET workload advertising-manifest check, telemetry)
  goes to the proxy as a `CONNECT`, because `HTTPS_PROXY` is set. The proxy
  refuses it with a ledger entry naming the host instead of letting it
  hang on a denied socket. If the tool fails because of that refusal,
  tog's error names the host and the reason.
- **Ruby sources other than rubygems.org.** Sync already fails closed on
  them (LIMITATIONS, Ruby). The proxy agrees: Bundler reaches them through
  `CONNECT`, the proxy refuses without interception and records
  `unattested-index` for the host, and the edit fails with the same
  sentence sync uses. When WP5 private-registry support arrives, a
  permitted Ruby source becomes a second mirror route and needs no new
  mechanism.
- **Hex beyond `repo.hex.pm`** (private organizations at
  `repo.hex.pm/repos/<org>`, other repos): the same visible `CONNECT`
  refusal until WP5 adds credentials. Hex organization access is a
  credentialed route, not a TLS problem.
- **`git://` remotes** (unencrypted, unauthenticated, port 9418): refused
  under every policy with "git:// is unauthenticated; use https://". The
  ledger records the refusal with kind `git-dependency`.
- **SSH git remotes with private keys.** The sandbox has no `~/.ssh` and no
  agent socket, on purpose. The `insteadOf` rewrite serves public
  repositories over https. A private repository needs a WP5 credential
  reference that the proxy attaches upstream. Until then the fetch fails
  with the host named. The tool never holds the credential.
- **Direct-URL dependencies** (npm `https:` tarball specs, PEP 508
  `name @ https://...`): fully proxied for npm and uv by interception, and
  recorded as `unattested-index` when the host is not a permitted
  endpoint (see policy mapping). Cargo, Go, Bundler, Hex, and NuGet have no
  arbitrary-URL dependency form.
- **Tools that ignore proxy settings for some traffic.** Whatever is not
  routed fails against the sandbox, which is the fail-closed outcome. PR 0
  records which requests those are. The fix is always to route them, never
  to open the fence.

### PR 0 evidence (Linux, measured 2026-09-23)

**How it was measured.** `tools/proxy_spike/` runs every census
invocation through a logging mitmproxy (12.2.3) that speaks both dialects
on one listener, with the session token checked on `CONNECT` and in the
mirror path. Each run is confined the way the door will be: bubblewrap
(0.12.0) with `--unshare-net --unshare-pid --clearenv`, the host root
read-only, fresh `/tmp` and `/run`, and an in-sandbox relay on
`127.0.0.1:8119` spliced to the proxy's Unix socket at
`/run/tog/proxy.sock`. The tool runs under `nounix.c`, a seccomp filter
built to this section's rules: arch check (kill otherwise), x32 refused,
`socket(AF_UNIX)` refused with `EAFNOSUPPORT`, `io_uring_*`, `ptrace`, and
`process_vm_*` refused with `EPERM`. strace (7.2) counts every AF_UNIX
attempt and `io_uring_setup` call. Host: Fedora 44, kernel 7.2.5, x86_64.
Toolchains are tog-provisioned from a scratch store built by
`cargo build --release`: uv 0.12.7 with CPython 3.12.14, Node 24.20.0 with
npm 11.19.0, pnpm 9.15.4, cargo 1.96.1, go 1.27.0, Ruby 3.4.6 with Bundler
2.6.9, OTP 29.0.5 with Elixir 1.20.4 and Hex 2.5.1, .NET SDK 9.0.317, and
the host's git 2.55.0. To rerun:
`python3 tools/proxy_spike/spike.py --work <dir> --store <store> --record census`,
then `forced`, then `fixtures`.

**Where the evidence lives.** `tests/fixtures/proxy/census/` holds every
request (`requests.jsonl`), every run's argv, exit code, AF_UNIX and
io_uring counts (`runs.jsonl`), every claim with its evidence
(`claims.jsonl`), and the marker results (`forced.jsonl`), with the
session tokens and local paths redacted. `tests/fixtures/proxy/registry/<ecosystem>/`
holds the recorded upstream responses (one body per URL, stored as
`<host>/<path>.body`, listed in `index.json` with status, headers, and
sha256). Bodies over 256 KiB, and npm's update-notifier packument, are
listed with their digest but not stored. Rubygems' `/versions` is cut to
the gems the census used. `tests/fixtures/proxy/forced/<tool>/` holds the
marker-program fixtures (see "Forced program settings").

**Every request the census made.** Names in angle brackets stand for the
package, version, or hash of the run. "Mirror" rows are what the proxy
fetched upstream for a mirror route. Only one redirect happened in the
whole census, Hex's update check (row marked). No tool followed a
redirect to another host through the mirror, and no tool fetched from a
CDN host other than the ones listed.

| Ecosystem | Dialect | Method | Host | Path | Status | When |
|---|---|---|---|---|---|---|
| Python (uv) | intercept | GET | `pypi.org` | `/simple/<name>/` (PEP 691 JSON) | 200 | every resolution |
| Python (uv) | intercept | GET | `files.pythonhosted.org` | `/packages/<h>/<h>/<h>/<wheel>.whl.metadata` (PEP 658) | 200 | every resolution. No wheel or sdist is downloaded to resolve |
| Python (uv) | intercept | GET | `files.pythonhosted.org` | `/packages/<h>/<h>/<h>/<wheel>.whl` | 200 | only when a build ran: a git dependency (`uv add git+https://...` built it with hatchling and setuptools-scm) or a dynamic-metadata member |
| Python (uv) | intercept | GET | `api.github.com` | `/repos/<owner>/<repo>/commits/<ref>` | 200 | git dependency on GitHub (uv resolves the ref first) |
| Python (uv) | intercept | GET | `raw.githubusercontent.com` | `/<owner>/<repo>/<commit>/pyproject.toml` | 200 | git dependency on GitHub (uv reads static metadata without cloning) |
| Python (uv) | intercept | GET, POST | `github.com` | `/<owner>/<repo>/info/refs?service=git-upload-pack`, `/git-upload-pack` | 200 | git dependency (git CLI, see the git row) |
| npm | intercept | GET | `registry.npmjs.org` | `/<name>` (full `application/json` packument, not the abbreviated form) | 200 | resolution |
| npm | intercept | GET | `registry.npmjs.org` | `/<name>/-/<name>-<version>.tgz` | 200 | a lock-only install with a git dependency in the tree |
| npm | intercept | POST | `registry.npmjs.org` | `/-/npm/v1/security/advisories/bulk` | 200 | **every** `install`, `update`, and `uninstall` (npm audit sends the resolved tree) |
| npm | intercept | GET | `registry.npmjs.org` | `/npm` (2.4 MB, abbreviated) | 200 | update notifier, once per cache |
| npm | intercept | GET, POST | `github.com` | smart HTTP as above | 200 | git dependency |
| pnpm | intercept | GET | `registry.npmjs.org` | `/<name>` (abbreviated `application/vnd.npm.install-v1+json`) | 200 | resolution. No audit, no tarballs in lock-only mode |
| cargo | intercept | GET | `index.crates.io` | `/config.json` | 200 | every run |
| cargo | intercept | GET | `index.crates.io` | `/<prefix>/<name>` (sparse index file) | 200, or 304 with a warm `CARGO_HOME` | resolution |
| cargo | intercept | GET | `static.crates.io` | `/crates/<name>/<version>/download` | 200 | `cargo metadata` (the attest check downloads every crate to read its manifest). The URL comes from `config.json`'s `dl`, so there is no `crates.io` redirect |
| cargo | intercept | GET | `api.github.com` | `/repos/<owner>/<repo>/commits/<ref>` | 200 | git dependency on GitHub |
| cargo | intercept | GET, POST | `github.com` | smart HTTP as above | 200 | git dependency (`net.git-fetch-with-cli=true`) |
| Go | mirror `go` | GET | `proxy.golang.org` | `/<module>/@v/list`, `/@v/<v>.info`, `.mod`, `.zip` | 200 | resolution and `download` |
| Go | mirror `go` | GET | `proxy.golang.org` | `/<path prefix>/@v/list`, `/@v/<v>.info` | 404 | `go get` probes each shorter prefix of the import path. The mirror passes 404 through unchanged (go reads it as "not a module") |
| Go | mirror `go` (answered by the proxy) | GET | none | `/sumdb/sum.golang.org/supported` | 200 | once per go command. Both `proxy.golang.org` and `sum.golang.org` answer 404 here, so the proxy answers itself |
| Go | mirror `go` | GET | `sum.golang.org` | `/lookup/<module>@<v>`, `/tile/8/<level>/<n>[.p/<width>]` | 200 | checksum verification (from `/sumdb/sum.golang.org/<rest>`) |
| Ruby (Bundler) | mirror `rubygems` | GET | `index.rubygems.org` | `/versions` | 200, then 304 with a warm cache | resolution |
| Ruby (Bundler) | mirror `rubygems` | GET | `index.rubygems.org` | `/info/<gem>` | 200 | resolution |
| Ruby (Bundler) | mirror `rubygems` | GET | `rubygems.org` | `/gems/<name>-<version>.gem` | 200 | only today's `bundle add` and `bundle update`, which **install** what they resolve (see the Ruby row) |
| Elixir (Hex) | mirror `hex` | GET | `repo.hex.pm` | `/packages/<name>` (signed) | 200 | resolution. `/names` and `/versions` were never fetched |
| Elixir (Hex) | mirror `hex` | GET | `repo.hex.pm` | `/tarballs/<name>-<version>.tar` | 200 | `mix deps.get` fetches every tarball (it is not lock-only) |
| Elixir (Hex) | mirror `hex` | GET | `repo.hex.pm` | `/installs/hex-1.x.csv` | **301** to `https://builds.hex.pm/installs/hex-1.x.csv` | Hex's update check. With no proxy variable set Hex cannot follow it and continues (exit 0). With `http_proxy` set it sends `CONNECT builds.hex.pm:443`, which the door refuses, and Hex still continues |
| .NET (NuGet) | mirror `nuget` | GET | `api.nuget.org` | `/v3/index.json` (rewritten) | 200 | every restore |
| .NET (NuGet) | mirror `nuget` | GET | `api.nuget.org` | `/v3-flatcontainer/<id>/index.json`, `/v3-flatcontainer/<id>/<v>/<id>.<v>.nupkg` | 200 | resolution. No registration pages were read |
| .NET (NuGet) | mirror `nuget` | GET | `api.nuget.org` | `/v3/vulnerabilities/index.json`, `/v3-vulnerabilities/<stamp>/vulnerability.base.json`, `.../vulnerability.update.json` | 200 | NuGetAudit, on by default in SDK 9 |
| git | intercept | CONNECT | `github.com:443` | none | **407**, then 200 | git's first `CONNECT` carries no credentials. It retries with the URL's userinfo only after a 407 with `Proxy-Authenticate: Basic` |
| git | intercept | GET, POST | `github.com` | `/<owner>/<repo>/info/refs?service=git-upload-pack`, `/<owner>/<repo>/git-upload-pack` | 200 | `ls-remote`, `clone`, and the rewritten `ssh://` and scp-style URLs |

No certificate-revocation, OCSP, telemetry, or workload-manifest request
appeared for any tool on Linux. `git://` and `ext::` URLs were refused by
git's `protocol.*.allow` before any traffic.

**Every census tool runs under the filter.** 176 confined runs (census and
marker fixtures) ran under the seccomp filter, and every run that should
succeed did (the failures are the negative controls, such as a drifted
lock under an attest check). Node (npm and pnpm) calls `io_uring_setup` 3 or 4 times per
run, gets `EPERM`, and falls back. No other tool touched io_uring. Two
tools create AF_UNIX sockets, and both tolerate the refusal: Elixir's glibc
resolver tries systemd-resolved's varlink socket
(`/run/systemd/resolve/io.systemd.Resolve`, from Fedora's `nsswitch.conf`)
3 times per run, and .NET creates 1 or 2 without connecting them, with or
without the IPC settings in its row. No census tool needs an exception to
layer 3 of "Unix sockets".

**The † claims.**

| Claim | Result | Change made in this section |
|---|---|---|
| bwrap brings up the namespace's loopback | confirmed (`lo` is UP) | none |
| uv: `SSL_CERT_FILE` is the whole root set, and the proxy path needs it | confirmed (a direct fetch with only the tog CA fails, the proxied fetch without it fails) | none |
| uv: the `--no-build` error form | confirmed, two forms (below) | "resolution-build" step 2 names both |
| uv: `--no-build-package <member>` exempts a workspace member | **refuted**: it forbids that build too | "resolution-build" step 3 uses a member-metadata pre-step instead |
| npm: `--cafile` replaces the roots | confirmed | none |
| pnpm: `--http-proxy`, `--https-proxy`, `--no-proxy`, and "pnpm ignores `--config.proxy`" | **refuted**: `--http-proxy` is an unknown option, `pnpm remove` rejects `--proxy`, and pnpm honors `--config.proxy`, `--config.https-proxy`, and `--config.noproxy` on every verb | pnpm row |
| pnpm: `cafile` in the XDG config | **refuted**: a `cafile=` line there is not read. `--config.cafile=<tog CA>` works and replaces the roots. An inline `ca=` in the XDG config and `NODE_EXTRA_CA_CERTS` also work | pnpm row |
| cargo: `http.cainfo` replaces curl's roots | **refuted**: curl keeps its default `CApath` (`/etc/pki/tls/certs` on Fedora), so a direct fetch still succeeds. It **adds**, like `NODE_EXTRA_CA_CERTS` | cargo row and "What the CA file does and does not prevent" |
| git: `http.sslCAInfo` replaces the roots | confirmed | none |
| Go: the proxy serves `/sumdb/sum.golang.org/...` | confirmed with a correction: the proxy must answer `supported` itself | Go row |
| Bundler: the mirror in a config file in `BUNDLE_APP_CONFIG` | confirmed with a correction: tog's `BUNDLE_IGNORE_CONFIG=1` makes Bundler ignore that file. The environment variable `BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/` works, and `Gemfile.lock` keeps `remote: https://rubygems.org/` | Ruby row |
| Hex: `HEX_MIRROR` | confirmed | none |
| Hex: `HEX_HTTP_PROXY` and `HEX_HTTPS_PROXY` | **refuted**: Hex 2.5.1 has no such variables (its source names none). It reads lowercase `http_proxy` and `https_proxy`, and `HEX_CACERTS_PATH` for a CA | Elixir row |
| NuGet: an `http://` source with `allowInsecureConnections="true"` | confirmed with a correction: the rewritten service index must also drop the `RepositorySignatures/*` resources, or restore fails with NU1301. Without the attribute restore fails with NU1302 | .NET row |
| NuGet: `NUGET_CERT_REVOCATION_MODE=offline` | confirmed harmless. No revocation traffic appeared with or without it on Linux | none |
| .NET: no Unix-socket IPC with the listed settings | confirmed. Restore also passes without them | none |
| "No resolver in the census uses io_uring" | **refuted** for Node, harmless (above) | "Unix sockets" wording |
| Lock checks for `tog attest` | confirmed for all eight (see "Attestation") | none |
| Ruby gate 1 needs no network | confirmed (helper check with no proxy settings: exit 0, no request) | census row |
| Forced program settings | confirmed for npm, cargo, uv, go, Bundler, mix, dotnet. **Refuted** for pnpm (two more settings run programs) and git (a repository's `protocol.ext.allow=always` beats `protocol.allow=never`) | "Forced program settings" |
| Seatbelt `localhost:<port>` rule and the Mach allow-list | **pending: needs a macOS host** | "Mach services" |

### TLS: which of the three designs, per ecosystem

The three options:

1. **HTTP CONNECT tunnel, no interception.** The proxy sees only
   `host:port` and an encrypted byte stream. It can allow or deny a host
   but cannot record a URL, a digest, or a package. Rejected as the
   recording mechanism: it cannot answer "what did the tool fetch". Kept
   as the **refusal detector** for traffic an ecosystem should not produce
   (rows ".NET" and "Ruby" above): the tool announces the host, and the
   proxy says no with a reason.
2. **Local HTTPS with a tog-generated CA (interception).** The proxy sees
   full requests. The tool must trust the CA. Chosen for **uv, npm, pnpm,
   cargo, and git**. Their locks record upstream URLs (`resolved` in
   `package-lock.json`, `source`/`url` in `uv.lock`), and a mirror would
   put `http://127.0.0.1:...` into them. Undoing that means rewriting
   registry responses on the way in and lock files on the way out: two
   format-specific transforms on security-relevant files, each a place for
   a mistake. With interception the tool talks to the real URLs and the
   lock comes out byte-identical (contract 8), which is also a directly
   testable property. All five tools take a CA file through an environment
   variable or flag on both platforms (Node bundles its own OpenSSL, uv and
   cargo use their own TLS stacks, git uses `http.sslCAInfo`). PR 0
   confirmed each one on Linux: uv `SSL_CERT_FILE`, npm `--cafile`, pnpm
   `--config.cafile`, cargo `http.cainfo`, git `http.sslCAInfo`.
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
system and user trust stores are never touched. New dependencies: `rcgen`
(certificate building, `ring` backend) and the server half of `rustls`,
which `ureq` already pulls in at 0.23. The proxy PR pins rustls's `ring`
provider explicitly. Upstream TLS (proxy to registry) is tog's existing
`ureq`/rustls client with webpki roots, plus WP3's company roots when
WP3 PR 1 lands.

**What the CA file does and does not prevent.** For uv (`SSL_CERT_FILE`),
git (`http.sslCAInfo`), npm's own requests (`--cafile`), and pnpm's own
requests (`--config.cafile`), the file **replaces** the root set, so those
clients cannot complete a handshake with anything but the proxy (PR 0
measured each: a direct fetch with only the tog CA fails). Cargo's
`http.cainfo` does not: PR 0 found that cargo's curl keeps its default
`CApath` (`/etc/pki/tls/certs` on Fedora), so a direct fetch with the tog
CA still succeeds, and the file **adds**. `NODE_EXTRA_CA_CERTS` also
**adds** to Node's built-in roots, so any other Node code (a script that
ran anyway) can still make a directly trusted TLS connection. Cargo is in
the same position. Under confinement this does not matter, because the network
reaches only the proxy. Without a network fence (the `isolated` tier
below) it does: **Node without a fence is treated as capable of direct
trusted TLS**, and so is every other unfenced tool. That is why
unfenced runs record `unconfined-resolution` and why the recording
guarantee applies only to the `confined` tier.

**ALPN.** The interception server offers only `http/1.1`. Tools that
prefer HTTP/2 (cargo's sparse index, uv) fall back to parallel HTTP/1.1
connections. The cost is in "Performance".

### Confinement

The door is a third sandbox mode beside "no network" builds: network =
`Proxy`. It uses the same `kernel::sandbox` engines and their existing
rules (canonical roots, `--clearenv`), and adds four things: a staged
snapshot, the proxy bridge, Unix-socket denial, and output checking.

#### The staged snapshot (the real project is never writable)

Before the tool starts, the door builds a **snapshot** of every tree the
tool reads from the project side, in a 0700 store stage with an
unguessable name:

- the lock root (the project, or the workspace root for Cargo and pnpm),
  and
- each declared extra read root that is not a store object (an
  out-of-root Cargo `path =` dependency, an npm `file:` target, a uv path
  source), placed at the same path relative to the lock root.

The snapshot copies only regular files, directories, and symlinks. Unix
sockets, FIFOs, and device nodes are omitted, so the snapshot is
**socket-free by construction**. Files are cloned rather than copied where
the filesystem allows it (`clonefile` on APFS, `FICLONE` reflink on
btrfs and XFS), otherwise copied. Each tailor names the heavy build outputs
that are not resolution inputs, and those are left out (`target/`,
`_build/`, `bin/` and `obj/` for .NET, `.venv`, `node_modules`; the last
two are symlinks into the store anyway). `.git` **is** included, because
dynamic-version build backends (setuptools-scm) read it. It is included
as a copy, so a change to it is a diff like any other. While building the
snapshot, the door records a **baseline manifest**: path, type, mode,
and, for a regular file, the SHA-256 of its contents (for a symlink, its
target string) for every entry. The digests are computed from the bytes
the door itself wrote into the stage, so building the manifest costs one
extra read of data already in the page cache.

The tool runs on the snapshot:

- **Linux:** bwrap binds each snapshot tree **at the real path** (`--bind
  <stage>/root <lock_root>`, and likewise for each extra root), so every
  absolute and relative path the tool sees is the real one, and the real
  project is not mounted at all.
- **macOS:** Seatbelt cannot remap paths, so the tool runs at the stage
  path. Relative paths still resolve, because extra roots sit at the same
  relative position. The output checks (below) fail the door if a
  declared output contains the stage path, which is how an absolute-path
  leak into a lock would show up. Seatbelt denies writes everywhere except
  the stage and scratch, and denies reads of the real project.

After the tool exits and the tree is stopped, the **diff** is computed
from the baseline by content: an entry added, removed, changed in type
or mode, whose symlink target changed, or whose contents hash to a
different digest has changed. Timestamps are never consulted. (A ctime
or mtime rule misses a same-second rewrite on a filesystem with coarse
timestamps and flags a no-op rewrite as a change. A digest has neither
problem.) The walk never follows a symlink, and it opens each file with
the same no-symlink rule as the output copy below. Each changed path is
classified by the spec:

- a **declared output** (`package.json`, `package-lock.json`, ...): kept
  for publication, but only if it is a **regular file**. A declared output
  that is now a symlink, a directory, a FIFO, or any other type fails the
  door, naming the path. So does any declared output whose parent
  directory inside the stage became a symlink,
- **declared scratch** (per tool: .NET `obj/`, uv's `.venv` if created):
  discarded,
- anything else, **including a new `.git`, a changed `.git/hooks/*`, or any
  file under `.tog`**: the door fails, names the paths, and publishes
  nothing.

Because the real project was never mounted writable, "fails" means that
nothing happened to it. No restore step is needed for the tool's writes,
and a newly created `.git` never reaches the real tree.

**Publication** happens only after the tree is stopped, the diff and the
output checks have passed on the immutable output copy, and the ledger
has committed (see "The transaction"). Each target is swapped in
atomically and the displaced bytes are compared with the pre-run digest.
If the user edited `package.json` during the run, the swap is reversed
and their edit is kept.

**Cost.** Cloning is near-instant on APFS, btrfs, and XFS. On ext4 the
copy is proportional to the source tree minus the excluded outputs,
typically well under a second for application repositories. The budget in
"Performance" covers it, and a tailor that finds a heavy input tree adds
it to its exclusion list only if its tool provably does not read it.

#### The proxy bridge

**Linux (bubblewrap).** `--unshare-net` as for builds gives the tool a
network namespace whose only interface is its own loopback, which bwrap
brings up (PR 0 confirmed: `lo` is UP). The host proxy is not reachable there, so the bridge is a Unix
socket:

1. The proxy listens on a Unix socket in a 0700 session directory under
   `$XDG_RUNTIME_DIR` (else the temp dir). The path is kept short, under
   the 108-byte `sun_path` limit.
2. bwrap binds that one socket file at `/run/tog/proxy.sock`, and binds
   the running tog executable (`/proc/self/exe`, resolved before the
   sandbox starts) read-only at `/run/tog/tog`.
3. The sandbox's first process is `tog __resolution-relay
   /run/tog/proxy.sock 127.0.0.1:8119 -- <tool argv>`, a hidden
   subcommand. It listens on the fixed port inside the private namespace,
   connects the Unix socket once per accepted TCP connection and splices
   the two, spawns the tool (with the seccomp filter below installed in
   the child before `exec`), and exits with the tool's status. The fixed
   port keeps every proxy URL identical from run to run.
   `--die-with-parent` and the PID namespace end every descendant when the
   relay exits, so nothing outlives the door on Linux.
4. No DNS exists in the namespace (`/etc/resolv.conf` is not bound, and no
   resolver is reachable). The tool never needs one because every proxy
   URL uses a literal IP.

**macOS (Seatbelt).** There is no network namespace. The proxy listens on
`127.0.0.1:<ephemeral>`, bound by tog before the tool starts so nothing
else can hold the port. The profile keeps `(deny network*)` and adds
`(allow network-outbound (remote ip "localhost:<port>"))`† (pending: needs a
macOS host, measured by the same run as the Mach allow-list). Other local
processes can reach the TCP port during the run, which is why every
tunnel and every mirror request must carry the session token. Seatbelt
applies to every descendant. Stragglers are handled by "Quiescence and
the immutable output copy" below.

**Mach services are denied by default.** A Mach service is a system
daemon a process talks to by name through `mach-lookup` instead of a
socket, and many of them do work on the caller's behalf **outside** the
sandbox. The build profile allows `mach-lookup` wholesale, which is an
escape for the door: `/usr/bin/open` reaches LaunchServices and can start
any app or open any URL in the user's browser, `nsurlsessiond` performs
downloads and uploads for the caller, `securityd` and the Keychain
services hand out credentials, and `mDNSResponder` resolves (and so
sends) names. Blocking a few names after a blanket allow leaves every
other service open. So the door profile does not start from the build
profile's Mach rule. It starts from `(deny mach-lookup)` and adds
`(allow mach-lookup (global-name ...))` only for the services each tool
is measured to need. PR 0 records that per-tool allow-list by running
every census invocation under a profile that logs denied lookups
(`(deny mach-lookup (with report))`)† and then iterating to the smallest
set that passes. **Pending: needs a macOS host.** It cannot be measured on
Linux. The procedure is ready to run from the repository root on a Mac:
`tools/proxy_spike/macos_mach.sh [work dir]` builds tog, provisions every
census toolchain into a scratch store, installs mitmproxy in a venv, runs
the census through `spike.py --engine seatbelt` (each run under
`sandbox-exec` with the reporting profile from
`tools/proxy_spike/mach_report.py`, reading denials with `log show` and
rerunning with them allowed until the tool passes), and prints the table
and per-ecosystem union for this section. It exits non-zero if a run
failed or a list names a forbidden service. The door's macOS rows ship
only after that table is pasted here. The list lives beside the tool's row in
`kernel::resolve` and is expected to be small: the system logging
service (`com.apple.logd`), `com.apple.system.notification_center`, and
the directory-services lookup for the user's own record
(`com.apple.system.opendirectoryd.libinfo`), which libc needs for
`getpwuid`. PR 0 fails any tool whose measured list includes a service
that acts for the caller outside the sandbox (LaunchServices
`com.apple.coreservices.*` and `com.apple.lsd.*`, `com.apple.nsurlsessiond`,
`com.apple.securityd` and `com.apple.SecurityServer`, the Keychain
services, `com.apple.dnssd.service`, `com.apple.mDNSResponder`, the
pasteboard, and the Apple Events services). Such a tool's row has to be
configured off that service before the door ships for it. The named
tests `macos_door_cannot_open_urls_or_apps` and
`macos_door_cannot_reach_nsurlsessiond` run a fixture inside the door
that tries each, and `macos_door_cannot_resolve_names` covers DNS.

#### Unix sockets: no connection to any host socket

A Unix socket is a network door the network namespace does not close. A
resolver that can `connect(2)` to a host socket (a Docker socket, an SSH
agent, a D-Bus session bus) bypasses both the namespace and the ledger.
Three layers close it on Linux:

1. **Socket-free snapshot.** Every project-side tree is the snapshot
   above. No host project tree is mounted.
2. **Every other mounted root is scanned and refused.** Store objects, tool
   objects, and the system roots bound by `system_root_args` are scanned
   before mounting, and a socket anywhere in them refuses the door, naming
   the path. (Today's sandbox scans writable roots only; see
   `src/kernel/sandbox.rs` module docs. The door scans every root.) Store
   object scans are cached per object id in the object's metadata, since
   objects are immutable. `/run/tog` holds only tog's own socket, and
   `/tmp` and `/dev` are fresh.
3. **A seccomp filter denies creating Unix sockets.** The relay installs
   a filter in the tool's process before `exec`, inherited by every
   descendant: `socket(AF_UNIX, ...)` fails with `EAFNOSUPPORT`.
   `socketpair(2)` stays allowed, because libuv (Node) and Python's
   asyncio use it for child-process pipes, and a socketpair cannot reach
   a named socket. This layer covers a socket that appears in a mounted
   root **after** the scan: it cannot be connected to, because nothing in
   the tree can create the socket to connect with. The relay is outside
   the filter (it installs it in the child), so the proxy bridge keeps
   working.

   Three details keep the filter from being sidestepped:
   - **The architecture is checked first.** The filter's first
     instruction loads `seccomp_data.arch` and kills the process
     (`SECCOMP_RET_KILL_PROCESS`) unless it equals the build's native
     `AUDIT_ARCH_*` value. Otherwise a process could switch to another
     syscall table (32-bit `int 0x80` on x86-64, where the `socket`
     number differs and `socketcall(2)` multiplexes it) and create the
     socket under a number the filter does not match. On x86-64 the
     filter also refuses syscall numbers with the x32 bit
     (`__X32_SYSCALL_BIT`) set.
   - **`io_uring_setup` is denied** (`EPERM`), along with
     `io_uring_enter` and `io_uring_register`. An io_uring ring submits
     socket and connect operations that never pass through the seccomp
     check, so a ring would bypass every rule above. PR 0 found that Node
     (npm and pnpm) calls `io_uring_setup` 3 or 4 times per run. libuv
     falls back to its thread pool on `EPERM`, and every Node run passed.
     No other census tool calls it.
   - **The relay is not dumpable.** The relay calls
     `prctl(PR_SET_DUMPABLE, 0)` before it spawns the tool. The tool runs
     as the same user in the same PID namespace, and without this it
     could `ptrace` the relay or open `/proc/<relay>/mem` and make the
     unfiltered relay create sockets for it. A non-dumpable process
     cannot be traced or have its memory opened by an unprivileged
     process of the same user. The exec log's user-notification listener
     lives in the relay too, so this also protects the log. The filter
     additionally denies `ptrace`, `process_vm_readv`, and
     `process_vm_writev` to the tool tree.

Tools that need named Unix-socket IPC among their own processes are
configured not to: .NET gets `DOTNET_EnableDiagnostics=0`, no build
servers, and no MSBuild worker nodes (table above). PR 0 ran every census
invocation under the filter and every tool passed (see "PR 0 evidence").
The AF_UNIX attempts it saw are tolerated: Elixir's glibc resolver trying
systemd-resolved's socket, and .NET creating one or two sockets it never
connects. If some tool cannot be configured
off AF_UNIX, that tool's door keeps layers 1 and 2, and the named
test for layer 3 is replaced by one proving every mounted root is either
a snapshot or an immutable store object. The design names that exception
in the tool's row before merging.

**macOS.** Seatbelt's `(deny network*)` covers Unix-socket connections
(`network-outbound` with a `remote unix-socket` filter), and the door
profile allows only the proxy's TCP port. So a host socket is unreachable
whether or not it exists at scan time. The same two tests run there.

#### Quiescence and the immutable output copy

A process the tool started can outlive it (a daemon, a double fork) and
keep writing the stage while tog diffs, hashes, signs, and publishes.
Two measures close that window, on both platforms:

1. **Stop the whole tree before validation.**
   - *Linux:* the tool runs in bwrap's PID namespace. When the tool
     exits, the relay sends `SIGKILL` to every other process in the
     namespace (it enumerates `/proc` inside the namespace) and exits.
     bwrap's init then exits, which kills anything left, and the door
     waits for bwrap to be reaped. No process of the tree survives, and
     none can escape a PID namespace. The container backend gets the same
     result by removing the container.
   - *macOS:* there is no PID namespace, and children stay in tog's
     process group (§5, guarantee 4), so the door cannot kill a group it
     shares. It freezes and kills the tree instead. After the tool exits,
     or on timeout, it walks the descendants of the tool's pid with
     `proc_listchildpids` and sends each `SIGSTOP`. It repeats the walk
     until two walks in a row find no new pid, then sends `SIGKILL` to the
     frozen set. It also kills every same-uid process whose
     `proc_pidinfo` parent chain leads to a pid first seen in the tree
     (this catches processes reparented to `launchd`, because the door
     keeps the set of pids it has observed). A `setsid` double fork that
     escapes between two walks is the one case the walk can miss, and
     the next measure makes it harmless. Such a process also stays inside
     Seatbelt: it can write only the stage, reach only the proxy port
     (which closes when the session ends), and look up only the Mach
     services on the tool's measured allow-list, none of which acts for
     it outside the sandbox.
2. **Validate and publish from an immutable copy.** Once the tree is
   stopped, the door copies each declared output from the stage into a
   store stage owned by tog. It opens each output relative to a held
   descriptor for the stage directory, never by a path string: on Linux
   with `openat2(stage_fd, rel, O_RDONLY|O_NOFOLLOW, RESOLVE_BENEATH |
   RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`, and on macOS by walking
   one component at a time with `openat(dirfd, component,
   O_NOFOLLOW|O_DIRECTORY)` and opening the last with `O_NOFOLLOW`. Then
   `fstat` on the open descriptor must report a regular file, else the
   door fails naming the path. So a tool that replaced
   `package-lock.json` (or a parent directory) with a symlink to
   `~/.ssh/id_ed25519` or to a file in another project gets a failed door,
   not a signed copy of that file. The named tests
   `declared_output_symlink_fails_the_door`,
   `declared_output_parent_dir_symlink_fails_the_door`, and
   `declared_output_replaced_by_fifo_fails_the_door` cover the three
   cases on both platforms. The copy lies outside every path the
   sandbox profile allows the tool to write, and the door makes it
   read-only and holds its descriptors open. The diff classifies paths in
   the stage, but every check on output **contents** (the token, address,
   and stage-path scans, the digests), the signature, and publication read
   only this copy. Whatever a missed straggler writes to the stage
   afterward is never read.

The named test `descendant_writes_during_publication_do_not_reach_the_project`
runs a fixture tool whose `setsid`, double-forked child rewrites a
declared output in a loop for ten seconds after the tool exits. It
asserts that the published bytes equal the immutable copy, that the
record's `outputs` digests match the published files, and, on Linux,
that the child was killed. It runs on both platforms.

#### Isolation tiers: what runs when the native sandbox is unavailable

Every door runs in the strongest tier the host offers, and there are
only two tiers. Every delegated tool is treated as able to run
project-chosen code. For Bundler (Gemfile), mix (`mix.exs`),
`dotnet restore` (MSBuild), uv whenever builds are allowed, and the
no-route helpers that evaluate project files, that is their job. For the
rest it is a configuration away: npm runs whatever program `.npmrc`'s
`git=` or `script-shell=` names, cargo runs `build.rustc-wrapper` and any
credential provider `.cargo/config.toml` names, git runs `core.fsmonitor`
and `core.sshCommand`. The door forces these settings (below), but the
list of such settings is only as complete as each tool's documentation,
so isolation is the backstop and no tool runs without it. (Earlier drafts
had a third tier, `none`, for "resolve-only" tools on keyless machines.
It is removed.)

The tiers, strongest first:

1. **`confined`** means network fenced to the proxy plus filesystem
   isolation. It comes from the two engines below, or from the Linux
   isolation helper when it can create a network namespace (see
   `isolated`):
   - the **native sandbox**: bwrap on Linux, Seatbelt on macOS;
   - the **container backend** (Linux; on macOS the VM backend described
     under `isolated`): when bwrap cannot create a user
     namespace (`kernel.unprivileged_userns_clone=0`, or the AppArmor
     `restrict_unprivileged_userns` policy) but a container engine
     (`podman` or `docker`) is reachable. The relay runs as the
     container's entrypoint. The container has `--network none`, the
     snapshot and the tool's store objects bind-mounted at their real
     paths, the proxy socket bind-mounted, a read-only root from a
     minimal tog-built image (the store's system-runtime subset, pinned
     by digest), the same seccomp filter, and `--pids-limit`. Removing
     the container kills the tree. Everything else (snapshot, diff,
     transaction) is identical.
2. **`isolated`** (Linux only) means filesystem and process isolation
   under a **per-run ephemeral identity**. There is no shared resolver
   account. A shared UID would let a surviving or concurrent malicious
   run reach another run's stage and change the outputs that the
   developer's tog then signs. The identity comes from
   **`tog-isolate`**, a small privileged helper (setuid root, or started
   through one sudoers rule; `tog doctor --isolation` prints the install
   steps). It does only this, per run:
   1. **Allocate a UID** from a reserved range configured in
      `/etc/tog/isolate.toml` (default `2147000000–2147065535`, outside
      `/etc/subuid` ranges and the system's login range). Allocation is an
      exclusive lock file per UID under `/run/tog-isolate/`, so two
      concurrent sessions never share a UID. A UID is never reused while
      any process with it exists (checked through the cgroup below) or
      while any file owned by it remains in a place the helper does not
      wipe. The only writable places are the ones listed in step 3, and
      the helper wipes all of them.
   2. **Create a cgroup v2 leaf** for the run under a helper-owned subtree
      (`/sys/fs/cgroup/tog-isolate/<run id>`, with `pids.max` and
      `memory.max` set), and start the relay inside it. The run's UID owns
      neither that cgroup nor any other, so no process of the run can move
      itself out (moving a process needs write access to the destination
      `cgroup.procs`).
   3. **Build a private mount namespace** (root may always do this): `/`
      recursively read-only, fresh tmpfs on `/tmp`, `/var/tmp`, and
      `/dev/shm`, the developer's home and the real project not mounted,
      and one writable **stage**, owned by the run's UID with mode 0700,
      holding the snapshot and scratch. The tool's store objects are
      bind-mounted read-only. The helper also creates a **network
      namespace** with only loopback and bridges the proxy socket through
      the same relay. When the kernel lets it (it always lets root, unless
      a container runtime above has forbidden it), the run is fenced, and
      its tier is recorded as `confined` with engine `isolate-helper` in
      the diagnostics. Only where the network namespace cannot be created
      is the run `isolated` and records `unconfined-resolution`.
   4. **Drop to the UID** (`setgroups([])`, `setresgid`, `setresuid`,
      `PR_SET_NO_NEW_PRIVS`, and the AF_UNIX and exec seccomp filters)
      and exec the relay.
   5. **Quiesce.** After the tool exits: write `1` to the leaf's
      `cgroup.kill`, then wait until `cgroup.events` reports
      `populated 0`, with a bounded timeout. Timing out fails the door,
      and the UID stays allocated and the stage untouched until an
      operator runs `tog-isolate --reap`. **The door never validates
      while the cgroup is populated.** Only then does the helper hand the
      stage to the developer, and the door proceeds to the immutable
      output copy. The hand-over runs as root over a tree the run's UID
      controlled, so it never follows a link: the helper walks the stage
      from a held directory descriptor with `openat2(RESOLVE_BENEATH |
      RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)`, changes each entry with
      `fchownat(dirfd, name, uid, gid, AT_SYMLINK_NOFOLLOW)` (so a symlink
      itself changes owner, never its target), descends only into entries
      whose `fstatat(AT_SYMLINK_NOFOLLOW)` reports a real directory, and
      refuses a hard-linked regular file (`st_nlink > 1`), which could
      otherwise hand the developer ownership of a file linked in from
      elsewhere on the same filesystem. (The helper also requires
      `fs.protected_hardlinks=1`, the default on current distributions,
      so the run's UID cannot link a file it does not own in the first
      place. The `st_nlink` refusal holds even where that is off.) The named
      tests `isolate_handover_does_not_follow_symlinks` (a stage symlink
      to a root-owned file keeps that file's owner) and
      `isolate_handover_refuses_hardlinks` cover it.
   6. **Release**: remove the stage and the cgroup leaf, and release the
      UID lock.

   The signing key (0600, owned by the developer) and the developer's tog
   process are unreachable across the UID boundary, and nothing of one
   run is visible to another: each has its own UID, 0700 stage, mount
   namespace, tmpfs, and cgroup. **macOS has no `isolated` tier.**
   Seatbelt ships with the OS. If it is unusable, the only fallback is
   the container/VM backend: a Linux VM through Virtualization.framework
   (via `podman machine`, `colima`, or Docker Desktop), running the
   aarch64-linux tool rows with the tool told to resolve for the host
   platform (`bundle lock --add-platform arm64-darwin`, uv
   `--python-platform aarch64-apple-darwin`, and so on). That backend
   depends on the `aarch64-unknown-linux-gnu` platform rows, which tog
   does not ship yet. Until they exist, a Mac without usable Seatbelt
   fails with the missing-capability message.

The rule: every tool, on every machine, with or without a signing key,
runs `confined` or `isolated` (Linux), and fails when neither is
available. Nothing depends on whether a key is configured, so there is
no key-presence check to get wrong. (The earlier `none` rule hinged on
"no signing key configured", which a check of `TOG_SIGNING_KEY` alone
would misread: a key file can exist with the variable unset in this
shell and set in the next.) The key is protected by the tiers instead:
the door profile denies reads of the path `TOG_SIGNING_KEY` names, and
of the default path `tog keygen` suggests, on both platforms, and the
`isolated` tier puts it across a UID boundary. `tog keygen` refuses a
path under the sandbox's system read roots (`/usr`, `/etc`, `/opt`,
`/private/etc`, `/Library`, `/System`), which every tier can read.

The failure message names the tool, why it needs isolation, and each
missing capability with its fix. For example: "tog add runs Bundler,
which evaluates the Gemfile, so it needs isolation. bubblewrap cannot
create a user namespace here (AppArmor restrict_unprivileged_userns=1),
no container engine is reachable (podman/docker not found), and the
isolation helper is not installed (see `tog doctor --isolation`). Enable
one of them." A sync that needs a missing-lock door fails the same way.

`unconfined-resolution` keeps its meaning, "the ledger may be missing
traffic because the network was not fenced", and it is recorded for the
`isolated` tier. The record's `isolation` field states the tier
(`confined` or `isolated`). The tier is a semantic fact. Which engine
provided it is a diagnostic. The company template denies
`unconfined-resolution`, so under it only `confined` runs pass.

#### Forced program settings

For each tool, every setting that names a program to run is forced on
the command line or in the environment, where the tool gives those
sources priority over project files. PR 0 listed each tool's settings
from its documentation and source and proved them with marker-program
fixtures in `tests/fixtures/proxy/forced/<tool>/` (driver:
`tools/proxy_spike/forced.py`). Each setting names a marker that records
that it ran. A **control** run puts one setting in the project's own
config file (`.npmrc`, `.cargo/config.toml`, `pyproject.toml`,
`.git/config`, the environment for Go) under today's census invocation.
The **forced** run puts all of them there and adds the forced settings
below. A setting "fires" when its marker runs in its control. The claim
holds when no marker runs in the forced run. All runs are confined and
under the seccomp filter.

| Tool | Forced settings (as measured) | Fired in control | Forced run |
|---|---|---|---|
| npm | `--git=<store git>`, `--script-shell=<store sh>`, `--shell=<store sh>`, `--ignore-scripts`, `--node-options=`, `--node-gyp=` (a nonexistent path), `--editor`, `--browser`, and `--viewer` set to `false` | `git` (the lock-only install of a git dependency runs it). `script-shell`, `shell`, `node-gyp`, `editor`, `browser`, `viewer`, and `node-options` did not fire, and a git dependency's `prepare` script did not run under `--ignore-scripts` | no marker ran, exit 0 |
| pnpm | `--config.script-shell=<store sh>`, `--config.shell-emulator=false`, `--config.git-shallow-hosts=`, `--ignore-scripts`, `--config.node-options=`, and **added by PR 0**: `--config.pnpmfile=.pnpmfile.cjs`, `--config.global-pnpmfile=`, `--config.manage-package-manager-versions=false` (the last from pnpm's docs: otherwise pnpm may download another pnpm named by `packageManager`). A `.pnpmfile.cjs` is project code pnpm runs by design, so it is left on (turning it off would change the lock) and the tier contains it | `pnpmfile` and `global-pnpmfile` (both name a JavaScript file pnpm loads). `script-shell` and `node-options` did not fire | only the by-design `.pnpmfile.cjs` ran, exit 0 |
| cargo | `--config build.rustc=<store rustc>`, `build.rustc-wrapper=""`, `build.rustc-workspace-wrapper=""`, `build.rustdoc=<store rustdoc>`, `registry.global-credential-providers=["cargo:token"]`, `registries.<name>.credential-provider=["cargo:token"]` for every registry in the config, `net.git-fetch-with-cli=true` with the forced git below. `target.<triple>.runner` and `.linker` stay unset | `build.rustc`, `build.rustc-wrapper`, and `build.rustc-workspace-wrapper` in `cargo metadata` (it asks rustc for target info), not in `generate-lockfile`. Both credential-provider forms, against a registry whose `config.json` says `auth-required`. `build.rustdoc`, `runner`, and `linker` never fired (proved: resolution never reads them) | no marker ran. The authenticated registry then fails (exit 101, `cargo:token` has no token), which is the intended outcome. Without that dependency, exit 0 |
| uv | `--keyring-provider disabled`, `--no-python-downloads`, `--python <store python>` (on both `lock` and `pip compile`, replacing `UV_PYTHON`, which `pip compile` ignores), `--no-config` plus the project's `[tool.uv]` read by tog and passed as flags | `keyring-provider = "subprocess"` in `[tool.uv]` (runs `keyring` from `PATH`), and `python = ...` in `[tool.uv.pip]` (runs the named interpreter). A `.python-version` naming a program did not fire. `--no-config` alone drops `[tool.uv]` settings but keeps `[[tool.uv.index]]` and `[tool.uv.sources]`, so tog must still read those itself | no marker ran, exit 0 |
| git | carried in `GIT_CONFIG_COUNT`/`KEY`/`VALUE` (the tools start git, so `-c` flags cannot reach it): `credential.helper=`, `core.fsmonitor=false`, `core.hooksPath=/dev/null`, `core.sshCommand=false` with `GIT_SSH_COMMAND` unset, `protocol.allow=never`, `protocol.https.allow=always`, `protocol.file.allow=always`, and **added by PR 0**: `protocol.ext.allow=never`, `protocol.ssh.allow=never`, `protocol.git.allow=never`, `protocol.http.allow=never`, `core.gitProxy=`; also `uploadpack.packObjectsHook=`, `core.askPass=false` with `GIT_ASKPASS` and `SSH_ASKPASS` unset, and `GIT_CONFIG_NOSYSTEM=1` with `GIT_CONFIG_GLOBAL=/dev/null` | `core.fsmonitor` (`status`), `core.sshCommand` (an `ssh://` remote), `core.gitProxy` (a `git://` remote), `credential.helper` and `core.askPass` (a 401 from an https remote), `core.hooksPath` (`commit`), and `protocol.ext.allow=always` (an `ext::` remote runs its command) | the design's set still ran the `ext::` marker: a repository's own `protocol.ext.allow=always` beats `protocol.allow=never`, which is only the default for unlisted protocols. With the per-protocol `never` entries above, no marker ran |
| go | the census environment is built from empty: `GOFLAGS=-mod=mod`, `GOTOOLCHAIN=local`, `GOVCS=*:off` (modules come only through GOPROXY), `GOPROXY` the mirror with no `direct`, `GONOSUMDB=` and `GOPRIVATE=` unset, `CC` and `CXX` unset with `CGO_ENABLED=0`, and **added by PR 0**: `GOENV=off` (so a user `go.env` cannot set any of these), `GOAUTH=off`, `GOCACHEPROG` unset | `GOCACHEPROG` (go runs it as the build cache), `GOVCS` allowing git with `GOPROXY=direct` (runs `git` from `PATH`), and a `toolchain go1.99.0` line in `go.mod` under `GOTOOLCHAIN=auto` (requests `golang.org/toolchain/@v/v0.0.1-go1.99.0.linux-amd64.zip` from the mirror). `GOFLAGS=-toolexec=...`, `GOAUTH=command ...`, `CC`, and `CXX` did not fire in `go mod tidy`/`download` | no marker ran, no toolchain request, exit 0 |
| Bundler, mix, dotnet | code-evaluating by design; the forced settings are the ones in their table rows (`BUNDLE_*` and `MIX_*` stripped, `BUNDLE_IGNORE_CONFIG=1`, `DOTNET_CLI_*` set, `--disable-build-servers`) and isolation is the control | Bundler: a `.bundle/config` naming another Gemfile fires without `BUNDLE_IGNORE_CONFIG=1` | the Gemfile, `mix.exs`, and an MSBuild `Exec` target in `Directory.Build.props` all ran, as designed, confined, exit 0 |

A tool release that adds a program-naming setting is caught when the
census row is refreshed for that version, and until then the tier still
contains it.

### The ledger: identity, contents, and redaction

**Two related objects.** A door run produces two store objects: the
**ledger** (portable evidence) and its **diagnostics sidecar** (run-local
data). The sidecar names the ledger, and nothing names the sidecar:

- **Portable evidence** is what the fetches were, independent of the
  machine and of cache state. It is a **set** of entries, each
  `{class, method, url, status, sha256, claimed, verified, freshness}`
  (`freshness` is `live` or `last-good`; see "Offline behavior").
  Duplicates are removed by exact equality, and the set is sorted by each
  entry's complete canonical bytes. The same fetches therefore produce the
  same bytes whatever order they arrived in and however often they were
  retried.
- **Diagnostics** hold what varies by machine or run: cache disposition
  (hit, miss, revalidated), arrival order, retry and duplicate counts,
  byte counts, the isolation engine, the platform, tool store object
  ids, the proxy port, refusal details, and on Linux the exec log below.
  Diagnostics are stored only in the sidecar object in the local store.
  They never enter portable data (the ledger, its identity, the signed
  record, an export) or anything committed to the project.

The canonical bytes of each part use the same canonicalization as
`kernel/signing.rs` (keys in byte order, compact).

**Store identity: portable bytes only.** The ledger is a store object of
the new kernel-owned kind `resolution-ledger`, with an `Identity` like
every other object: kind `resolution-ledger`, name = ecosystem, version =
`1`, inputs = `{portable: sha256(portable bytes)}`. Its object directory
holds only `portable.json`. The ecosystem and the door kind are inside
the portable bytes, so the identity covers them. The identity is a pure
function of the portable evidence, so **two machines holding the same
portable ledger compute the same object id**. It gets a `KindAdapter` row
in the kernel's object-kind table with live and migration grammars, as
every kind must have or GC refuses to certify it (§ARCHITECTURE "GC root
safety").

**The diagnostics sidecar.** The run-local part is the second object, of
kind `resolution-diagnostics`, identity inputs
`{ledger: <ledger object id>, diagnostics: sha256(diagnostic bytes)}`,
holding `diagnostics.json`. Nothing portable names it. The ledger does
not reference it, and it is found through the index
`<store>/resolve/diag/<ledger id>`. It has its own `KindAdapter` row, is
rooted alongside its ledger on the machine that produced it, and never
leaves that machine.

**Retention.** The door registers the ledger id (and the sidecar id) in
the project's root record as soon as the objects are committed, so GC
keeps them from the moment they exist, including across `--no-sync`.
When a resolution record joins a closure, the closure writer adds the
ledger id to that closure's `ClosureRefs` **only if the object exists in
the active store**, because `ClosureRefs` validates presence and must not
fail on a machine that never had it. On a fresh CI machine the join
succeeds with no ledger retained. Planner and `x` doors, which write no
record, add their ledger ids (always local) to the `ClosureRefs` of the
closure their sync (or `x` root) publishes.

**Portable versus local evidence.** The signed record carries the ledger's
object id and the sha256 of its portable bytes. Both are portable
values, fixed by the portable evidence and identical on every machine.
Verifying the record needs neither the object nor the store. `tog audit`
stays store-independent and judges the signed record's facts. The full
ledger is evidence you can move between machines but do not need to:

- `tog attest --ledger-export <ecosystem> <file>` writes the portable
  bytes of the ledger named by the project's current record. It fails if
  the object is not in the local store.
- `tog attest --ledger-import <file>` reads portable bytes, recomputes
  their sha256 and object id, and accepts them only if they equal the
  `portable_sha256` and ledger id of an attesting record in the project.
  It then commits the object and roots it, and the next closure write
  retains it through `ClosureRefs`. A CI job that wants the developer's
  ledger imports the file the developer exported (for example as a CI
  artifact).
- **Reconstruction by re-running** cannot give the same bytes (registry
  metadata changes over time), so it is not offered as a way to recover a
  ledger. `tog attest` on CI produces a **new** record and ledger for the
  same lock instead, which is the supported way for CI to hold its own
  evidence.

**Redaction, before anything is serialized.** Entries and the command
field pass through one redactor:

- URL userinfo is removed (`https://user:tok@host/` becomes
  `https://host/`).
- Query strings: each `RegistryProtocol` declares the query keys that
  identify content (for example none for npm tarballs, `format` for some
  index APIs). Every other key keeps its name and gets the value
  `REDACTED`. This covers presigned-URL signatures (`X-Amz-*`,
  `X-Goog-*`, Azure SAS `sig`/`se`/`sp`, `token`, `key`) without needing
  to list them. Intercepted hosts without a protocol get all values
  redacted.
- Redirect chains are redacted hop by hop the same way.
- Command operands: the tog verb's operands and the tool argv are
  scanned. URL-shaped operands are redacted as above. Values of
  credential-bearing flags (`--password`, `--token`, `--auth`, `-u`/
  `--user` with a colon, `--_authToken`, npm `//host/:_authToken=`, and
  every `--config` whose key contains `token`, `auth`, `password`, or
  `credential`) become `REDACTED`. The session token and proxy address are
  removed. The environment is never recorded.
- Headers are never recorded.

A redaction test feeds each form through the redactor, and a golden
ledger test fails if a known secret shape survives.

**The Linux exec log.** On Linux the relay's seccomp filter also returns
`SECCOMP_RET_USER_NOTIF` for `execve`/`execveat`. The relay (outside the
filter) receives each notification, reads the program path from the
notifying process, appends `{pid, parent, path}` to the diagnostics, and
lets the call continue. This makes the kernel, not the tool, report every
program the tool tree executed. It is diagnostics, and it cross-checks the
build probe (below). macOS has no equivalent without Endpoint Security
entitlements (Apple-granted; not available to tog) or disabling SIP for
dtrace, so the policy-relevant build fact must not depend on it. See
`resolution-build`.

### Attestation: the signed resolution record

**The record** (`.tog/resolution/<ecosystem>.json`) is the portable,
committed receipt of one door that produced project outputs. It uses the
**same envelope form as a signed closure**. The signature covers the
canonical bytes of the whole record minus its top-level `signature`
field, and `kernel/signing.rs` (`Signer::sign` and the closure verifier)
produces and checks it unchanged:

```json
{"schema":"resolution/1","ecosystem":"node","door":"edit",
 "tool":{"name":"npm","version":"10.9.2"},
 "command":["add","lodash@^4"],
 "outputs":{"package-lock.json":"<sha256>","package.json":"<sha256>"},
 "inputs":{".npmrc":"<sha256>","packages/web/package.json":"<sha256>"},
 "ledger":{"object":"<ledger object id>","portable_sha256":"<64 hex>",
           "endpoints":["registry.npmjs.org"],"entries":412,"refused":0},
 "isolation":"confined",
 "exceptions":[{"kind":"unattested-index","subject":"npm.example.com","detail":"..."}],
 "signature":{"alg":"ed25519","key":"<64 hex>","sig":"<128 hex>"}}
```

`signature.key` is **bare** 64-character lowercase hex, exactly as
`Signer::sign` writes it today (the `ed25519:` prefix belongs only to the
key-file and policy syntax). The record has no timestamps, port, token,
platform, isolation engine, or store object ids other than the ledger's,
and the ledger id is itself portable (see "Store identity"). The key is
`TOG_SIGNING_KEY`, the same key that signs closures. The door loads it at
preflight, as `sync` and `fmt` do, and that loading extends to `add`,
`remove`, `update`, `x`, and the new `tog attest`. When `TOG_SIGNING_KEY`
is unset in the running process, the record has no `signature` field (the
unsigned closure convention). Such a record is honest but unattested.
This is the only thing that depends on whether a key is present, and it
fails safe: a key file that exists on disk while the variable is unset
produces an unsigned record, which the join treats as unrecorded.

`outputs` holds the digest of every file the door published. `inputs`
holds the digest of every **resolution input** the tool read but did not
write, as the tailor names them (`Tailor::resolution_inputs`, below): the
other workspace members' manifests, `.npmrc`, `pnpm-workspace.yaml`,
`uv.toml` and `[tool.uv]`-bearing `pyproject.toml` files,
`.cargo/config.toml`, `go.work`, `Directory.Packages.props`,
`NuGet.config`, and so on. Paths in both maps are relative to the
closure's project directory. Input digests come from the baseline
manifest, so they describe exactly the bytes the tool was given. If the
user edits an input during the run, the record still describes the
snapshot, and the next join reports `stale-inputs`, which is the truth.

**What the signature binds.** It binds, in one signed object: the outputs'
digests (every lock and manifest the door wrote), the inputs' digests
(every manifest and tool config it read), the ledger's object id and
portable digest, the tool, the command, the isolation tier, and every
ledger-only exception. Changing any of them breaks the signature.
Because the record names the project's own manifests by content, a
record signed for one project cannot attest another project that
happens to have the same lock bytes, and a manifest edited after the
resolution (a dependency added by hand without relocking) no longer
matches.

**The join.** It happens in one ecosystem-neutral place,
`comforter::write_closure_inner`, before it claims the attribution. For
an ecosystem whose tailor declares a resolvable lock
(`Tailor::resolution_outputs`, the files a door would produce, relative
to the closure's project directory):

1. Collect the **candidate records**: `.tog/resolution/<ecosystem>.json`
   read through `ProjectRoot`, plus every file passed with
   `--resolution-record <file>` (the CI artifact flow below) whose
   top-level `ecosystem` string names this ecosystem. Each is read as raw
   bytes and parsed only as a generic JSON object. Steps 2 and 3 run on
   each candidate. The first candidate that attests is joined (supplied
   files first, in command-line order, then the committed one). If none
   attests, the reason recorded in step 5 is the committed record's (or
   `missing`), with each supplied file's reason appended to the detail.
   A hard failure in step 3 from any candidate fails the sync.
2. **Authenticate the raw envelope first**, before interpreting any field
   but `signature`. Compute the canonical bytes of the object minus its
   top-level `signature` (the closure rule in `kernel/signing.rs`), verify
   the Ed25519 signature, and check that the key is in the machine
   policy's `[signing] trusted` set (the same set audit trusts; project
   and `--policy` files can only intersect it). A record that fails here
   (no signature, bad signature, untrusted key, not a JSON object) is
   **unauthenticated**. Its contents are ignored entirely, whatever they
   say, and it goes to step 5.
3. **Authenticated records: check versions and vocabularies before
   anything else.** Read `schema`, `isolation`, and each exception `kind`
   as plain strings from the authenticated object:
   - `schema` of the form `resolution/<n>` with `n` greater than this
     tog supports, or with any `n` it does not implement, is a **hard
     failure under every policy**: "the resolution record uses schema
     `resolution/2`, which this tog cannot read; upgrade tog".
   - an `isolation` string outside `confined` and `isolated` is the
     same hard failure ("... isolation tier `<value>` ..."). No tog ever
     signed `none` (the tier never shipped), so no compatibility case
     exists for it.
   - an exception `kind` not in `policy::KINDS` (through `canonical_kind`)
     is the same hard failure ("... exception kind `<kind>` ..."). This
     matters because `policy::record_with` itself accepts free-string
     kinds. Without the check, an older tog would publish a closure from a
     newer signed record and silently drop a finding it cannot judge.

   These checks run on strings, before the typed `resolution/1` parser,
   so no enum parser can turn a newer value into "malformed". Only after
   they pass is the object parsed as `resolution/1`. A signed record with a
   supported schema that still fails to parse (a missing field, a wrong
   type) is `malformed` and goes to step 5. So is a record whose
   `outputs` map is **empty**, or which names a path outside the
   tailor's `resolution_outputs(dir)` and `resolution_inputs(dir)`
   lists, or a path that is absolute or contains `..`. Then the join
   checks **coverage and freshness** against the files on disk:
   - every file `resolution_outputs(dir)` names that **exists** must
     appear in `outputs`. A lock the record does not cover is
     `incomplete` (step 5). Without this rule, a signed record for
     `package.json` alone would vouch for a `package-lock.json` that no
     door produced.
   - every file `resolution_inputs(dir)` names that exists must appear
     in `outputs` or `inputs`, else `incomplete`. A file the record names
     that no longer exists is `stale-outputs` or `stale-inputs`.
   - every digest in `outputs` must match the file on disk (else
     `stale-outputs`), and every digest in `inputs` likewise (else
     `stale-inputs`).

   A record that passes all of this **attests**.
4. If it attests and every kind is known: the closure body gains
   `"resolution": <envelope>`, and the record's `exceptions` are recorded
   into the attribution on the writer's thread. The ledger id joins
   `ClosureRefs` only if the object exists in the active store.
5. If it does not attest (missing, unauthenticated, malformed,
   incomplete, or stale digests): its contents are **ignored
   entirely**, and the join records **`unrecorded-resolution`** with the
   reason (`missing`, `unsigned`, `untrusted-key`, `bad-signature`,
   `malformed`, `incomplete`, `stale-outputs`, `stale-inputs`). The record file is **left untouched** in
   every case: the join never deletes or rewrites a receipt. A stale
   receipt stays as forensic evidence of what was last resolved, and it
   is replaced only by the publication step of a later **successful**
   resolution transaction (an edit, a missing-lock door, or `tog
   attest`). An unsigned or untrusted record likewise stays, since a
   machine that trusts its key can still attest it.
6. Recording goes through `policy::record_with`, so a denied kind, whether
   an attested exception or `unrecorded-resolution` itself, refuses
   publication and the sync fails. Because the join writes nothing to the
   project, a refusal leaves the checkout exactly as it was.

This is what makes the record enforceable rather than informational:

- **Deleting** a record gives `unrecorded-resolution`.
- **Replacing** it with a clean one needs a trusted key.
- **Editing** it (removing `unconfined-resolution`) breaks the signature,
  which again gives `unrecorded-resolution`.
- **Replaying** an older signed record for the same output bytes is
  harmless: it genuinely describes a resolution that produced exactly
  those bytes.

Exceptions in a record affect policy only when the record attests.

**Where provenance is required.** `unrecorded-resolution` is an ordinary
policy kind. Permissive policy records it (so `tog status` and the
exception summary show that a lock came from outside a tog door) and
continues. `docs/human/policy-company.toml` denies it, beside
`unconfined-resolution`, with a comment. A company that uses `tog audit`
already has machine `[signing]` keys (audit exits 2 without them), and
that is the one prerequisite. From then on a lock must come through a tog
door on a machine whose key the gate trusts. Which machines sign is the
team's choice, and both options below use the same verification path
(see "Decisions").

**Existing locks: `tog attest [<eco>]`.** Every repository adopting that
policy starts with locks that no door produced. `tog attest` runs a
**verification door** (door kind `attest`) per ecosystem: the tool's own
lock-consistency check, confined through the proxy. Its declared outputs
are the lock and manifest, and success requires that the diff leaves
them **byte-unchanged**. The check fetches metadata and proves the
committed lock is what the tool accepts from permitted endpoints.
Success writes a signed record with `door: "attest"`. The checks are
`uv lock --locked`, `npm install --package-lock-only` with an unchanged
lock, the pnpm equivalent (`install --lockfile-only --frozen-lockfile`),
`cargo metadata --locked`, `go mod tidy -diff` plus
`go mod download -json all`, `bundle lock` with an unchanged lock,
`mix deps.get --check-locked`, and `dotnet restore --locked-mode`. PR 0
confirmed all eight: each passes with the lock unchanged on a consistent
project, and each fails (or, for npm and Bundler, which exit 0 either way,
rewrites the lock, so the byte diff is the check) when the manifest has
drifted. Go needs both commands: after an edit that removes a module,
`go mod tidy -diff` is what catches the stale `go.sum` lines.
Tailors without a lock check refuse `attest` with the reason. Run on CI
with the signing key, this converts a repository in one command. It is
also the remedy the `unrecorded-resolution` refusal prints.

**`--strict` (and `TOG_STRICT=1`, and `strict = true`).** Strict mode
denies every exception kind (`policy::StrictSource`), so from PR 4, the
PR that introduces the join, onward strict has these outcomes:

- **Every lock needs an attesting record.** A sync under strict with a
  lock that has none refuses publication with `unrecorded-resolution`,
  and the refusal carries this remedy in place of the generic
  "rerun without --strict": "`tog --strict` requires every lock to carry
  a signed resolution record. `<lock>` has none (`<reason>`). To create
  one: run `tog keygen <path>`, set `TOG_SIGNING_KEY=<path>`, add the
  printed public key to the `[signing] trusted` list in your machine
  policy (`TOG_POLICY`, else `~/.tog/policy.toml`), then run `tog attest
  <ecosystem>`. Or rerun without --strict." The reason is the join's
  (`missing`, `unsigned`, `untrusted-key`, `stale-inputs`, and so on),
  so a developer whose record is merely stale is told to run
  `tog attest` and not to make a new key.
- **Last-good metadata is refused.** `stale-resolution` is denied, so the
  proxy answers 504 where it would have served last-good, and the door
  fails with: "`tog --strict` refuses stale metadata: `<url>` could not
  be fetched (`<transport error or --offline>`) and the last-good copy
  from the cache was not used. Retry when `<host>` is reachable, or rerun
  without --strict." It names the first such URL and the reason the
  upstream fetch failed.
- **Only the `confined` tier passes.** `unconfined-resolution` is denied,
  so an `isolated`-tier run is refused before the tool starts, naming the
  missing network namespace.

The named tests are
`strict_sync_refuses_unrecorded_lock_with_keygen_and_attest_remedy`,
`strict_sync_with_stale_record_says_attest_not_keygen`,
`strict_last_good_fetch_fails_naming_the_url_and_reason`, and
`strict_refuses_the_isolated_tier_before_the_tool_starts`. PR 4 updates
`docs/human/CLI.md`'s `--strict` and `TOG_STRICT` entries to say that
strict requires a signed resolution record for every lock and names the
remedy.

**Signing on CI: the record artifact.** The default setup (see
"Decisions") keeps the signing key in one CI job that runs no project
code, and passes that job's records to the gate as a build artifact, so
nothing is committed by a bot:

- `tog attest [<eco>] --record-out <path>` runs the verification doors
  as above but writes each signed record to `<path>` (a file when one
  ecosystem is named, else a directory holding `<eco>.json` per
  ecosystem) instead of `.tog/resolution/`. The project checkout is left
  unchanged.
- `tog sync --frozen --resolution-record <path>` (repeatable; a file or
  a directory of records) adds those records to the join's candidates
  (step 1 above). They are verified exactly like a committed record: the
  signature against the machine policy's trusted keys, then coverage and
  digests against the checkout. A supplied record is only ever evidence.
  It is never written into the project.

A worked GitHub Actions example. The public half of the attest key is in
the repository variable `TOG_ATTEST_PUBKEY`, and the gate writes its
machine policy from that variable, never from the checkout, because
project policy files can only narrow trust:

```yaml
jobs:
  attest:                      # holds the key, runs no project code
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -fsSL https://raw.githubusercontent.com/DigitalWestern/tog/main/install.sh | sh
      - run: |
          umask 077
          printf '%s\n' "$TOG_ATTEST_KEY" > "$RUNNER_TEMP/attest.key"
          TOG_SIGNING_KEY="$RUNNER_TEMP/attest.key" tog attest --record-out resolution/
        env:
          TOG_ATTEST_KEY: ${{ secrets.TOG_ATTEST_KEY }}
      - uses: actions/upload-artifact@v4
        with: { name: resolution-records, path: resolution/ }

  gate:                        # no key, verifies the records
    needs: attest
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -fsSL https://raw.githubusercontent.com/DigitalWestern/tog/main/install.sh | sh
      - uses: actions/download-artifact@v4
        with: { name: resolution-records, path: resolution/ }
      - run: |
          printf '[signing]\ntrusted = ["%s"]\n' "$TOG_ATTEST_PUBKEY" > "$RUNNER_TEMP/policy.toml"
          export TOG_POLICY="$RUNNER_TEMP/policy.toml"
          tog --strict sync --frozen --resolution-record resolution/
          tog audit
        env:
          TOG_ATTEST_PUBKEY: ${{ vars.TOG_ATTEST_PUBKEY }}

  test:                        # runs project code, holds no key
    needs: gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -fsSL https://raw.githubusercontent.com/DigitalWestern/tog/main/install.sh | sh
      - run: tog sync --frozen && tog run test
```

The `attest` job runs only confined tools (every door is `confined` or
`isolated`), so no project code runs outside a sandbox in the job that
holds the key. The `test` job, which does run project code unsandboxed,
never sees the key. GitHub withholds secrets from pull requests opened
from forks, so a fork's `attest` job fails and its gate reports
`unrecorded-resolution`. That is the fail-closed result: the lock is
attested when a maintainer's run of the same commit signs it. The gate
should be a required check whose workflow file is protected by branch
rules, as with any CI gate. PR 10 puts this example in the README.

**The bot-commit alternative.** A team that prefers committed records
runs `tog attest` without `--record-out` in the same key-holding job and
commits `.tog/resolution/` back to the branch (a bot commit). The gate
is then `tog --strict sync --frozen` with no extra flag. Both flows go
through the same join, the same trust check, and the same named tests:
`ci_record_artifact_attests_through_resolution_record_flag`,
`supplied_record_for_another_project_is_incomplete_or_stale`,
`supplied_record_is_never_written_into_the_project`, and
`committed_record_from_bot_flow_attests_without_flag`.

**Resolution doors without a project** (planner, `x`, the sdist Cargo
lock) write no record, so the join never looks for one. Planner doors run
inside a sync whose lock already exists: that lock's own record is what
the join judges.

**Double counting.** Facts the lock itself shows (`git-dependency`,
`weak-integrity`) are recorded by the tailor from the lock during sync.
The proxy uses them only for real-time denial and leaves them out of the
record. Facts only the proxy can know (`unattested-index` for an endpoint
the resolution consulted, `resolution-build`, `unconfined-resolution`,
`stale-resolution`) go into the record. As a second safety, `Attribution::claim` now removes
exact `(kind, subject, detail)` duplicates, which closes the separate
known gap that the frame had no dedupe at all (see "Known gaps").

**Threading.** `policy::record_with` refuses a record from a thread that
does not own the frame. The proxy runs on its own threads, so it never
records. It holds a clone of the effective `Policy`, calls the pure
`policy::denied` per request, and collects facts in the ledger. The door,
on the thread that opened the attribution, records after the tool exits.

### Policy checks: how proxy facts map to exception kinds

| What the door or proxy establishes | Kind | Real-time action when denied | Otherwise |
|---|---|---|---|
| Any git fetch (smart HTTP through interception, or a refused `git://`) | `git-dependency` (existing) | refuse the request with the policy refusal text | ledger only (sync re-derives from the lock) |
| An artifact whose registry claim is SHA-1 or MD5 only (npm `shasum` without `integrity`, a PyPI `md5` fragment), or has no claim where the protocol provides one | `weak-integrity` (existing) | refuse | ledger only |
| A request to an endpoint outside the permitted set: an intercepted host (uv extra index, `.npmrc` scoped registry, direct-URL dependency) or a refused `CONNECT` | `unattested-index` (existing; the policy text already covers "index-like options") | refuse | intercepted tools (uv, npm, pnpm, cargo): forward and record in the resolution record; mirror tools (Go, Bundler, Hex, NuGet): refuse visibly and record |
| The resolution required building a source distribution (see below) | `resolution-build` (**new**) | uv runs with `--no-build` only, so the edit fails naming the package that needs a build | record |
| The door ran without a network fence (the `isolated` tier; see "Isolation tiers") | `unconfined-resolution` (**new**) | refuse before the tool starts | record |
| Metadata was served from last-good because the upstream was unreachable (offline or transport failure) | `stale-resolution` (**new**; subject = endpoint, detail = number of last-good responses) | the proxy answers 504 for any request it would otherwise serve last-good, so the door fails naming the first such URL | record; the entries are also marked `freshness: last-good` in the portable evidence, which the signature covers |
| A lock has no attesting resolution record at closure time | `unrecorded-resolution` (**new**) | the sync refuses to publish, and names `tog attest` | record |
| Lifecycle scripts | none | `--ignore-scripts` and `npm_config_ignore_scripts=true` stay as today; a script that ran anyway would be confined | `install-script-failed` stays a realize-time kind |
| Integrity mismatch (bytes differ from the claimed digest) | not an exception | always a hard failure: 502 to the tool, door fails, nothing cached | no permissive path |

**`resolution-build`, established by a probe instead of by guessing.** The
proxy cannot see whether uv executed a build backend: fetching an sdist
does not prove a build, and a build can happen without a fetch in that
run. On Linux the exec log can see it, but macOS offers no equivalent
tog can use. So the fact is established by construction on both
platforms:

1. Every uv door first runs with `--no-build` (the **probe**). With no
   build allowed, no third-party code runs, so the probe's outcome is
   trustworthy. If it succeeds, no build was needed, and its outputs are
   the result.
2. If the probe fails, and uv's error names a distribution that must be
   built (the `--no-build` refusal), then
   when `resolution-build` is denied the door fails with that package
   named. Otherwise the door records `resolution-build` with the package
   names and reruns without `--no-build`. The rerun is cheap, because
   every fetch is warm in the proxy cache. PR 0 captured the two forms
   (uv 0.12.7). A third-party distribution with no usable wheel:
   `Because <name>==<v> has no usable wheels and you require ...` followed
   by `hint: Wheels are required for `<name>` because building from source
   is disabled for all packages (i.e., with `--no-build`)`. A distribution
   uv has to build for metadata (a path or git dependency):
   `Failed to build `<name> @ <url>`` followed by
   `Building source distributions for `<name>` is disabled`. The door
   parses the name out of either form.
3. The project's own build (a workspace member with dynamic metadata) is
   the project's code, not a third party's. PR 0 refuted the planned
   exemption: `--no-build-package <member>` forbids that member's build
   too (same error). The probe instead builds the members' metadata
   first, in the run's own cache:
   `uv pip compile --no-deps --only-binary <names in the member's build-system.requires> -e <member>`
   (the build backend itself must come as a wheel, so only the project's
   own code runs), then `uv lock --no-build` reuses the cached metadata
   and passes (measured). A member whose build requirements are
   themselves sdist-only fails that pre-step, and the door treats it as a
   `resolution-build` naming that requirement.
4. uv's caches are per run (see "Performance"), so a build cached earlier
   cannot hide a build this run needed.

The kind therefore means exactly "resolution could not complete without
building a third-party source distribution, and the build was allowed".
On Linux the rerun's exec log is compared with the probe, and a build
recorded without any interpreter exec from a uv build environment (or the
reverse) is written to diagnostics for investigation. That is a
cross-check, not the source of the fact. No other ecosystem builds
packages during resolution (Bundler, mix, and MSBuild evaluate the
project's own files; git dependencies' `mix.exs` is covered by
`git-dependency`), so the probe is Python's alone.

The four new kinds go into `policy::KINDS`.
`docs/human/policy-company.toml` denies `unconfined-resolution` and
`unrecorded-resolution`. It lists `resolution-build` and
`stale-resolution` as deliberately not denied, each with its reason. The
build ran confined, and the lock it produced is verified at sync like any
other lock. A stale resolution produces an older lock, not a less honest
one, since every artifact is still verified. A company that wants neither
denies the kind. The decisions are recorded under "Decisions".

**Permitted endpoints.** Until WP3 PR 1 lands, the permitted set is
compiled in and is exactly today's forced public set: `pypi.org`,
`files.pythonhosted.org`, `registry.npmjs.org`, `index.crates.io`,
`static.crates.io`, `crates.io` (the download redirect), `proxy.golang.org`,
`sum.golang.org`, `rubygems.org`, `index.rubygems.org`, `repo.hex.pm`,
`api.nuget.org`, plus the hosts PR 0 saw the tools reach through the
door: `api.github.com` and `raw.githubusercontent.com` (uv's and cargo's
GitHub shortcuts for git dependencies, which are git fetches and so
`git-dependency`). No registry redirected to a CDN host in the census.
Cargo takes `static.crates.io` from `config.json`, with no `crates.io`
redirect. Hex's update check redirects `repo.hex.pm/installs/hex-1.x.csv`
to `builds.hex.pm`, which stays outside the set. The door refuses it
visibly and Hex continues. Git hosts are not endpoints: any public https host is
allowed for git, and every git fetch is `git-dependency`. WP3 PR 1 turns
the set into the typed endpoint configuration (machine policy may add,
project policy may only intersect). The proxy is where WP5 credential
references are used: attached upstream per endpoint, never forwarded
across a redirect to another origin, never visible to the tool. The
proxy strips `Authorization`, `Proxy-Authorization` (after checking the
token), and `Cookie` from every tool request.

**SSRF: resolve once, validate, connect to exactly that address.**
Sandboxed code can send the proxy any request. Routes accept only paths
that parse in their protocol's grammar (no `..`, no percent-encoded `/`,
no absolute-form URLs inside a route). The upstream host is fixed by the
route, or by `CONNECT` for interception. For each upstream connection the
proxy:

1. resolves the hostname **once**,
2. validates **every** returned address and refuses the connection if
   any address is not globally routable. "Globally routable" is decided by
   a table compiled from the IANA IPv4 and IPv6 Special-Purpose Address
   Registries, pinned by registry date in the source. Every entry whose
   "Globally Reachable" column is not `True` is refused. For IPv6, only
   `2000::/3` global unicast is eligible at all. Addresses that embed an
   IPv4 address (IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96`,
   NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo
   `2001::/32`) are refused outright rather than unpacked. That refuses,
   for IPv4, `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (CGNAT),
   `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`,
   `192.0.2.0/24`, `192.31.196.0/24`, `192.52.193.0/24`,
   `192.88.99.0/24`, `192.168.0.0/16`, `192.175.48.0/24`,
   `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`,
   `224.0.0.0/4`, `240.0.0.0/4`, and `255.255.255.255/32`, and for IPv6,
   `::/128`, `::1/128`, `100::/64`, `2001::/23`, `2001:db8::/32`,
   `3fff::/20`, `5f00::/16`, `fc00::/7`, `fe80::/10`, `ff00::/8`, and
   the embedding forms above. A registry host that genuinely lives in a
   non-global range (a company mirror on `10.x`) is a WP5 permitted
   endpoint with an explicit address allowance in machine policy, never
   a default,
3. connects to one of **those validated `SocketAddr`s**, through a `ureq`
   `Resolver` that returns exactly the validated list, so the client
   performs no lookup of its own,
4. keeps the original hostname for TLS SNI, certificate verification, and
   the `Host` header.

A second lookup that could answer differently never happens, so DNS
rebinding has nothing to race. Redirects repeat all four steps for each
hop, and each hop is also checked against the permitted set, as WP3
requires.

### Offline behavior

Two situations, handled the WP3 way ("a transport failure may fall back
to last-good; an integrity failure never does"):

- **Upstream unreachable while online** (DNS, connect, TLS, timeout, HTTP
  5xx): metadata requests are served from the proxy's last-good copy if one
  exists. Each such entry is marked `freshness: last-good` in the portable
  evidence, the door records `stale-resolution` per endpoint (denied:
  the proxy answers 504 instead of last-good, and the door fails), and
  one note is printed ("npm: 12 metadata responses served from cache;
  registry unreachable"). With no copy, the answer is 504 with a body naming the
  URL. Artifacts are served only from the verified cache (below), never
  from anything unverified. A 4xx is passed through, not converted to
  stale.
- **`--offline`** (WP3's mode; the flag does not exist yet, and until it
  does this mode is exercised by tests): the proxy makes no upstream
  connection. Metadata comes from last-good (recorded as
  `stale-resolution`, as above), artifacts from the cache, and every miss
  is 504 plus a ledger `offline-miss`. The door's error names the
  first miss, which is the thing to fetch online. A project whose lock
  already exists reaches no edit or missing-lock door offline, but two
  planner doors run on ordinary syncs: Go's `mod tidy -diff` and
  `mod download` on a plan-cache miss (served from the persistent planner
  module cache, so they need the proxy only for modules not yet seen) and
  mix `deps.get --check-locked` (Hex registry metadata, served from
  last-good). Offline, both succeed when the project was synced online
  once on this machine, and fail naming the first miss otherwise.

`--frozen` is unchanged: sync never calls `prepare`, so no missing-lock
door runs, and dependency edits are not frozen operations. The join still
runs under `--frozen`, so a frozen CI sync enforces
`unrecorded-resolution`.

### Missing-lock generation through the door

`commands::sync::run_in` calls `tailor.prepare` for each detected
ecosystem when not frozen. With the door:

1. `run_in` opens the ecosystem's `Attribution` as today and passes it
   into a `ResolutionDoor` for `prepare`.
2. The tailor decides a lock is missing and builds a `DelegateSpec` (tool,
   args, outputs = the lock file, routes, extra read roots).
3. The door snapshots, runs the tool confined through the proxy, diffs,
   and commits the transaction: ledger object, signed record, lock
   published. It records ledger-only exceptions into the same
   attribution. For a missing-lock door that attribution is already the
   ecosystem's own scope, so no hand-off is needed.
4. The tailor plans from the new lock exactly as today: every artifact is
   fetched and verified by tog at realize time.
5. The closure writer joins the record. It attests, because the outputs
   were just published and signed (when a key is configured).

Planner doors inside `Tailor::sync` (Go's `mod tidy -diff` and
`mod download -json all`, mix `deps.get --check-locked`) open a door from
the same attribution. They declare no project outputs: a Go planner
whose `go mod tidy` would change `go.mod` is the missing-lock door, not a
planner. They write a ledger, retained through `ClosureRefs`, and no
record. A refusal still fails the sync. Go's closure download keeps its
"re-verify every artifact" rule. The proxy's cache and tog's
`cache/sha256` are the same store, so the second copy costs nothing.

### `Tailor::edit_manifest` and the door API (#61, #169)

The kernel owns the door (`src/kernel/resolve/`: proxy server, CA,
routes, ledger, redaction, snapshot and diff, the transaction, the relay
subcommand's body). Tailors own protocol knowledge through a kernel trait.
Commands own nothing ecosystem-specific.

```rust
// src/kernel/resolve/mod.rs
pub enum DoorKind { Edit, MissingLock, Planner, X, Attest }

/// The only way to run a dependency tool that may use the network or
/// evaluate project code. Borrowing the attribution ties every fact the
/// run produces to the scope that will publish (or discard) it.
pub struct ResolutionDoor<'a> { /* store, activity, platform, kind,
                                    attribution: &'a mut Attribution, policy,
                                    signing key */ }

impl<'a> ResolutionDoor<'a> {
    pub fn open(store: &'a Store, activity: &'a StoreActivity, platform: Platform,
                kind: DoorKind, attribution: &'a mut Attribution) -> io::Result<Self>;
    /// Run one tool invocation on a staged snapshot, confined to the
    /// proxy, and publish its declared outputs, ledger, and signed record
    /// as one transaction. Fails, leaving the project unchanged, when the
    /// tool fails, when any request was refused by policy, when the diff
    /// holds an undeclared change, or when any publication step fails.
    pub fn run(&mut self, spec: DelegateSpec<'_>) -> io::Result<DelegateReport>;
    pub fn attribution(&mut self) -> &mut Attribution;
}

pub struct DelegateSpec<'s> {
    pub ecosystem: &'static str,
    pub tool: ToolId,                     // name, version, store object id
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub lock_root: &'s Path,              // snapshotted; cwd inside the sandbox
    pub outputs: Vec<PathBuf>,            // relative to lock_root; the only files published
    pub scratch_outputs: Vec<Glob>,       // relative to lock_root; allowed to change, discarded
    pub exclude: Vec<Glob>,               // not snapshotted (heavy build outputs)
    pub extra_roots: Vec<PathBuf>,        // project-side read roots, snapshotted
    pub store_reads: Vec<PathBuf>,        // store objects, scanned for sockets, read-only
    pub env: Vec<(String, String)>,       // tog-forced values; the environment starts empty
    pub routes: Vec<Route>,               // mirror routes: (&'static dyn RegistryProtocol, Endpoint)
    pub intercept: Intercept,             // Intercept::{Tls, RefuseVisibly}
    pub probe: Option<Probe>,             // uv's --no-build probe and its rerun args
    pub wire: &'s dyn Fn(&ProxyAddress) -> io::Result<Wiring>, // proxy URL/CA path -> args, env, config files
}

/// Implemented in tailor folders; the kernel never names an ecosystem.
pub trait RegistryProtocol: Sync {
    fn route_id(&self) -> &'static str;                       // "go", "rubygems", "hex", "nuget"
    fn upstream(&self, endpoint: &Endpoint, path: &str) -> io::Result<Url>; // grammar-checked
    fn classify(&self, url: &Url) -> RequestClass;            // index | metadata | artifact | sumdb
    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)>; // digests this metadata promises
    fn content_query_keys(&self) -> &'static [&'static str] { &[] } // kept by redaction
    fn rewrite(&self, _url: &Url, body: Vec<u8>, _base: &ProxyAddress) -> io::Result<Vec<u8>> { Ok(body) }
}
```

Interception needs no `RegistryProtocol` to forward. Registering one for a
host still gives classification, claims, and redaction keys, so npm
packuments feed the tarball `integrity` claims and PyPI JSON feeds the
wheel `sha256` claims.

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
/// `door`: on a staged snapshot, network limited to tog's resolution
/// proxy, outputs published with a signed resolution record. A tailor
/// that cannot make an edit refuses with the exact command to run; the
/// default refuses.
fn edit_manifest(
    &self,
    ctx: &Context,
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    Err(unsupported(self.id(), "add, remove, and update"))
}

/// `tog attest`: run this ecosystem's lock-consistency check through
/// `door`. The default refuses.
fn attest_lock(&self, ctx: &Context, dir: &Path, toolchain: &Selected,
               door: &mut ResolutionDoor<'_>) -> io::Result<()> {
    Err(unsupported(self.id(), "attest"))
}

/// The project files a door of this ecosystem produces, relative to the
/// closure's project directory. The join requires the record's `outputs`
/// to cover every one of them that exists.
fn resolution_outputs(&self, _dir: &Path) -> io::Result<Vec<PathBuf>> { Ok(Vec::new()) }

/// The project files the tool reads to resolve but never writes (other
/// workspace members' manifests, tool config such as `.npmrc` or
/// `.cargo/config.toml`), relative to the closure's project directory.
/// The door records their digests in `inputs`, and the join requires
/// every one that exists to be covered and unchanged.
fn resolution_inputs(&self, _dir: &Path) -> io::Result<Vec<PathBuf>> { Ok(Vec::new()) }
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
tailor's `edit_manifest` unchanged. .NET keeps refusing edits: MSBuild
evaluation is now confined, but `dotnet add package` restores and edits
the project file, and that decision is not part of this design.

### Every door goes through the door

Contract 1 needs enforcement, not review alone:

- **Runtime tripwire.** `kernel::supervise` gains `local_status`,
  `local_status_with_stderr`, and `local_output` for host-local helpers,
  one for each of today's three spawn primitives (`status`,
  `status_with_stderr`, and `output`, `src/kernel/supervise.rs`). Their contract is "this child
  needs no network". They refuse to spawn a program whose file name is in
  `RESOLVERS` (`uv`, `npm`, `npx`, `pnpm`, `cargo`, `go`, `bundle`, `gem`,
  `ruby`, `mix`, `elixir`, `erl`, `dotnet`, `git`) unless the argv matches
  a row of a small reviewed table of offline forms
  (`cargo locate-project ... --offline`, `go` with `GOPROXY=off`; `tar`
  never matches). Helpers that evaluate project files without needing the
  network (the Ruby gate-1 helper, the Elixir `mix.lock` parser) go
  through a door with no routes, which means full network denial. The
  door calls the unrestricted primitive, and so do `sandbox` builds.
  Every other supervise caller moves to `local_*`. That includes
  `tailors/python/build.rs`: its sdist `cargo generate-lockfile` becomes a
  door in PR 1 (`Legacy`) and a proxied door in PR 5. It is not an
  offline-form exemption.
- **Compile-time.** `clippy.toml` adds `tog::kernel::supervise::status`,
  `tog::kernel::supervise::status_with_stderr`, and
  `tog::kernel::supervise::output` to `disallowed-methods`, allowed only in
  `kernel::resolve`, `kernel::sandbox`, and `kernel::supervise` itself,
  each with its reason. That is three kernel sites, not an allow-list row
  per tailor. Any spawn primitive added to `supervise` later joins the
  list in the same PR, and the named test
  `every_public_supervise_spawn_is_fenced` fails if a `pub fn` in
  `kernel::supervise` that takes a `Command` is neither a `local_*`
  function nor on the `disallowed-methods` list.
- **Named test.** `every_resolver_invocation_goes_through_the_door` runs
  the tripwire table against the argv of every census row (including the
  sdist Cargo lock) and fails if a census tool can start through
  `local_*`.

### The transaction

`ResolutionDoor::run` is all-or-nothing for the project. In order:

1. **Preflight.** Load the policy snapshot and signing key. Choose the
   isolation tier. Refuse now if neither `confined` nor `isolated` is
   available, or if `unconfined-resolution` is denied and only
   `isolated` is. First, **recover** any leftover
   publication journal for this project (see "Recovery").
2. **Hold the originals.** Open the lock root through `ProjectRoot` and
   keep the directory descriptor for the whole run. The **held target
   set** is every declared output **plus the existing receipt**
   `.tog/resolution/<ecosystem>.json` (the receipt is never a
   `DelegateSpec` output, since the tool does not write it, but the
   transaction replaces it). Open `.tog/resolution/` through the same
   `ProjectRoot` walk, and keep that directory descriptor too. For each
   target that exists, open it `O_NOFOLLOW` through its directory
   descriptor, copy its bytes into an immutable store stage (the
   **original copy**), and record their sha256 as the pre-run digest. A
   target that does not exist is recorded as `absent`, which step 8
   enforces with a no-replace create.
3. **Snapshot** the lock root and extra roots (socket-free), with the
   baseline manifest. Scan store and system roots for sockets.
4. **Run** the tool (probe first for uv) in its tier, through the proxy.
   Then **stop the whole tree** (see "Quiescence").
5. **Copy and check.** Copy the declared outputs into the immutable output
   copy. Check that the tool succeeded, that no request was refused by
   policy, that the diff holds only declared outputs and declared
   scratch, and that no output copy contains the session token, the proxy
   address, or (macOS) the stage path.
6. **Commit the ledger** and its diagnostics sidecar (store commits:
   staged directory plus rename, as for every object), and register them
   in the project's root record. Build the record from the output copy's
   digests and sign it.
7. **Journal.** Write `.tog/resolution/.journal-<ecosystem>.json` through
   the held descriptor, with `fsync` of the file and the directory. It
   lists, per target (each output, then the record), the target name,
   the temporary name, the original copy's store path and pre-run digest
   (or "absent"), the new digest, and a state (`pending`). The journal's
   presence means "publication may be incomplete". Every tog command that
   writes this project (sync, `add`/`remove`/`update`, `attest`) runs
   recovery before anything else when it finds one. The journal's
   root-record entry keeps the original copies alive until recovery or
   commit.
8. **Publish, one target at a time: swap, then compare.** Write the new
   bytes from the output copy to a temporary name beside the target and
   `fsync` it. Then **atomically exchange** the temporary and the target
   (`renameat2(RENAME_EXCHANGE)` on Linux, `renameatx_np(RENAME_SWAP)` on
   macOS, both through the held directory descriptor). The file now at
   the temporary name is exactly what the target was an instant before
   the swap. Hash it. If it differs from the pre-run digest (the user,
   or anything else, changed the file after step 2), **exchange back**,
   which restores their bytes exactly, and fail. No edit can be read into
   a backup and then overwritten, because the compare runs on the
   displaced bytes after an atomic swap. A target that did not exist is
   created with `renameat2(RENAME_NOREPLACE)` (`renameatx_np(RENAME_EXCL)`
   on macOS), which fails if something appeared in the meantime. After
   each target, mark it `swapped` in the journal and `fsync`. The
   receipt is the last target and gets the same swap-then-compare as
   every output. A receipt edited or replaced during the run (another
   `tog attest`, a `git checkout`, a hand edit) is detected, swapped
   back, and the door fails. A receipt is therefore replaced only here,
   inside a successful transaction, and only if it is still the one held
   at step 2.
9. **Commit point.** When the record has been swapped, mark the journal
   `committed`, `fsync`, delete the displaced temporaries, and delete the
   journal. The resolution is now published.
10. **On any failure before step 8**, nothing has touched the project:
    remove the temporaries and unroot the ledger and sidecar for `tog gc`.
    **On failure during step 8**, undo every `swapped` target in reverse
    order, by exchanging the displaced original back (or removing a
    created file), then delete the journal. The project is byte-for-byte
    as it was.

**Recovery** (at the start of any writing command, after a crash): a
`committed` journal only needs its temporaries and itself deleted. Any
other journal is rolled back target by target. A target whose current
digest is the journal's new digest is restored from its original copy
(or removed if it was absent). A target at its pre-run digest is left
alone. A target at a third digest was edited after the crash, so it is
left alone and reported. Then the journal is deleted. A crash therefore
never leaves a new lock that the next sync accepts silently: after
recovery the project is back at its originals, and the receipt that was
there before (if any) still describes them.

### Failure modes and fail-closed rules

| Failure | Behavior |
|---|---|
| Proxy cannot start (bind, CA generation) | door fails before the tool starts; no direct-network fallback |
| Native sandbox unavailable | next tier per "Isolation tiers"; every tool fails naming each missing capability when neither the container/VM backend nor (Linux) the isolation helper is available. There is no unisolated tier |
| A declared output is not a regular file, or a path to it crosses a symlink | nothing published; the path and its type are named |
| The seccomp filter sees a foreign syscall arch | the process is killed; the door fails with the tool's signal |
| A Mach lookup outside the tool's allow-list (macOS) | Seatbelt denies it; the tool usually fails, and the denial is in the sandbox log the door prints |
| A descendant outlives the tool | the tree is stopped before validation; contents are read only from the immutable output copy |
| Socket found in a mounted root at preflight | door refuses, naming the path |
| Request matches no route and is not interceptable | 403 with a tog body, ledger `refused`; the door fails if the refusal was a policy denial, even when the tool exits 0 (npm tolerates failed optional fetches) |
| `CONNECT` or mirror request without the session token | 407/403, ledger entry; never forwarded |
| Upstream bytes do not match the claimed digest | 502 to the tool, nothing cached, the door fails with both digests named; no stale fallback |
| Redirect to a non-permitted origin | refused; credentials never follow a redirect to another origin |
| Any resolved upstream address is not globally routable (IANA special-purpose registries) | refused (SSRF rule) |
| Transport failure | last-good metadata marked `last-good`; otherwise 504 |
| Relay or proxy thread dies | the tool sees connection refused and fails; the door reports the proxy error first |
| Tool exits non-zero | nothing published; the tool's stderr is shown after any proxy refusal, which is usually the real cause |
| Undeclared change in the snapshot (source files, `.github/`, a new `.git`, `.git/hooks/*`, `.tog/*`) | nothing published; the paths are named |
| An output contains the session token, the proxy address, or the stage path | nothing published |
| A real output changed during the run, at any moment up to its swap | the post-swap compare sees it, the swap is reversed, and nothing stays published; the user's edit is kept byte-for-byte |
| Ledger commit, sidecar commit, record signing, or any swap fails | the transaction rolls back (step 10); the project is unchanged |
| tog is killed mid-run | before step 8 the project is unchanged; after that, the next writing command recovers from the journal |
| Record names an unknown exception kind, isolation value, or schema | hard failure at the join under every policy |
| Record does not cover an existing lock or manifest, or has empty `outputs` | `unrecorded-resolution` (`incomplete` or `malformed`) |

### Performance and caching

- **One proxy per tog process**, started lazily on the first door
  (`OnceLock` in `kernel::resolve`). Startup cost: bind, P-256 keygen, and
  a self-signed CA, well under 10 ms. Sessions are per door run, each with
  its own token and ledger, so concurrent doors in one process stay
  separate.
- **Threads, not async.** tog has no async runtime, and this does not add
  one. Each accepted connection gets a thread from a bounded pool (64).
  Connections beyond that wait in the accept backlog rather than being
  refused, because uv opens up to 50 concurrent downloads by default.
  Upstream uses one shared `ureq` agent with per-host keep-alive and the
  validating resolver. HTTP/1.1 only, in a strict hand-written subset in
  `kernel/resolve/http.rs`: request line and headers up to 64 KiB,
  `Content-Length` or chunked but never both, no obs-fold, no pipelining.
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
  full packuments share a URL): each response is stored with its ETag or
  Last-Modified and its sha256. Online, every metadata request
  revalidates with a conditional GET, which is a 304 when nothing changed.
  It is a cache under the store's GC rules (age-based sweep). Losing it
  costs only refetches.
- **No persistent tool caches in the sandbox.** Each run's uv, npm, pnpm,
  cargo, and Bundler caches live in the run's scratch. A writable cache
  shared across projects is a poisoning path (uv caches wheels it built
  from sdists, and a hostile build could plant one), and it would let a
  cached build hide from the `resolution-build` probe. The proxy cache is
  tog-verified and makes cold tool caches cheap. Go's planner module cache
  stays persistent as today: no third-party code runs in Go resolution,
  and tog re-verifies every module it keeps.
- **Snapshot cost:** see "The staged snapshot". The content-digest
  diff hashes the snapshot twice (the baseline while copying, and the
  post-run walk). SHA-256 runs at roughly 1 to 2 GB/s per core on
  current hardware, and an application tree without the excluded build
  outputs is usually tens of megabytes, so both passes together stay in
  the tens of milliseconds. The post-run walk hashes every file and never
  skips one by timestamp, since a skip would bring back the timestamp
  problem. The budget below includes it.
- **Budget.** A warm `tog add` through the door within 1.2x of today's
  wall time, and a cold one within 1.5x, measured from PR 4 onward on the
  hit-rate projects and reported in each PR. HTTP/1.1 fallback is the
  likely cost for cargo's sparse index, and the snapshot copy on ext4 for
  large repositories. If a PR misses the budget, the fix goes into the
  proxy or the snapshot (connection count, cache hits, exclusions of
  provably unread trees), never into widening the fence.

### Test plan

Offline tests use a fixture upstream: a local HTTP(S) server in
`kernel/testutil` serving a miniature registry per ecosystem from
`tests/fixtures/proxy/registry/<ecosystem>/` (recorded by PR 0, one body per
URL with an `index.json` of status, headers, and digest), with its own test CA passed as the
proxy's upstream root. Endpoint configuration accepts a loopback upstream
only under `cfg(test)`, and the SSRF tests run with that exception
switched off.

Kernel unit tests (`src/kernel/resolve/`):
- `proxy_refuses_requests_without_the_session_token`
- `connect_tunnel_is_authenticated_once_and_bound_to_its_session`
- `inner_requests_of_an_authenticated_tunnel_need_no_token`
- `proxy_routes_only_to_permitted_endpoints`
- `proxy_refuses_every_iana_special_purpose_range`: table-driven, one
  named case per IPv4 and IPv6 registry row listed in the SSRF rule
  (`refuses_100_64_0_0_10_cgnat`, `refuses_198_18_0_0_15_benchmarking`,
  `refuses_fc00_7_ula`, ...), each with an address at the start, middle,
  and end of the range, plus the embedding forms
- `proxy_accepts_a_global_address_next_to_each_refused_range` (the
  adjacent addresses just outside each range pass, so the table is not
  over-broad)
- `iana_special_purpose_table_matches_the_pinned_registry` (parses the
  checked-in registry CSVs and compares them with the compiled table)
- `proxy_connects_only_to_the_validated_address` (a rebinding test
  resolver answers public first and loopback on every later call; the
  connection must reach the public listener, and the resolver must be
  called once)
- `proxy_refuses_when_any_resolved_address_is_private`
- `proxy_keeps_the_hostname_for_sni_and_host`
- `proxy_rechecks_every_redirect_hop_and_drops_credentials_across_origins`
- `proxy_strips_tool_authorization_and_cookies`
- `claimed_digest_mismatch_is_a_hard_failure_and_caches_nothing`
- `transport_failure_serves_last_good_metadata_marked_last_good`
- `last_good_records_stale_resolution_per_endpoint`
- `denied_stale_resolution_turns_last_good_into_504`
- `http_4xx_is_passed_through_not_served_stale`
- `offline_mode_serves_cache_only_and_names_the_first_miss`
- `metadata_cache_key_includes_accept`
- `http_parser_rejects_ambiguous_framing` (CL+TE, obs-fold, oversize headers)
- `interception_mints_leaf_for_sni_host_signed_by_session_ca`
- `connect_without_interception_is_a_visible_refusal`
- `git_scheme_is_refused_as_git_dependency`

Ledger and redaction (`src/kernel/resolve/ledger.rs`):
- `portable_ledger_bytes_are_stable` (golden)
- `portable_ledger_is_independent_of_arrival_order_and_duplicates`
- `portable_ledger_excludes_cache_state_and_platform`
- `resolution_ledger_identity_golden` (the `Identity` bytes and object id)
- `ledger_identity_depends_only_on_portable_bytes` (two runs with the same
  portable evidence and different diagnostics give one ledger id)
- `diagnostics_sidecar_is_a_separate_object_never_named_by_the_record`
- `join_retains_ledger_only_when_present_locally` (a fresh store joins a
  developer's record without failing `ClosureRefs`)
- `ledger_export_import_round_trips_and_rejects_mismatched_bytes`
- `resolution_ledger_kind_is_registered_for_gc`
- `ledger_is_rooted_from_commit_and_retained_through_closure_refs`
- `redaction_removes_userinfo_secret_queries_and_credential_operands`
- `no_known_secret_shape_survives_in_a_ledger` (golden over a corpus of
  presigned URLs, `_authToken` settings, and `-u user:pass`)

Snapshot, sockets, and transaction (`src/kernel/resolve/door.rs`):
- `snapshot_omits_sockets_fifos_and_devices`
- `door_refuses_a_socket_in_a_store_read_root`
- `undeclared_change_publishes_nothing` (a fixture tool edits
  `src/main.rs` and `.github/workflows/x.yml` and exits 0)
- `new_git_directory_publishes_nothing_and_never_reaches_the_project`
- `git_hook_change_publishes_nothing`
- `declared_scratch_is_discarded`
- `descendant_writes_during_publication_do_not_reach_the_project` (both
  platforms; see "Quiescence")
- `linux_tree_is_killed_before_validation`
- `macos_tree_is_frozen_and_killed_before_validation` (including a child
  reparented to `launchd`)
- `user_edit_before_swap_is_restored_by_reverse_exchange` (a test hook
  edits the target between step 2 and its swap)
- `user_edit_after_hold_is_never_copied_into_a_backup`
- `concurrent_receipt_edit_is_swapped_back_and_fails_the_door` (a test
  hook rewrites `.tog/resolution/<eco>.json` between step 2 and its
  swap)
- `receipt_appearing_during_the_run_fails_noreplace`
- `crash_during_receipt_swap_recovers_the_original_receipt` (kills the
  door after the outputs are swapped and while the receipt is swapped,
  then runs recovery: outputs and receipt are back to their original
  bytes)
- `created_target_that_appeared_meanwhile_fails_noreplace`
- `ledger_commit_failure_restores_every_output` (fault injection)
- `sidecar_commit_failure_restores_every_output` (fault injection)
- `swap_failure_mid_publication_rolls_back_every_swapped_target`
- `crash_at_every_journal_state_recovers_to_the_originals` (kills the
  door after each `fsync` point and runs recovery)
- `committed_journal_recovery_only_cleans_up`
- `recovery_leaves_a_target_edited_after_the_crash_and_reports_it`
- `denied_kind_fails_the_door_even_when_the_tool_exits_zero`
- `ledger_only_exceptions_are_recorded_on_the_owner_thread`
- `output_containing_the_token_fails`
- `unconfined_resolution_is_refused_when_denied_and_recorded_otherwise`
- `no_tool_runs_unisolated_when_no_tier_is_available` (every census
  tool, with and without `TOG_SIGNING_KEY` set, and with a key file on
  disk but the variable unset: the command fails naming the missing
  capability)
- `npm_forced_settings_never_run_the_project_git_or_script_shell` (a
  fixture `.npmrc` sets `git=` and `script-shell=` to a marker program)
- `cargo_forced_settings_never_run_project_wrappers_or_credential_providers`
  (a fixture `.cargo/config.toml` sets `build.rustc-wrapper`,
  `build.rustc`, and a `credential-provider` to a marker program)
- `forced_program_settings_hold_for_every_census_tool` (table-driven
  over the "Forced program settings" rows)
- `door_profile_denies_reading_the_signing_key`
- `keygen_refuses_a_path_under_a_system_read_root`
- `declared_output_symlink_fails_the_door`
- `declared_output_parent_dir_symlink_fails_the_door`
- `declared_output_replaced_by_fifo_fails_the_door`
- `diff_detects_same_second_rewrite_by_content` (a fixture tool rewrites
  an undeclared file with different bytes of the same size and restores
  its mtime)
- `diff_ignores_a_byte_identical_rewrite_of_an_undeclared_file`
- `container_backend_is_used_when_user_namespaces_are_unavailable`
- `isolate_helper_allocates_distinct_uids_to_concurrent_sessions`
- `isolate_helper_never_reuses_a_uid_with_a_live_process`
- `isolate_survivor_is_killed_by_cgroup_kill_before_validation` (a
  double-forked, `setsid` child that ignores `SIGTERM`; validation must
  not start until `populated 0`)
- `isolate_populated_timeout_fails_and_keeps_the_uid_allocated`
- `isolate_run_cannot_leave_its_cgroup`
- `isolate_concurrent_session_cannot_read_or_write_another_stage` (two
  runs in parallel; each tries to open, list, and write the other's stage
  and `/tmp`)
- `isolate_run_cannot_read_the_signing_key_or_the_real_project`
- `isolate_tmp_is_private_and_wiped` (a file left in `/tmp` by one run is
  absent in the next run that gets the same UID)
- `isolate_helper_fences_network_when_it_can_and_records_confined`
- `isolate_handover_does_not_follow_symlinks` (a stage symlink to a
  root-owned file keeps that file's owner)
- `isolate_handover_refuses_hardlinks`
- `macos_has_no_isolated_tier` (with Seatbelt disabled by a test hook
  and no VM backend, the door fails with the missing-capability message)
- `missing_isolation_message_names_every_missing_capability`
- `every_resolver_invocation_goes_through_the_door` (tripwire table vs census)
- `local_supervise_refuses_resolver_programs` (all three `local_*`
  functions)
- `every_public_supervise_spawn_is_fenced`

Sandbox tests (`tests/sandbox_deny.rs`, extended, not a new file, per §4):
- `linux_door_reaches_only_the_proxy` (curl to a host-side listener
  fails, to the relay succeeds)
- `linux_door_has_no_dns`
- `linux_door_does_not_mount_the_real_project`
- `linux_door_descendants_die_with_the_relay`
- `linux_door_cannot_connect_to_a_socket_in_a_read_root` (a listening
  socket planted in a declared store read root with the preflight scan
  bypassed by a test hook: connect fails through seccomp)
- `linux_door_cannot_connect_to_a_socket_created_after_preflight` (the
  host creates a listening socket in a mounted root after the scan: the
  tool's `socket(AF_UNIX)` fails with `EAFNOSUPPORT`)
- `linux_door_socketpair_still_works` (Node spawns a child with pipes)
- `linux_door_exec_log_records_every_exec`
- `linux_door_filter_kills_a_foreign_syscall_arch` (an `int 0x80`
  `socketcall` from the 32-bit table, and an x32-bit syscall number)
- `linux_door_denies_io_uring_setup`
- `linux_door_tool_cannot_ptrace_or_read_the_relay` (`ptrace` attach and
  `/proc/<relay>/mem` both fail)
- `macos_door_reaches_only_the_proxy_port`
- `macos_door_cannot_resolve_names` (mDNSResponder is not on any
  allow-list)
- `macos_door_cannot_open_urls_or_apps` (`/usr/bin/open` of a URL and of
  an app both fail, and LaunchServices lookups are denied)
- `macos_door_cannot_reach_nsurlsessiond` (an `NSURLSession` background
  download fails)
- `macos_door_mach_allow_list_matches_pr0_measurement` (the compiled
  per-tool list equals the checked-in measurement, and contains no
  service from the forbidden list)
- `macos_door_cannot_connect_to_a_host_unix_socket` (both the read-root
  and after-preflight cases)
- `macos_door_cannot_read_or_write_the_real_project`

Attestation, join, and audit (`tests/cli.rs` and `src/comforter/`):
- `signed_record_joins_closure_when_outputs_match`
- `deleted_record_yields_unrecorded_resolution`
- `edited_record_yields_unrecorded_resolution` (removing
  `unconfined-resolution` from the body)
- `record_signed_by_untrusted_key_yields_unrecorded_resolution`
- `unsigned_record_yields_unrecorded_resolution_and_is_kept`
- `stale_record_yields_unrecorded_resolution_and_is_left_untouched`
- `denied_unrecorded_resolution_leaves_the_checkout_unchanged`
- `stale_receipt_is_replaced_only_by_a_successful_transaction`
- `join_hard_fails_an_unknown_exception_kind_under_permissive_policy`
- `join_hard_fails_an_unsupported_schema_in_an_authenticated_record`
  (a validly signed `resolution/2`)
- `join_hard_fails_an_unknown_isolation_value_in_an_authenticated_record`
- `unauthenticated_record_with_an_unknown_schema_is_unrecorded_not_fatal`
- `signed_supported_record_missing_a_field_is_malformed_not_fatal`
- `record_signature_key_is_bare_hex_and_verifies_with_kernel_signing`
- `unattested_record_exceptions_are_ignored`
- `company_policy_denies_unrecorded_resolution_under_frozen_sync`
- `tog_attest_signs_an_unchanged_lock_and_refuses_a_changed_one`
- `joined_exceptions_are_not_duplicated_by_sync`
- `attribution_claim_removes_exact_duplicates`
- `audit_denies_unconfined_resolution_under_company_policy`
- `audit_fails_closed_on_an_unknown_resolution_kind`
- `closure_readers_accept_the_resolution_field`
- `record_body_has_no_timestamps_port_platform_or_engine`
- `record_not_covering_the_lock_is_unrecorded` (a signed record whose
  `outputs` name `package.json` but not the existing
  `package-lock.json`: `unrecorded-resolution`, reason `incomplete`)
- `record_with_empty_outputs_is_malformed`
- `record_naming_a_path_outside_the_tailor_lists_is_malformed`
- `record_for_another_project_with_the_same_lock_is_unrecorded` (same
  lock bytes, different manifest: `stale-outputs` or `stale-inputs`)
- `edited_workspace_member_manifest_is_stale_inputs`
- `strict_sync_refuses_unrecorded_lock_with_keygen_and_attest_remedy`
- `strict_sync_with_stale_record_says_attest_not_keygen`
- `strict_last_good_fetch_fails_naming_the_url_and_reason`
- `strict_refuses_the_isolated_tier_before_the_tool_starts`
- `ci_record_artifact_attests_through_resolution_record_flag`
- `supplied_record_for_another_project_is_incomplete_or_stale`
- `supplied_record_is_never_written_into_the_project`
- `committed_record_from_bot_flow_attests_without_flag`
- `attest_record_out_leaves_the_checkout_unchanged`

Per ecosystem, offline against fixtures (one per migration PR):
- `go_get_through_mirror_uses_proxied_sumdb`
- `cargo_add_through_interception_keeps_crates_io_source_in_lock`
- `sdist_cargo_lock_generation_goes_through_the_door`
- `npm_add_through_interception_lock_matches_direct_run` (byte-identical
  lock versus the same npm run against the fixture directly)
- `pnpm_add_through_interception_lock_matches_direct_run` (and asserts
  the `--http-proxy`/`--https-proxy`/`--no-proxy` flags took effect)
- `uv_add_through_interception_lock_matches_direct_run`
- `uv_add_forces_the_public_default_index`
- `uv_probe_without_build_records_nothing`
- `uv_probe_needing_a_build_records_resolution_build_and_reruns`
- `uv_probe_needing_a_build_fails_when_denied`
- `uv_project_self_build_is_not_resolution_build`
- `bundle_add_through_mirror_keeps_rubygems_remote`
- `bundle_other_source_is_refused_as_unattested_index`
- `mix_deps_update_through_hex_mirror_keeps_signature_check`
- `dotnet_missing_lock_restore_through_nuget_mirror`
- `dotnet_restore_runs_without_unix_sockets`
- `git_dependency_through_interception_records_commit`
- `npm_url_dependency_is_intercepted_and_recorded`

Network (`--ignored`, run on Linux and the Mac): the ten existing
`deps_e2e` round trips, unchanged in expectations, now running through the
door, plus one live missing-lock generation and one `tog attest` per
ecosystem.

### Implementation plan (PRs, in order)

**PR 0: evidence spike (docs and fixtures only).** For each tool, run the
census invocations through a logging interception proxy and record every
request (host, path, method, redirect chain) in a table in this section.
Confirm each † claim: the pnpm proxy flags, npm `--cafile`, uv's
`SSL_CERT_FILE`, `--no-build` error form and `--no-build-package`, every
tool's lock check for `tog attest`, every census tool running under
the AF_UNIX seccomp filter (with `io_uring_setup` denied), each tool's
**program-naming settings** (the "Forced program settings" table, from
the tool's documentation and source, each proven with a marker-program
fixture), and each tool's **macOS Mach allow-list** (measured under a
reporting `(deny mach-lookup)` profile, checked against the forbidden
services list). Capture fixture registries for the offline
tests. Nothing is built on an unconfirmed claim. A † claim that fails
changes that ecosystem's row here first, and a finding that only a mirror
works for an intercept-planned tool means that tool gets response and
lock rewriting designed here before its PR. **Status: done on Linux**
(#197, see "PR 0 evidence"). Every intercept-planned tool worked through
interception, so no tool moves to a mirror. The refuted claims changed
the pnpm, cargo, Go, Ruby, Elixir, .NET, and git rows, the uv
`resolution-build` probe, and the pnpm, git, and Go forced settings. The
macOS Mach allow-list and the Seatbelt port rule are **pending: needs a
macOS host** (`tools/proxy_spike/macos_mach.sh`), and no macOS door
ships before they are measured.

**PR 1: the door type, #61 and #169 (moves only, no behavior change).**
Add `kernel::resolve::ResolutionDoor` with a single `Legacy` mode that
runs exactly today's command, unsandboxed and inheriting the environment,
with no snapshot, and records nothing new. Route every census row through
`door.run`, including `tailors/python/build.rs`'s sdist
`cargo generate-lockfile`. Add `Tailor::edit_manifest`, move each
delegate from `commands/deps.rs` into its tailor, move `realize_node_tool`
and `verify_corepack_hash` into `src/tailors/node/`, change `prepare` and
`RegistryTool::realize` to take the door, and add
`Tailor::registry_exists`. Add the `local_*` supervise split, the
tripwire, and the clippy entries. This follows layering rule 7 ("moves
are not rewrites"): every golden and every test output stays identical.
After it, #61's grep is empty and every door is in one place.

**PR 2: proxy core.** The HTTP subset, routes and `RegistryProtocol`,
tunnel authentication, the forward proxy with visible refusal, the
validating resolver (SSRF pinning) with the IANA special-purpose table
and its per-range tests, the portable ledger and the diagnostics
sidecar, redaction, the `resolution-ledger` and `resolution-diagnostics`
kinds and identities (portable bytes only for the ledger), the metadata
cache, the
artifact-cache integration, redirect rules, offline mode, and the
last-good path with its `freshness` marking and the per-session switch
that turns last-good into 504 when `stale-resolution` is denied. Kernel unit
tests against the fixture upstream. No tool uses it yet.

**PR 3: confinement and the transaction.** The staged snapshot and diff,
tree quiescence on both platforms, the immutable output copy, the
transaction (held originals, swap-then-compare publication, the journal,
and recovery), the `Proxy` network mode for both sandbox engines, the
`__resolution-relay` subcommand, the AF_UNIX seccomp filter and exec log,
the seccomp arch check and `io_uring` and `ptrace` denials, the relay's
`PR_SET_DUMPABLE=0`, the all-roots socket scan, the content-digest diff,
the regular-file rule for declared outputs (`openat2` with
`RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS` on Linux, per-component
`O_NOFOLLOW` on macOS), the forced program settings for every tool row,
the tier rule (native sandbox only in this PR; no unisolated tier, so a
host without it fails with the missing-capability message until PR 3b),
the signing-key read deny and the `tog keygen` path check, the
`unconfined-resolution` kind, and the sandbox, quiescence, and
transaction tests. On the Mac: the Seatbelt rules, the deny-by-default
Mach profile with the per-tool allow-lists from PR 0, and the same
deny-by-default Mach rule for the **build** profile (known gap 1).

**PR 3b: the other isolation backends.** The Linux container backend
(podman/docker, the pinned minimal image, `--network none`, the same
relay and seccomp filter) and the Linux `tog-isolate` helper (per-run UID
allocation, cgroup v2 leaf with `cgroup.kill` and the `populated 0`
gate, private mount and network namespaces, 0700 per-run stages, release
and `--reap`, `tog doctor --isolation`), with the survivor and
concurrent-session tests. The macOS VM backend follows the
`aarch64-unknown-linux-gnu` platform rows and is not in this PR. Until it lands, a host without the native
sandbox fails with the missing-capability message, which is the
fail-closed outcome.

**PR 4: Go end to end, attestation, and the join.** Switch the Go rows to
the proxied mode (mirror plus sumdb), including the planner doors that
run on ordinary syncs (known gap 3, Go half). Add the signed resolution
record in the closure envelope format (bare-hex key), key loading for the
edit verbs, the join in `write_closure_inner` (kind, isolation, and
schema validation with hard failure on unknowns; stale receipts left
untouched), `ClosureRefs` retention only for locally present ledgers,
`tog attest --ledger-export` and `--ledger-import`,
`unrecorded-resolution`, `stale-resolution`,
`Tailor::resolution_outputs` and `Tailor::resolution_inputs` with the
join's coverage rule (every existing output covered, empty `outputs`
malformed, `inputs` digests checked), `tog attest` with Go's lock check,
`tog attest --record-out` and `tog sync --resolution-record` (the CI
artifact flow) beside the committed-record bot flow, both with their
named tests, the `--strict` outcomes (the `unrecorded-resolution` remedy
text naming `tog keygen` and `tog attest`, and the precise last-good
refusal) with their tests, the `docs/human/CLI.md` update for
`--strict`, `TOG_STRICT`, `--record-out`, and `--resolution-record`, the
per-developer key path (a laptop key in the machine `[signing]` set
attests a record exactly as a CI key does, with
`developer_key_record_attests_when_trusted` and
`developer_key_record_is_unrecorded_when_not_trusted`),
`Attribution::claim` dedupe (known gap 5), and the attestation and audit
tests. Go goes first because it has no code execution, no TLS, and no
lock URLs.

**PR 5: interception.** The session CA, leaf minting, TLS termination
(`rcgen` and rustls server, `ring` provider pinned), and the git row.
Switch cargo (interception plus git) and the sdist
`cargo generate-lockfile` in `tailors/python/build.rs`. Cargo `attest`.

**PR 6: Node.** npm and pnpm (edit, missing lock, `x`, `attest`), with the
byte-identical-lock tests and the corrected pnpm flags.

**PR 7: Python.** uv (edit, missing lock, build requirements, `x`,
`attest`), the default index forced on every uv invocation (known gap 2),
the `--no-build` probe, and `resolution-build`.

**PR 8: Ruby and Elixir.** Bundler mirror and Hex mirror, the visible
refusals, the Ruby gate-1 helper and Elixir lock parser behind no-route
doors, and mix `deps.get --check-locked` on ordinary syncs through the
proxy (known gap 3, Elixir half). `attest` for both.

**PR 9: .NET.** The `nuget.config` mirror with service-index rewriting,
the no-Unix-socket restore settings, and missing-lock restore confined,
which closes the LIMITATIONS row "Restore-time MSBuild evaluation runs
unsandboxed" (known gap 4). `attest` with `--locked-mode`.

**PR 10: remove `Legacy`.** Delete the mode. The company template denies
`unconfined-resolution` and `unrecorded-resolution`, lists
`resolution-build` and `stale-resolution` as deliberately not denied with
their reasons, and its comment names `tog attest` as the migration step.
The README documents both signing setups: `tog attest` in a separate CI
job, the default, and per-developer keys in the machine `[signing]`
set. The CI setup is the worked GitHub Actions example from
"Attestation" (an `attest` job that holds the key and uploads
`--record-out` records as an artifact, a keyless `gate` job running
`tog --strict sync --frozen --resolution-record`, and a separate `test`
job), with the bot-commit flow as the documented alternative. ARCHITECTURE gains a "Resolution
doors" section with the census as a covered/not-covered table (WP5's
"state which doors are covered"). LIMITATIONS rows are rewritten: the
`add`/`remove`/`update` row, "Delegated planning runs unsandboxed", the
audit paragraph's "does not cover the doors" sentence, and the .NET
restore row. CLI.md documents `tog attest`, the new notes, and the new
errors. The README `.gitignore` stanza gains `!**/.tog/resolution/`.
FOLLOW-UPS "Delegated-tool doors" is deleted and #68 closed.

Each PR from 3 on runs its ecosystem's `--ignored` tests on the Mac
before merge, and PR 3 also runs `tests/sandbox_deny.rs` there.

### Known gaps found while designing

Found in today's code while writing this section. None is fixed by the
design commit itself; each has a slot above.

1. **Seatbelt Mach escapes in the build sandbox.** The build profile
   allows `mach-lookup` wholesale, so sandboxed builds can resolve names
   and send data out through mDNSResponder, open URLs and apps through
   LaunchServices, and download through `nsurlsessiond`
   (`src/kernel/sandbox.rs`, `Sandbox::profile`). Slot: PR 3, which moves
   the build profile to `(deny mach-lookup)` plus an allow-list measured
   the same way as the door's, over every build fixture in the test
   suite, with the same forbidden-services check, and adds
   `macos_build_cannot_resolve_names` and
   `macos_build_cannot_open_urls_or_apps` to `tests/sandbox_deny.rs`.
2. **`uv add` / `remove` / `lock` do not force the index.** Only
   `pip compile` passes `--index-url https://pypi.org/simple`, so
   `[[tool.uv.index]]` entries in `pyproject.toml` are contacted directly
   during edits (`src/commands/deps.rs`, `uv_command`/`python_uv`). Slot:
   PR 7 (`--default-index` on every uv invocation, extra indexes
   through interception as `unattested-index`).
3. **Go and mix reach the network on ordinary syncs**, not only when a
   lock is missing: Go's `mod tidy -diff` and `mod download -json all` on
   a plan-cache miss, and mix `deps.get --check-locked` when its inputs
   changed since its last pass in the project
   (`src/tailors/go/mod.rs`, `src/tailors/elixir/mod.rs`). Slot: PR 4
   (Go) and PR 8 (Elixir), as planner doors.
4. **`dotnet restore` runs the project's MSBuild on the host** during
   missing-lock generation (`src/tailors/dotnet/mod.rs`, `plan_dotnet`).
   Slot: PR 9.
5. **Exception frames have no dedupe.** `policy::record_with` pushes every
   record, so the same `(kind, subject, detail)` can appear twice in a
   closure (`src/kernel/policy.rs`). Slot: PR 4 (`Attribution::claim`
   removes exact duplicates, `attribution_claim_removes_exact_duplicates`).

### Adversarial self-check

Holes found in the drafts (round 0 by the author, round 1 by review), and
where the design above closes each:

1. *"Scrub the user's environment" misses variables nobody listed*
   (`CARGO_REGISTRIES_*`, `UV_*` added in a newer uv, `NODE_OPTIONS`
   `--require`). Fixed: the door's environment starts empty (contract 2).
   Under confinement a leaked setting can only fail to connect. Unfenced
   tiers are denied by the company template.
2. *Project config files re-point the tool* (`.npmrc registry=`,
   `[tool.uv] index-url`, `.cargo/config.toml` `[source]`,
   `.bundle/config`). Under confinement they can only make resolution
   fail, never reach another host. The forced routing flags exist for
   correct routing. The forced **program** settings are a security
   control (item 40). Parent-directory configs outside the project
   (cargo walks up to `~/.cargo/config.toml`) are not readable in the
   sandbox.
3. *A mirror leaks `127.0.0.1:<port>` into committed locks.* Fixed by
   choosing interception for every tool whose lock records URLs, plus the
   token, address, and stage-path scan of outputs (contract 8).
4. *Sandboxed code uses the proxy as an SSRF pivot* to cloud metadata or
   localhost services, including by DNS rebinding between the check and
   the connection. Fixed by resolving once, validating every address,
   and connecting only to a validated `SocketAddr` (review 4).
5. *Another local user or process on macOS uses the proxy* (and, after
   WP5, its credentials). Fixed by the session token: once per `CONNECT`
   tunnel, and in the path for mirror routes (review 10).
6. *Double-counted exceptions* between the proxy and sync's lock-derived
   records. Fixed by the ledger-only split plus claim-time dedupe.
7. *The proxy thread records into an attribution it does not own.* Fixed:
   the proxy only calls `policy::denied`; the owner thread records.
8. *A tool treats a refused optional fetch as success*, so a policy denial
   is silently swallowed. Fixed: any policy refusal fails the door
   regardless of exit status.
9. *Resolution-time code rewrites project files*: sources, `Makefile`,
   `.github/workflows/publish.yml`, `.git/hooks`, a new `.git`. Fixed:
   the tool runs on a snapshot, the real project is never writable, and
   only declared outputs are published after the diff passes (review 2).
10. *A host Unix socket bypasses the network namespace*, whether planted
    in a read root or created after preflight. Fixed by the socket-free
    snapshot, the all-roots scan, and the AF_UNIX seccomp filter on
    Linux (with the arch check and the `io_uring` deny, item 45), and on
    macOS by Seatbelt's network deny. The first draft of this item said
    macOS was closed by the network deny alone. That was wrong while the
    profile allowed every `mach-lookup`: a Mach service is a socket-like
    door the network rule does not cover, and several of them act for the
    caller outside the sandbox. It holds now because the door profile
    denies `mach-lookup` by default (item 38) (review 3, review 4.1).
11. *The committed record is unauthenticated*, so deleting it, replacing
    it, or editing out `unconfined-resolution` would pass a company gate.
    Fixed: records are signed with the closure key, only attesting
    records reach the closure, and anything else is
    `unrecorded-resolution`, which the company template denies (review 1).
    The first draft's claim that forgery "can only add exceptions" was
    wrong and is gone.
12. *A failed ledger or record write leaves an accepted lock.* Fixed: the
    transaction publishes nothing unless the ledger commits and the
    record is staged, and it rolls back on any rename failure (review 5).
13. *A census row was missing*: the sdist `cargo generate-lockfile` in
    `tailors/python/build.rs`. Added, routed in PR 1 and proxied in PR 5
    (review 6).
14. *The ledger was a hash, not a store object*, so GC could sweep it,
    and it could persist presigned URLs or tokens. Fixed: the
    `resolution-ledger` identity and kind, retention from commit, and the
    redactor (review 7).
15. *The "canonical" ledger was not stable*: duplicate order, cache state,
    and machine fields in the committed record. Fixed: portable evidence
    versus diagnostics, set semantics sorted by full entry bytes, and a
    record body without engine, platform, or tool object ids (review 8).
16. *`resolution-build` was inferred from an sdist fetch*, which over- and
    under-reports. Fixed: the `--no-build` probe establishes it by
    construction on both platforms, with per-run caches and the Linux
    exec log as a cross-check (review 9).
17. *Wrong pnpm flags, a per-request token inside tunnels, and "the tog CA
    alone prevents direct TLS" for Node.* Fixed in the wiring table and
    in "What the CA file does and does not prevent" (review 10).
18. *Stale metadata masks a yanked or security release.* Stale serving
    happens only on transport failure and is marked per entry in the
    portable evidence, so it is inside the signed record's digest. The
    bytes are still verified. It is also the policy kind
    `stale-resolution`, so a company can deny it (see "Decisions").
19. *Buffering large artifacts stalls resolution.* Few artifacts are
    fetched during resolution. See Performance.
20. *Cross-project poisoning through a shared tool cache.* Fixed: tool
    caches are per run.
21. *A lingering descendant writes after tog's checks.* Superseded by item
    27: the tree is stopped first, and only the immutable copy is read.
22. *#61 lands before the proxy and bakes in an unconfined signature.*
    Fixed by ordering: PR 1 puts the door type in the signature from day
    one, in `Legacy` mode, so no later PR changes the trait.
23. *`--no-sync` edits never join.* The signed record persists in
    `.tog/resolution/`, and the ledger is rooted from commit, so the next
    sync joins it if the outputs are unchanged.
24. *Credentials in the project `.npmrc` (`//registry.npmjs.org/:_authToken`)
    reach the proxy.* They are stripped and never forwarded. Redaction
    keeps them out of the ledger, and private registries use WP5
    credential references held by tog.
25. *The unconfined fallback runs a hostile Gemfile, `mix.exs`, or MSBuild
    project as the user.* It could edit the real repository outside the
    transaction, read `~/.tog` signing keys, and forge a clean receipt.
    Fixed: code-evaluating tools never run without filesystem isolation
    (container/VM backend or, on Linux, the per-run isolation helper as
    fallbacks, otherwise a failure naming what is missing). Since round
    4, no resolver of any class runs without isolation (item 40)
    (review 2.1).
26. *A developer's record names a ledger that CI does not have*, and
    `ClosureRefs` would reject the missing object. Fixed: verifying the
    record never needs the object, the ledger is retained only when
    present locally, and `--ledger-export`/`--ledger-import` move it when
    wanted (review 2.2).
27. *macOS descendants race validation and publication.* Fixed: the tree
    is stopped before validation, and every content check, the
    signature, and publication read an immutable copy (review 2.3).
28. *The ledger id hashed the diagnostics*, so the "portable" record
    changed between machines. Fixed: the identity covers only portable
    bytes, and diagnostics are a separate sidecar object (review 2.4).
29. *A user edit between the recheck and the backup was silently
    overwritten.* Fixed: originals are copied through a held descriptor
    before the run, each target is atomically exchanged and the displaced
    bytes are compared (a mismatch is swapped back), and a journal makes
    a crash recoverable (review 2.5).
30. *The SSRF list missed non-global ranges* such as CGNAT
    `100.64.0.0/10` and benchmarking `198.18.0.0/15`. Fixed: everything
    the IANA special-purpose registries do not mark globally reachable
    is refused, with a test per range (review 2.6).
31. *An older tog silently accepts unknown kinds from a newer signed
    record*, because `record_with` takes free strings. Fixed: the join
    validates every kind against `policy::KINDS` and fails hard on
    unknowns (review 2.7).
32. *The join deleted stale receipts*, destroying evidence and mutating
    the checkout during validation. Fixed: the join never writes. Receipts
    are replaced only by a successful transaction (review 2.8).
33. *The record's `signature.key` example used the prefixed policy
    syntax.* Fixed: bare hex, the envelope `kernel/signing.rs` already
    writes and verifies (review 2.9).

34. *A shared resolver UID lets one run tamper with another*, and a
    survivor outlives quiescence, so the developer's tog signs outputs a
    different run changed. Fixed: per-run ephemeral UIDs from a reserved
    range, 0700 per-run stages, private mount namespaces, and a cgroup v2
    leaf killed and checked for `populated 0` before validation. macOS has
    no such tier (review 3.1).
35. *The receipt was replaced without being held*, so a concurrent edit or
    a crash mid-swap could lose its exact bytes. Fixed: the receipt is in
    the held target set, with swap-then-compare and journal recovery like
    every output (review 3.2).
36. *An unsupported schema in a signed record fell through to
    `malformed`*, which permissive policy accepts. Fixed: the raw envelope
    is authenticated first, and schema, isolation, and kinds are checked
    as strings before typed parsing (review 3.3).
37. *"Two parts, one object" contradicted the sidecar.* Fixed wording:
    two related objects, and diagnostics never enter portable or
    project-committed data (review 3.4).
38. *The macOS door allowed every Mach service*, so a tool could open a
    URL or an app through LaunchServices (`/usr/bin/open`), download or
    upload through `nsurlsessiond`, or ask `securityd` for credentials,
    all outside Seatbelt. Fixed: the door profile starts from `(deny
    mach-lookup)` and allows only each tool's measured list, PR 0 fails a
    list that includes a service that acts for the caller, and the build
    profile gets the same rule (known gap 1). Tests
    `macos_door_cannot_open_urls_or_apps` and
    `macos_door_cannot_reach_nsurlsessiond` (review 4.1).
39. *A declared output replaced by a symlink* (to `~/.ssh/id_ed25519`, or
    to another project's lock) would be copied, signed, and published.
    Fixed: declared outputs must be regular files, opened with `openat2`
    and `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS` from the held stage
    descriptor (per-component `O_NOFOLLOW` on macOS), and the isolation
    helper's hand-over uses `fchownat(AT_SYMLINK_NOFOLLOW)`, never
    descends a symlink, and refuses hard links (review 4.2).
40. *Tier `none` trusted "resolve-only" tools*, but npm (`git=`,
    `script-shell=`) and cargo (`build.rustc-wrapper`, credential
    providers) run programs a project config names. Fixed: the tier is
    removed, every tool runs `confined` or `isolated`, and every
    program-naming setting of each tool is forced, listed and proven in
    PR 0. With nothing conditioned on key presence, the "is a key
    configured" check that could misread an existing key file is gone
    (review 4.3).
41. *A signed record could cover part of a project*, for example
    `package.json` without the lock, or be copied to another project with
    the same lock bytes. Fixed: the join requires `outputs` to cover every
    existing file in `resolution_outputs`, treats empty `outputs` as
    malformed, and binds the project's manifests and tool configs through
    the signed `inputs` digests. Test
    `record_not_covering_the_lock_is_unrecorded` (review 4.4).
42. *`--strict` became unusable without saying why*, since it denies
    `unrecorded-resolution` and `stale-resolution` from PR 4 on. Fixed:
    the refusal names the remedy (`tog keygen`, `TOG_SIGNING_KEY`, the
    trusted list, `tog attest`), a stale record is told to re-attest, the
    last-good refusal names the URL and why the fetch failed, and CLI.md
    says so in PR 4 (review 4.5).
43. *The CI flow required a bot commit.* Fixed: `tog attest --record-out`
    writes records to a CI artifact and `tog sync --resolution-record`
    feeds them to the same join. The bot-commit flow stays as an
    alternative through the same verification. A worked GitHub Actions
    example is in "Attestation" and goes to the README in PR 10
    (review 4.6).
44. *`supervise::status_with_stderr` was outside the fence.* Fixed: it is
    on the `disallowed-methods` list with a `local_*` twin, and
    `every_public_supervise_spawn_is_fenced` catches the next one
    (review 4.7).
45. *The seccomp filter could be sidestepped* by a foreign syscall table
    (`int 0x80` `socketcall` on x86-64, x32 numbers), by an io_uring
    ring, or by tracing the unfiltered relay. Fixed: the filter checks
    `seccomp_data.arch` first and kills on mismatch, denies the io_uring
    and `ptrace`-family calls, and the relay sets `PR_SET_DUMPABLE=0`
    (review 4.8).
46. *The diff trusted ctime*, which misses a same-size rewrite within one
    timestamp tick on coarse filesystems. Fixed: the baseline records
    content digests and the diff compares by content (review 4.9).

### Review round 1

Codex (Sol), 2026-09-23, verdict "changes needed", ten findings: an
unauthenticated record (blocker), writable project root (blocker), host
Unix sockets (blocker), DNS-rebinding SSRF, non-transactional ledger and
record writes, a missing census row, no ledger identity or redaction, an
unstable canonical form, an unobservable build fact, and wrong pnpm and
proxy-authentication wiring. Every one is fixed above (self-check items
4, 5, and 9–17). None was downgraded to a documented limitation. The one
residual channel stated as documented (data encoded in request paths to
a permitted registry, under "What this does not claim") says why no
enforceable design exists.

### Review round 2

Codex (Sol), 2026-09-23, verdict "changes needed", nine findings. The
blockers were the unconfined fallback reaching the real project and the
signing key, developer ledgers missing on CI, and macOS stragglers racing
publication. The majors were a machine-dependent ledger id, an
edit-overwrite gap between recheck and backup, incomplete SSRF ranges,
unknown kinds accepted at the join, and stale receipts deleted by the
join. The minor was the key format in the record example. All nine are
fixed above (self-check items 25–33), with the coordinator's choices:
isolation tiers instead of an unconfined fallback, the portable-only
ledger identity with an optional local object and export/import,
quiescence plus an immutable output copy, a diagnostics sidecar, held
originals with swap-then-compare and a journal, the full IANA tables,
hard failure on unknown kinds, receipts replaced only by successful
transactions, and bare hex.

### Review round 3

Codex (Sol), 2026-09-23, verdict "changes needed", four findings: the
shared resolver UID (blocker), the receipt missing from the held target
set, a schema check that could not be reached, and the ledger wording.
Fixed as self-check items 34–37, with the coordinator's choices: per-run
ephemeral identities with cgroup v2 containment on Linux, no isolated
tier on macOS (container/VM backend only), the receipt held and swapped
like an output, and authentication before version checks.

### Review round 4

Claude (Opus), 2026-09-23, standing in while Codex was out of quota,
nine findings: the macOS door allowed every Mach service (blocker),
symlinked declared outputs, tier `none` running tools that can be told
to run project programs, records that did not have to cover the lock or
name the project, the unstated `--strict` outcome, a CI flow that needed
a bot commit, `status_with_stderr` outside the fence, three seccomp
gaps, and a ctime diff. All nine are fixed above (self-check items
38–46), with the coordinator's choices: deny `mach-lookup` by default
with measured per-tool allow-lists, regular-file outputs opened without
following symlinks, tier `none` removed and program settings forced, a
coverage rule plus signed manifest digests, the strict remedy text in
PR 4, the record-artifact CI flow with the bot commit as an alternative,
the fence extended, the filter hardened, and a content-digest diff.

### Decisions

Owner decisions, 2026-09-23, choosing the flexible option each time:

- **Stale metadata is the policy kind `stale-resolution`.** It is recorded
  whenever the proxy served last-good metadata (transport failure or
  `--offline`). It is permitted by default, deniable by any policy, and
  always marked per entry as `freshness: last-good` in the portable
  evidence, which the signature covers. A company that must never
  resolve against old metadata denies the kind: the proxy then answers
  504 instead of serving last-good, and the door fails naming the URL.
  Everyone else gets the resilience. Rollout: PR 2 (serving, marking,
  and the deny switch) and PR 4 (the kind, joined through the record).
- **Signing: `tog attest` on CI is the documented default, and
  per-developer keys are also supported.** Both go through the same
  verification: a record attests when its key is in the machine policy's
  `[signing] trusted` set. A team either runs `tog attest` in CI, which
  keeps signing keys off laptops, or distributes per-developer keys into
  the machine `[signing]` set, so a laptop `tog add` attests directly.
  The standing rule holds either way: a job that runs untrusted project
  code must not hold a signing key, so CI attests in a separate job from
  the one that runs the project's tests. (The key stays in the tog
  process and is never in a sandbox read root, but the test job runs the
  project's code outside any sandbox.) Rollout: PR 4 (both paths and
  their tests) and PR 10 (the README's two setups).


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

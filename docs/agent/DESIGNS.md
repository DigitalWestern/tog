# DESIGNS — work that is designed but not built

The one agent-facing design file. Everything here is **future work**: nothing
in it describes shipped behavior (for that, read `docs/human/ARCHITECTURE.md`).
Open decisions and the ordered to-do list live in `FOLLOW-UPS.md`; this file
holds the detail a session needs to pick an item up cold.

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
work-package names (WP1 is `blanket fmt`, shipped) and "GC Package A–D"
the shipped GC-safety work; both are kept because FOLLOW-UPS and commit
history use them.

## Contents

1. Toolchain lock and exact version selection (WP2)
2. Release catalog and publisher trust (WP3)
3. Daily-driver gaps (WP4 open items)
4. The company layer (WP5)
5. GC-safety leftovers (supervision gaps, `fsroot`, missing tests)
6. Backlog

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

The file is `blanket-toolchain.toml` at the project root, next to manifests and
outside ignored `.blanket/`; workspaces use the same nearest root as their
planner. TOML is reviewable with strict unknown-field/type errors, and the
writer emits canonical key/array order so equivalent locks have identical bytes.

The schema is versioned and intentionally boring:

- root keys are `schema_version`, `blanket_version`, and `toolchain`;
- each `toolchain.<ecosystem>` has `runtime`, a `release` key naming the catalog
  bundle the row was minted from — provenance and a uniqueness check, never a
  key blanket looks up to honor the lock —
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
  `.python-version` — would change nothing the lock knows about, and blanket
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
  `blanket add` that delegates a rewrite of `pyproject.toml`, `package.json`,
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
  evidence only; Blanket's own verified artifact digest is mandatory.

Both triples appear for every fetched component even when syncing on one host;
platform-neutral components repeat their digest. A lock records provider
builds, components, recipes, and per-platform bytes — never dependency entries,
credentials, store paths, object ids, or host facts. `blanket_version` is
provenance, not staleness: `schema_version`, recipe support, source inputs, and
artifact rows decide compatibility, and trust fixes never rewrite old locks.
Because recipe ids are append-only, "recipe support" can only fail forward — a
lock written by a newer blanket naming a recipe this one has never heard of —
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
the whole independently-fetched set. Its `.node-version` holds `24.20.0\n`,
whose sha256 is that input row's digest, and its `package.json` carries no
`engines.node`, which the second row records rather than omits:

```toml
schema_version = 1
blanket_version = "0.1.0"

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
or `blanket update --toolchain` selects a new bundle. Removing a release from
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
stale. The current GC implementation keeps these descriptor-relative
primitives in those modules; WP2 PR 3 may extract the shared pieces as
`src/fsroot.rs` and extend them for lock/input discovery. Keep the root
descriptor, walk components with `openat`/`O_NOFOLLOW`, create with `O_EXCL`,
and rename descriptor-relative. Path-based `fs::read`/`fs::write`/`fs::rename`
do not satisfy the refusal tests in this section.

The retained snapshot includes `blanket-toolchain.toml`: its held descriptor,
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
regardless of lock ownership, reopen `blanket-toolchain.toml` through the held
root descriptor with descriptor-relative `openat` and `O_NOFOLLOW` and compare
its bytes to the snapshot. A mismatch aborts with `blanket-toolchain.toml
changed during sync (update --toolchain race)`, leaving the old closure and
projection untouched.

The lock has exactly two writers — the first writable sync of a project with
no lock, and `blanket update --toolchain` — and both publish by ONE rule, with
no weaker path for the first write: create the temp file descriptor-relative
in the held project-root directory with `O_EXCL` and `O_NOFOLLOW`, write it,
`fsync` that file descriptor, rename it descriptor-relative and without
following symlinks over `blanket-toolchain.toml`, then `fsync` the held root
directory descriptor, mirroring closure publication. Both syncs carry weight
and neither is a nicety: the file `fsync` is what makes the rename publish
bytes instead of a filesystem-dependent window of zeros after a power loss,
and the directory `fsync` is what makes the rename itself durable. A `write`
that has only left the process is not on the disk.

The temp name is drawn from the operating system — 16 bytes read from
`/dev/urandom`, rendered hex, as `.blanket-toolchain.toml.<hex>.tmp`. That is
the randomness source already in the tree (`src/sbom.rs:36-41`, the CycloneDX
`urn:uuid` v4), factored into one helper rather than added a second time, and
it reads identically on Linux and macOS. Process identity is deliberately not
the source. Pid-plus-sequence — the shape download temps use
(`src/fetch.rs:360-366`) — separates concurrent writers inside one machine,
which is all `src/fetch.rs` needs, but it has fixed points: a sequence
restarts at 0 in every process, and a pid is reused after wrap and starts from
the same small numbers in every PID namespace. So
`.blanket-toolchain.toml.1.0.tmp` is the exact name the first write of a
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
what is in the way, because blanket cannot know that file is its own.

A leftover temp is inert — never read, never an input, never a lock, and never
consulted for staleness; it is garbage the user (or a `.gitignore` rule) may
delete at any time. Blanket unlinks its own temp on every exit path it
controls, success and error alike, and never scans for or deletes a temp it
did not create.

After dependency planning, on EVERY sync (including an existing-lock sync),
reopen the source inputs through the held root descriptor with `O_NOFOLLOW` and
recheck identity metadata and bytes before publishing the closure or
projection; a change aborts and leaves lock, closure, and projection untouched.

--frozen never modifies project inputs, blanket-toolchain.toml, or the catalog
cache; it may realize store objects and write the projection after validation
succeeds; validation failure exits before any write. That sentence is
byte-identical in exactly two places — here and in CLI.md's "Planned (WP2
design ...)" section. It appears in neither CLI.md's help screen nor its
command grammar, and neither gains a `(planned:)` marker, because the help
screen is the spec for the bytes `blanket --help` actually prints and the
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
planning at all: `blanket add` and `blanket update` run the store tool in the
project directory through `run_checked` (`src/ruby.rs:290-297`,
`src/elixir.rs:896-904`), and frozen invokes neither verb.

What frozen calls instead is named, owned, and tested like every other
guarantee in this design. `src/toolchain_input.rs`, owned by PR 3 below
exactly as `src/fsroot.rs` is, exposes one reader per ecosystem that returns
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

On the first writable `blanket sync` with no lock, selection runs against the
shipped catalog, stderr names the selected runtimes and the created
`blanket-toolchain.toml`, and the file is published by the shared publication
rule above — descriptor-relative `O_EXCL`/`O_NOFOLLOW` temp in the held project
root, flushed, then renamed without following symlinks; the committed file
remains for review.

The lock gate runs before dependency planning. Missing or stale under
`--frozen`, strict policy, or a read-only project is an error naming `blanket
update --toolchain [<ecosystem>]`, and ordinary sync also refuses stale locks.
Permissive mode cannot change a runtime silently: that is a correctness error,
not a hidden exception; other gaps still record one (`src/policy.rs:187-204`).

Writers take the per-project lock exclusively around read/compare/rename.
Byte-identical candidates keep the first file and let the second sync succeed
as a cache hit; different candidates leave the existing file, discard the
loser, and fail naming both selections, inputs, and `blanket update
--toolchain`. Ordinary sync creates a lock when there is none but never
rewrites one; only `blanket update --toolchain` replaces an existing lock.
That rule is per file, and the per-ecosystem case follows from it: a lock with
no section for an ecosystem newly present in the project — `[toolchain.python]`
committed, then a `package.json` appears — is stale, not absent, so ordinary
sync refuses and names `blanket update --toolchain`, which adds the section.

`blanket update --toolchain` updates every ecosystem present in the project —
present as source discovery finds it, not as the lock's existing sections list
it, which is how a newly added ecosystem gains one — or only the named one; it
is separate from dependency update and cannot take package names. It
re-reads sources, chooses the globally selected newest compatible stable/LTS
release described below, verifies every platform row, writes one lock
atomically, then runs ordinary sync; it never updates a dependency lock.
`--frozen` instead validates the committed lock with no catalog fallback and no
resolver-generated dependency-lock write, exiting before realization on a
missing, stale, or unresolvable input.

### Selection sources and precedence

Source discovery is explicit rather than an abstract "read the ecosystem" step.

It is also **anchored at the project root, not at the current directory.** The
root is the one blanket already resolves — the nearest manifest/workspace root
walking up from cwd — and it is where `blanket-toolchain.toml` sits once there
is one, so the anchor is defined identically before the first lock exists and
after, with no separate rule for the creating sync. The table below describes
where each ecosystem's own tools look, which is cwd-relative for most of them;
blanket's toolchain discovery starts at that root instead, so the consulted
path list is a property of the project and every developer, every CI job, and
every subdirectory produces the same list, the same lock, and the same
staleness verdict. A cwd-relative walk would make `blanket status` answer differently
depending on which directory the person was standing in, which is not a
property a committed lock can have. The cost is real and must be recorded in
`docs/human/LIMITATIONS.md` when the lock ships: a toolchain source file in a subdirectory — `web/.node-version`
under a root-level lock — is not a toolchain source for blanket, though uv or
`nvm` would honor it. One toolchain per lock root is the rule; per-subproject
toolchains would need per-subproject sections and are not in this design.


| ecosystem | native tools walk from | walk boundary | source precedence (blanket reads these from the lock root) | compatibility intersection and conflict |
|---|---|---|---|---|
| Python | cwd | parents through the uv project/workspace root; [uv documents this walk](https://docs.astral.sh/uv/reference/cli/) | `.python-version`, then a `requires-python` declared in `pyproject.toml`, including Poetry's `tool.poetry.dependencies.python`; `setup.py`-computed metadata is deliberately not a source, because reading it means running a build hook | use the supported request grammar below; intersect with metadata; current code parses at `src/pyselect.rs:309-362` but reads one supplied directory at `src/pyselect.rs:368-404` |
| Node | cwd | nearest package/workspace root | exact `.node-version`, then `engines.node` | intersect exact/range; empty intersection or conflicting same-level declarations is a hard error; current code only has platform rows (`src/npm.rs:114-146`) |
| Cargo | cwd | Cargo workspace root | nearest `rust-toolchain`, then `rust-toolchain.toml`, then shipped default | channel, targets, and supported components must intersect the catalog; an unsupported or conflicting request is a hard error; current nearest-file walk is `src/cargo.rs:246-264` |
| Go | module/project root | no workspace expansion; an ancestor `go.work` is refused | `go` is the minimum; non-`default` `toolchain goX.Y.Z` is exact; absent or `toolchain default` means newest compatible once | exact toolchain must be a catalog release and satisfy the minimum; otherwise fail closed; platform filtering is `go_pins` (`src/golang.rs:72-83`) and directive parsing is `src/golang.rs:243-269` |
| Ruby | cwd | parents through the project root | exact `.ruby-version`, then a Ruby entry in `.tool-versions`; the Gemfile's `ruby` directive is deliberately not a source, because reading it means evaluating a Ruby program | intersect exact declarations; disagreement is a hard error; current code has only platform rows (`src/ruby.rs:47-67`) |
| Elixir | cwd | parents through the Mix workspace root | exact `.tool-versions` OTP/Elixir; `mix.exs` compatibility is deliberately not a source, because reading it means evaluating an Elixir program | intersect OTP/Elixir requirements and OTP-qualified Hex/rebar rows; empty intersection is a hard error; current plan checks `mix.exs`/`mix.lock` at `src/elixir.rs:1075-1110` and pins OTP at `src/elixir.rs:26-31` |
| .NET | project directory | inspect ancestors only to reject inherited SDK inputs | exact project `global.json` with `rollForward = "disable"` | no roll-forward or second source; a mismatch is a hard error; current ancestor rejection and exact gate are `src/dotnet.rs:542-593` |

Python requests use a supported subset of uv's grammar: exact `X.Y.Z`, minor
`X.Y` (newest compatible catalog release once, then locked), or a PEP 440-style
specifier set restricted to `>=`, `<`, `==`, `~=`, and `!=`, comma-joined
(newest satisfying release once, then locked). An explicit CPython prefix is a
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
`blanket update --toolchain`.

The lock then supplies the exact artifact. A matching source request is stable;
a changed source stops sync with both values and `blanket update --toolchain`.
An exact request with no matching catalog row is a hard error in every
ecosystem, a range is selected once at lock creation or explicit update and
never reselected on sync, and dependency lockfiles stay delegated to native
tools. Every sentence in this section describes choosing a version, which
happens only at lock creation and `blanket update --toolchain`; a sync that
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
candidate, so recipe revisions of one upstream version coexist. The selector
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

`blanket run` resolves every runtime through that closure id using
`project::closure_object` (`src/project.rs:197-234`). Today Node calls the
global platform pin after sync (`src/main.rs:1404-1412`) while Cargo/Go use
closure ids (`src/main.rs:1416-1433`); later refreshes must not alter a run.

The cached `x` key becomes `x/3`: store root, ecosystem, package request,
platform, primary runtime version, selected `bundle_id`, and runtime object id.
The store root stays in the key exactly as `x/2` hashes it today
(`src/xrun.rs:326-334`), because every other input is store-independent —
`cpython_identity`/`node_identity` take no store root (`src/python.rs:131-152`,
`src/npm.rs:149-158`), unlike the env identities (`src/project.rs:279-282`,
`src/npm.rs:1241-1244`). Dropping it would make `BLANKET_STORE=/a blanket x
ruff` and `BLANKET_STORE=/b blanket x ruff` share one `~/.blanket/x/`
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
that re-parse `status` would exit 1 after every `blanket add` that rewrites a
multi-purpose manifest, breaking its documented CI gate; without re-deriving
the absent rows it would exit 0 while blanket and the rest of the repo
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
with `blanket update --toolchain`; it never guesses from the current default,
and a same-platform closure is not foreign-platform evidence. With an existing
lock, realize the current platform from its row.

If a recorded input now differs, the old closure is not a migration authority:
keep the old lock and closure, report both values, and require `blanket update
--toolchain` to snapshot the changed source and write a new lock. Legacy
closures with no snapshot for a consulted field take the same refusal. This
preserves rollback and stops changed source pairing with old dependencies.
Closure object refs keep toolchains alive through the existing root/GC walk;
the lock itself is not a GC root.

### Interaction with WP3

The lock needs provider build, component recipe, URL, and a verified,
algorithm-qualified digest for both triples. Sync downloads only the current
row and never rewrites the other.
Until WP3, the compiled rows in the ecosystem modules are the shipped catalog
(`src/python.rs:22-85`, `src/npm.rs:122-135`, `src/cargo.rs:25-68`,
`src/golang.rs:32-45`); `src/platform.rs:83-86` is only the supported-platform
enumeration, so locks are writable offline. WP3 must retain the rows existing
locks need, and an unrelated refresh cannot alter an Identity or a lock.

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
process; and the project-side `src/fsroot.rs` refusals all
fail closed — a symlinked `blanket-toolchain.toml`, a symlinked input file, a
symlinked ancestor directory of either, and an occupied temp name. ACTIVATION
stays dormant until selection sources and runtime propagation land: the feature
is off, and the lock is neither written nor required.

0. **Exact selection fixes (landed as two PRs)** — #21 `wp2/python-exact-selection` (`src/pyselect.rs`, `src/python.rs`) and #22 `wp2/go-selected-version` (`src/golang.rs`), each with its own unit tests: exact patches, duplicate rows, selected-Go realization, unchanged defaults, Darwin goldens.
1. **Shipped-table adapter and source selection (landed)** — pin modules, `src/platform.rs`, typed source-policy interface with configurable endpoint defaults, selector tests: complete bundles, matrix intersections, carrying the existing verified digests (including the sha512s .NET/Hex/rebar already use) into catalog rows, and legacy seeding (evidence-based success plus the refusal when evidence is missing). No lock-byte or replay tests before the format exists.
2. **Secure archive extractor (landed; follow-up before a second consumer)** — `src/archive.rs` and unit tests for absolute paths, `..`, hard links, special files, symlink escape, and an outside sentinel under GNU tar and (asymmetric until the Mac gate) bsdtar. Ordered follow-up **2b** replaces column-parsed tar listings with direct header validation before any second consumer adopts the module.
3. **Lock core, dormant** — parser/writer plus `src/cli.rs`, `src/main.rs`, and project input handling: canonical bytes as defined above, the consulted-path input list with its absent rows, and the concurrent writer/reader lock. This PR also owns `src/toolchain_input.rs`, the per-ecosystem declarative readers, with a unit test per ecosystem asserting the reader spawns no process. It extends the descriptor-relative primitives currently in `src/store.rs`/`src/project.rs` (which may be extracted as `src/fsroot.rs`) for lock/input-specific rules (`openat`/`O_NOFOLLOW` walk, `O_EXCL` create on an `/dev/urandom` name, file `fsync`, `renameat`, directory `fsync`), and moves `src/sbom.rs`'s `/dev/urandom` read into the shared helper it calls rather than adding a second randomness path. Unit tests refuse a symlinked `blanket-toolchain.toml`, a symlinked input file, a symlinked ancestor directory, and an occupied temp name; `fs::read`/`fs::write`/`fs::rename` do not pass them. Activation stays off; stale/frozen/replay/exit-status tests wait for it.
4. **Runtime propagation** — `src/main.rs`, `src/xrun.rs`, `src/inspect.rs`, `src/project.rs`, and closure writers: closure-selected runtimes, refresh isolation, old-`x/2` non-reuse; this permits activation.
5. **Activation and update** — `src/cli.rs`, `src/main.rs`, lock core, integration tests: update, two-store replay including the dropped-`release` upgrade replay, no-pin creation, stale/frozen refusal (with `frozen_validation_failure_precedes_all_writes` and the Gemfile-marker regression), added-higher-precedence-source staleness, unchanged dependency locks, foreign-platform refusal, exact statuses, Linux/Mac diff.


### Implementation status and remaining PRs

**Objective.** A committed toolchain lock outside the ignored `.blanket/`
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
  decides; a digest mismatch alone is never stale, so `blanket add` rewriting
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

**PR 2b — archive-header follow-up, before a second consumer.** Replace the
`tar -tv` column parser with direct tar-header validation, including supported
extended headers and all existing traversal/link/special-file refusals.
Preserve the existing Go consumer and outside-sentinel tests; verify GNU tar
and macOS extraction behavior. No other toolchain adopts the extractor until
this PR passes review. It is a scheduled prerequisite, not an unranked nit.

**PR 3 — lock core, dormant.**
- *Files:* new `src/toolchain_input.rs` (per-ecosystem declarative readers),
  extend the descriptor-relative helper extracted by GC C as `src/fsroot.rs` (root helper: `openat`/`O_NOFOLLOW`
  walk, `O_EXCL` create on a `/dev/urandom` name, file `fsync`, `renameat`,
  directory `fsync`), plus `src/cli.rs`, `src/main.rs`, project input
  handling; move `src/sbom.rs`'s `/dev/urandom` read into the shared helper
  rather than adding a second randomness path.
- *Tests:* one per ecosystem asserting the reader spawns no process; `fsroot`
  refusals for a symlinked `blanket-toolchain.toml`, a symlinked input file, a
  symlinked ancestor directory, and an occupied temp name — and a test that
  `fs::read`/`fs::write`/`fs::rename` do **not** pass those refusals.
- *Concurrency integration:* the toolchain-input lock is distinct from C's
  project transaction lock. Acquire activity → x-root (if any) → toolchain
  input lock → project transaction → cache → publication. Do not repurpose a
  shared input lock as an exclusive publication lock. Pure frozen input
  validation must complete before any store bootstrap or automatic metadata
  maintenance writes; preserve the frozen no-writes regression.
- *Activation stays off:* the lock is neither written nor required.

**PR 4 — runtime propagation.**
- *Files:* `src/main.rs:1598` (Node `run` takes the global pin via
  `npm::ensure_node_for`; likewise `src/main.rs:1008` and `src/xrun.rs:1546`,
  `src/xrun.rs:1827`), `src/xrun.rs:98` and `src/xrun.rs:1582` (the `x/2`
  cache keys omit runtime identity — the design's `x/3` key is
  store-root-scoped and bundle-complete), `src/inspect.rs` (`status` must compare toolchain inputs),
  `src/project.rs` and every closure writer (closure-selected runtimes,
  refresh isolation, old-`x/2` non-reuse).
- *Security requirement:* a catalog refresh must never pair old dependencies
  with a new runtime silently.

**PR 5 — activation and `update --toolchain`.**
- *Files:* `src/cli.rs`, `src/main.rs`, the lock core, integration tests.
- *Behaviour:* first writable sync of a project with no pin creates the lock
  visibly and atomically; `--frozen` or strict policy refuses a missing or
  stale lock; concurrent writers must agree; upgrades are only
  `blanket update --toolchain`, never a side effect.
- *Named tests from the design:* two-store replay including the dropped-
  `release` upgrade replay; no-pin creation; stale/frozen refusal with
  `frozen_validation_failure_precedes_all_writes` and the Gemfile-marker
  regression; added-higher-precedence-source staleness; unchanged dependency
  locks; foreign-platform refusal; exact statuses; the Linux/Mac lock diff.

**Migration and compatibility.** Legacy closures seed a lock only from proved
evidence; an unrecoverable mapping refuses with `blanket update --toolchain`
and never guesses from the current default. A same-platform closure is not
foreign-platform evidence. Writing a lock does not write or mutate a store
object; darwin goldens stay byte-identical.

**Linux verification.** `cargo fmt --check`, `cargo test`, and the selection
`--ignored` tests (`tests/python_select.rs`, `tests/go_e2e.rs`) with a
disposable store and `BLANKET_SANDBOX_TESTS=required`.

**Mac before merge.** The lock carries a hash per platform, so a lock written
on Linux must sync on the Mac without rewriting itself, and vice versa. Sync
the same project on both machines and diff the lock file (must be byte
identical) and `blanket status` (both "synced"). Run `cargo test` and the
selection `--ignored` tests on the Mac.

**Independent review.** The design has had 10 rounds; round 10's fixes are
unreviewed. Every implementation PR needs its own round.

**Completion criteria.** Ordered items 0–5 and the extractor follow-up below merged; the acceptance list at
the acceptance paragraph at the end of the contract passes on Linux; the two-machine lock diff is
recorded; `LIMITATIONS.md` loses the "Node/Ruby/Elixir select nothing" and
"one fixed .NET SDK" rows.

#### Recommended decision

Take **PR 1 next** (after GC safety), not PR 3. It establishes tested selection independently of lock parsing.
It does not close user-visible runtime-selection limitations until runtime
propagation and activation also land; update those rows only when behavior
actually changes. PR 3's `write_closure` neighbourhood is exactly what GC Package C
rewrites; sequencing PR 1 first keeps the two apart.


---

## 2. Release catalog and publisher trust (WP3)

Needs WP2.

**Objective.** One binary discovers a newly published upstream release without
a code change.

**Prerequisites.** WP2 PRs 1, 2b, 3, 4, 5. Default versions do not move until WP2
has merged.

**Scope.**
- **Catalog, not just a release list.** Per ecosystem: usable distributions
  (python-build-standalone builds, nodejs.org, static.rust-lang, go.dev,
  portable-ruby, erlef otp_builds plus blanket-toolchains for Linux OTP,
  Microsoft release metadata), provider build revisions, platform requirements
  (glibc floor), extraction recipes, and companion tools that must move
  together: uv, bundled npm, Bundler, OTP-qualified Hex and rebar3,
  Elixir-per-OTP compatibility.
- **Trust is a configured list, not a compiled-in constant** (owner direction,
  2026-09-09). "Which publishers count as real" must be data the user or the
  company sets, because an enterprise mirrors its toolchains internally and
  will want blanket pulling from its own repository, signed by its own key.
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
the catalog entry and in `LIMITATIONS.md` (blanket is TOFU today for
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
  `blanket ls`, `blanket sbom`, and an audit can answer "where did this
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
whether it covers the artifact blanket actually downloads. Commit the captured
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
  verifiable signing material covering the exact artifact blanket downloads.
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

Shipped from this package: the `x` lifecycle (`blanket x --clean`, per-root
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
`.blanket/policy.toml` and the machine-wide policy. Permissive stays the
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
  The current `BLANKET_POLICY` override can replace home-policy selection
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

### Supervision gaps (token threading)

Shipped: `src/kernel/supervise.rs` supervises awaited store-consuming
children while the caller's activity lease is held. Not finished: about 25
`status_owned`/`output_owned` sites mint a fresh lease per child instead of
borrowing the caller's token, and the helpers below take no token at all, so
protection cannot be proved at the call site. Threading a token through them
is a signature change. `Store::has` taking the activity lock underneath the
x-root lock (a lock-order inversion, not reachable as a deadlock today) goes
away with the same threading.

**Exclusion list, filled 2026-09-09.** Every production `.status()`,
`.output()` or `.spawn()` in `src/` that does **not** go through
`src/supervise.rs`, and why it is out. Test-module and test-helper sites are
excluded from this list by construction and are not repeated here
(`extract_ruby_bottle_for_test`, `project.rs::local_sdist`,
`project.rs::local_native_sdist`, and the `#[cfg(test)]` blocks in
`golang.rs`, `build_requires.rs`, `sandbox.rs`, `elixir.rs`, `build.rs`,
`cargo.rs`, `dotnet.rs`, `gitsrc.rs`, `store.rs`, `archive.rs`).

| Site | What it runs | Disposition |
|---|---|---|
| `pypi.rs:62` | `/usr/bin/getconf GNU_LIBC_VERSION` | **Legitimate.** Pure host probe; touches no store path and cannot outlive store protection. |
| `dotnet.rs:1080` | `/usr/bin/id -u` | **Legitimate.** Pure host probe. |
| `sandbox.rs:353`, `sandbox.rs:501` | unmanaged sandbox entry point | **Legitimate by construction.** Documented in-code as the path for "callers that do not consume a store"; store callers use the activity-aware sibling. |
| `sandbox.rs:895`, `sandbox.rs:941` | `--version` and classification probes | **Legitimate by construction.** These are the `None` arm of an `Option<&StoreActivity>`; the `Some` arm already routes through `supervise::output`. |
| `build_requires.rs:112,119`; `archive.rs:537,547` | delegated build/extract | **Legitimate by construction.** `None` arm of `Option<&Store>`; the `Some` arm calls `status_owned`/`output_owned`. |
| `cargo.rs:246` `extract_rust_components` | `/usr/bin/tar -xJf … -C <staged>` | **Gap.** Extracts into a **store staging directory**, which GC sweeps. No token is threaded in, so protection cannot be proved at the call site; it depends on an unverified outer lease (`cargo.rs:155`). |
| `elixir.rs:796` `extract_otp_archive` | `/usr/bin/tar -xzf … -C <destination>` | **Gap.** Same shape; no token parameter. |
| `dotnet.rs:115` `extract_sdk_archive` | `/usr/bin/tar -xzf … -C <staged>` | **Gap.** Same shape; no token parameter. |
| `elixir.rs:494` `run_installer_spec` | ecosystem installer | **Gap.** Runs a store-provisioning installer with no token. |
| `project.rs:751,757,767` `clone_tree` | tree copy for projection | **Gap.** Writes projection content with no token parameter. |
| `gitsrc.rs:172` `run_git` | `git` against a fetched tree | **Unproven.** `gitsrc.rs:493,1003` take a lease, but `run_git` receives no token, so no call site proves it. |

The six **Gap**/**Unproven** rows are not signal-safety defects — they are
the same "cannot be proved at the call site" shape as B.5's `*_owned`
problem, one level lower: these helpers take a `&Path` and no token at all,
so threading a token through them is a signature change, not a call change.
They are the reason B.5's completion criteria are not cleared.

### Store ownership checks and `src/fsroot.rs`

Never started. The rules the helper must enforce:

Enforced at the `ClosureRefs` API boundary, before anything is written:
- every object id validates as above;
- every projection ref rejects absolute paths, `..`, empty components, and
  NUL;
- **store ownership:** an object path supplied by a caller must have
  `path.parent().parent() == store.root` after canonicalization; a projection
  must resolve under `store.root/{forests,backups}` through no-follow anchored
  directories. Cross-store references are rejected with the offending path
  in the message. Only the legacy importer may construct retention-only
  sibling references; those must never become deletion authority.
- the `Store` is **passed explicitly**. Delete
  `project::store_from_closure_body` and its fallback to `Store::open()` from
  normal publication. Update `xrun::originating_store`, which currently calls
  this helper, in the same PR: new x markers carry explicit canonical store
  provenance; existing markers/closures use a narrow declarative, validated
  legacy-origin reader. An ambiguous origin skips cleanup. Do not retain a
  generic recursive JSON path guess under a different name.


### Missing named tests

The GC design named 26 tests for durable project records. On 2026-09-16 no
test function with these names exists in `src/` or `tests/`; some behaviors
may be covered under other names, so check before writing a duplicate:

- `root2_rejects_absolute_projection`
- `root2_rejects_cross_store_object`
- `root2_merge_is_a_union_never_a_replace`
- `symlinked_registry_entry_is_a_malformed_record`
- `closure_refs_reject_a_bare_path_that_merely_contains_an_id`
- `publication_persists_the_record_before_the_closure`
- `closure_refs_name_every_object_this_producer_created`
- `moved_project_keeps_its_tools_and_forests`
- `two_ecosystems_and_two_environments_all_stay_protected`
- `register_imports_every_shipped_closure_schema`
- `register_refuses_an_unknown_closure_and_keeps_the_old_record`
- `register_runs_no_project_code`
- `sibling_stores_have_disjoint_new_projection_namespaces`
- `sync_imports_all_legacy_ecosystems_before_switching_one`
- `forget_corrupt_record_works_with_an_unrelated_corrupt_record`
- `forget_registry_symlink_never_touches_its_target`
- `utf8_keys_unchanged_and_non_utf8_keys_distinct`
- `legacy_lossy_key_is_not_silently_reassigned`

---

## 6. Backlog

Unranked. "GC Package B/C/D" means the shipped GC-safety work.

Reviewed 2026-09-09. Items that the GC track or WP2 now subsume are marked;
the rest stand.

| Item | Status after this review |
|---|---|
| M5 hardening: RECORD verification and rewrite, Mach-service allowlist, deployment-target tags, streaming extractors | stands. Streaming extractors connect to the WP2 extractor's architectural finding (read tar headers directly instead of parsing `tar -tv`); do them together |
| Sol review 3 leftovers: dependency-order lifecycle execution and ancestor `.bin` paths; true npm optional-failure parity; planner subprocess sandboxing; process-tree quiescence after install scripts; Xcode/SDK fingerprint in build identity | stands. **Process-tree quiescence overlaps GC Package B**: B's supervisor bounds the awaited direct child; descendants surviving its exit remain outside the guarantee. Do not claim B closes this |
| Store-object content verification on use (same-user replacement is undetected), or an explicitly narrower documented trust boundary | stands, and GC Package D's replacement recheck is *not* this — D checks the deletion candidate, not the object a job is about to use |
| Contained atomic writes for the remaining project-side plan caches | stands; `src/fsroot.rs` (never extracted, see §5; WP2 PR 3 extends it) is the helper they should use |
| Per-package store objects with copy-on-write assembly | stands; deferred by the "env-level granularity" MVP decision |
| Reproducibility spot-checks (rebuild twice, compare, quarantine mismatches) | stands |
| Bytecode precompilation at realize time | stands |
| Pinned C toolchain as a store object (closes the unpinned host gcc/glibc and Xcode inputs on both platforms) | stands. Recording the current host Xcode/SDK fingerprint can land earlier; a managed C toolchain is the stronger reproducibility follow-up, not a prerequisite to honest fingerprinting |
| Breadth: system packages (CLI tools and libraries first; GUI apps and services are a different product) | stands |
| JVM | deliberately deprioritized |
| Health metric: lines of code per tailor must keep falling, or stop and fix the kernel | stands; measure it again after GC Package C, which adds per-producer code |

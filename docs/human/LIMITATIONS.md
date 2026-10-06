# Tog limitations ledger

A standing, honest record of what tog fails to address or does not get
right. Items leave this list only when fixed and regression-tested. Each
entry says what breaks, for whom, and whether it fails loud or silent.

Platforms: macOS arm64 and Linux x86_64 (glibc). All GC-safety work
(Packages A–D, merged 2026-09-10) was validated on Linux only — **no macOS
validation since**. Linux claims are verified on Fedora 44; other glibc
distros are untested. Intel macOS, aarch64 Linux, and musl/Alpine are
unported (a pin-table row plus a wheel-tag band each, not a port).

## Kernel-wide

- **`tog fmt` is Rust-only**; other ecosystems fail clearly (the locked Rust release's
  rustfmt, or a local toolchain's own, no `Cargo.lock`). It writes no closure, so nothing
  roots the rustfmt object: `tog gc` between two runs can reclaim it, and the next
  `tog fmt` realizes it again (a download when gc also cleared the archive cache).
- **`tog audit` vouches for who wrote a record only under a `[signing]` policy.** Without
  a `[signing]` table in the machine policy it judges records on their contents, says that
  signatures were not checked, and `--signed` refuses to run. Under CI (`CI` set, not
  `false` or `0`) a plain audit refuses too, unless `--allow-unsigned` is passed. With
  one, a pass proves that
  every closure file in
  the working tree carries a valid signature from a key the machine policy trusts, that
  every detected ecosystem has its primary closure, that each record is current for the
  inputs on disk, and that no recorded exception is denied or unknown. It reads `tog-toolchain.toml` the way
  `status` does: a missing lock, a missing section, a stale lock row, or a record built from
  another bundle than the lock names is `stale`. It does not prove the signer's sync was
  honest or safe to run: it does not cover the doors that run unsandboxed with network
  (`add`/`remove`/`update`, where the ecosystem's own tool edits the manifest and lock, and
  missing-lock generation during `sync`/`plan`, where uv, bundler, mix resolve
  with network; Go, Cargo, and Node (npm, pnpm) resolve confined through tog's proxy
  instead, and `attest` re-checks their locks), nor does it re-verify store bytes, re-check
  object metadata, or judge what
  `tog run`/`x` executed. A job that runs untrusted project code must not hold a signing
  key. The machine policy is whatever `TOG_POLICY` or `$HOME` selects: the gate's
  workflow, environment, binary, and machine policy must be controlled outside the
  untrusted checkout, and pointing `TOG_POLICY` at a checkout-controlled file gives that
  file machine authority. `projected_at` is authenticated metadata, not an expiry: a genuine
  old record whose recorded inputs still match passes. Any record the gate cannot believe or
  compare (no signature, no recorded inputs, no recorded platform, no exception record)
  fails as `outdated` rather than passing, so pre-signing projects need one `tog`
  under a trusted key before the gate is
  useful. An exception kind this binary does not know (a record written by a newer tog)
  fails as `unknown` rather than being permitted. Loud.
- **GC is conservative around what it cannot read.** Store jobs hold a shared activity
  lease; GC skips while work is active (older binaries do not know the protocol). `root/2`
  records survive moves, but a pathname-only root (the form before them) and an unreadable
  object record block the sweep — an unreadable registry record blocks it too. `tog gc
  --forget <key>` and `tog gc --drop-object <id>` are the give-up valves.
- **The GC safety guarantee has a stated boundary.** It covers cooperating tog processes
  on a local filesystem with working locks and atomic rename. Not covered: older binaries;
  programs run directly from store paths; malicious same-user modification; descendants
  outliving the awaited child; orphans after SIGKILL of the supervising tog; network
  filesystems, where `flock` is advisory in name only.
- **Signal delivery has three edges.** Parent-directed TERM is forwarded to the direct child;
  a group-directed TERM reaches parent and child independently and is forwarded too
  (at-least-once). Parent-only INT/QUIT/HUP are caught and waited on after startup, not
  forwarded — terminal process-group delivery (`^C`) is the supported path. A cancellation
  across the spawn boundary is never dropped. `128 + signal` is a shell-visible exit code, not
  a wait status. An inherited ignored SIGCHLD (`SIG_IGN` or `SA_NOCLDWAIT`) is overridden from
  tog's first supervised child on, for the life of the process, so no exit status is
  auto-reaped away; the child still execs with the inherited `SIG_IGN`. A TERM that reaches no
  child (it arrives after the child was reaped, while its output still drains) is re-raised
  when the last supervision ends, so tog stops as the inherited disposition says. Code that
  installs its own TERM/INT/HUP/QUIT handler after tog's first supervised child replaces tog's
  for good, and supervision stops forwarding that signal (debug builds assert against it).
- **The tools a sync runs find the project by pathname.** A sync holds the project
  directory open from its first read to its last write: detection, the project's own
  `.tog/policy.toml`, manifests, locks, closures (including the ones root registration
  imports), `.venv`/`node_modules` links and `.tog` all go through that one descriptor. The GC
  root and the per-project lock are keyed on the canonical path the project was opened at,
  never resolved again, and the sync refuses once that path stops naming the held directory
  (after the store wait, before each ecosystem, before a root is registered, and after the
  closure is renamed into place). The ecosystem tools a sync starts unsandboxed (uv, npm,
  cargo, go, mix, bundle, dotnet, git) start in the held directory: the child enters it
  through the descriptor (`fchdir`), not the path. A sandboxed child (the `setup.py` probe,
  a sandboxed build in the project) has the held directory bound in through its descriptor
  and starts there, and a confined resolution snapshots the held directory. A path handed
  to a tool as an argument (`--manifest-path`, `-r <requirements>`) or an environment
  variable (`BUNDLE_GEMFILE`) is still one the tool opens itself. So a same-user process
  that renames the directory away, puts another project at its path, and puts the original
  back while such a tool runs can make it read or write the replacement.
  Loud when the tool's output is read back (a lock it wrote is missing from the held
  directory); silent otherwise. Files above the project (a Cargo workspace root, a parent
  `go.work`, .NET `Directory.*` files, a parent `.tog/policy.toml`) are read from the
  directories that contain the held one (`..` from its descriptor), not from the path's
  parents. Policy loading verifies each held ancestor still has its original name and
  refuses a changed chain, so a temporary move cannot lift a parent policy.
  The machine policy is read by path. `status`, `doctor` and the environment `run`
  and `env` build open the project once and read it through that descriptor. `audit` uses the same held project for policy, closures,
  detection, freshness, and resolution evidence. `gc --register` still opens it by path.
- **CLI exit status is 0 / 1 / 2** (success / command failed / usage error); `run`, `x` and
  `fmt` pass the program's status through. A tool argument that is spelled like one of tog's
  own options needs `--` first: `-h`/`--help` for all four, and for `fmt` and `x` also the
  global options (`-C`, `-q`, `-v`, `--no-color`) while they precede the tool's first
  non-option word. `run` and `build` never take one, so they need no `--` for those.
- **`tog status` compares recorded inputs only.** `-r` includes, `requirements/` members,
  and workspace-member package.json are not recorded. Cargo/Ruby/Elixir/.NET compare the lock
  hash only; Go catches `require`/`replace` only via `go.sum`; a closure written before those
  fields were recorded is reported `unchecked` and fails the command, since nothing about it
  can be compared.
- **One toolchain per lock root.** Toolchain discovery is anchored at the project root
  where `tog-toolchain.toml` sits, not at the current directory, so every developer, CI
  job and subdirectory produces the same consulted-path list and the same staleness
  verdict. The cost is that a toolchain source in a subdirectory — `web/.node-version`
  under a root-level lock — is not a toolchain source for tog, though uv or `nvm` would
  honor it. Per-subproject toolchains would need per-subproject sections and are not
  designed.
- **The two-machine lock diff has been run once, by hand.** A lock carries a row per
  platform and is written from the intersection of releases complete on both. On
  2026-09-25 a seven-ecosystem lock written on Linux synced unchanged on an arm64 Mac, the
  Mac wrote the same bytes from scratch, and `tog status` matched. No CI job repeats it, so
  a change after that date is proven by test, not by two machines.
- **A committed lock is a set of URLs to review.** A lock row's URL must sit under an
  endpoint the source policy admits for the row's own `provider`, and so must every
  redirect, but a hostile lock can still name another file under that publisher's
  endpoints, or name a different shipped publisher as its provider. Reviewing a lock
  diff is reviewing its URLs and providers. A downloaded toolchain row can no longer
  name `file://` (a Rust `source = "path"` row names a local tree and downloads
  nothing); the generic fetch helper that package-registry downloads use still
  accepts it.
- **Frozen validation reads declarative files only.** A project whose only statement of
  its runtime version is computed — `setup.py` metadata, `mix.exs` compatibility, a
  Gemfile `ruby` directive — cannot be validated under `--frozen` and is refused with the
  declarative file to add. Reading those sources means running project code, which is
  exactly what frozen promises not to do.
- **`add` / `remove` / `update` delegate to store tools with network, unsandboxed** (uv,
  bundler, mix) — the same trust boundary as missing-lockfile generation. Go, Cargo, and
  Node (npm and the pinned pnpm) run theirs in the sandbox with no network of their own,
  through tog's resolution proxy.
  Refusal rows: Poetry/PDM, setup.py, `requirements/` dirs, Elixir add/remove, Yarn, .NET.
- **A Node `file:` or `link:` dependency outside the project is refused** by every door
  (edits, a missing lock, `attest`), naming the manifest and the path: the confined npm or
  pnpm reads the project alone, and a resolution record names files inside the project only.
  Move it inside the project, or depend on it from a registry. A scoped registry in `.npmrc`
  and a direct-URL tarball are fetched through interception and recorded as
  `unattested-index`, which the company policy denies.
- **pnpm edits require a root `packageManager` field** with an exact pinned version.
  Membership is the `pnpm-lock.yaml` `importers` list and nothing else. **A member added since
  the last `pnpm install` is not in the lock and cannot be distinguished from a deliberate
  exclusion**, so edits refuse loudly with two remedies: `pnpm install` at the root, or a
  `.tog` directory in it.
- **pnpm patches are resolution inputs only when `package.json` names them.** The patch
  files `pnpm.patchedDependencies` lists are in the resolution basis and the record, so a
  patch edited after signing reads as a change. The same setting in `pnpm-workspace.yaml`
  (pnpm 10) is not read: tog reads that file's `packages` alone.
- **An npm workspace member is edited at the root.** `tog add` in a member whose root
  `package.json` names it in `workspaces` runs npm in the member with the root as the lock
  root, so the root's `package-lock.json` (created there if it has none) and resolution record
  are what change. A pnpm member whose root has `pnpm-workspace.yaml` naming it but no
  `pnpm-lock.yaml` yet is placed at the root the same way. A member with a lock or a `.tog`
  directory of its own is its own root. A sync run in a member (npm or pnpm) that has no lock
  of its own refuses, naming the root: run `tog` there.
- **Yarn classic edits remain a refusal** (no lockfile-only edit mode); run the Yarn command
  tog names. Yarn Berry is not imported (cache-zip checksums are not tarball integrity
  values).
- **`tog x` covers PyPI and npm**. A removed *node* environment orphans its node_modules
  forest under `<store>/forests/`, which plain `tog gc` never visits: only `tog gc
  --project` reclaims it. Cleanup stops with an error when a root's recorded originating
  store is unavailable, and skips a root with no request record whose owning store its
  closure does not name.
- **A store is never migrated.** The store carries a format marker (`<store>/format`), and
  this tog reads exactly one format. A store written before the marker existed, or by a
  newer tog, or whose marker is damaged or unreadable, is refused by every command that
  reads or writes the store. `tog store path` and `tog doctor` still report on it, and
  `tog gc --reset` empties it (the download cache is kept), after which every project
  syncs again. Nothing carries old objects across a format change.
- **`cargo test -- --ignored` still runs single-threaded** (`--test-threads=1` in README.md
  and heavy.yml). The supervisor no longer needs it: any number of children can be supervised
  at once in one process (#57). No parallel run of the end-to-end suites has yet checked
  whether they share other state (`$HOME`, registries, scratch stores), so the flag stays
  until one has.
- **Unpinned host build inputs.** The Linux host C toolchain (gcc, binutils, glibc headers)
  and the macOS Xcode/clang/SDK are not in build identity — two hosts can produce different
  "identical" objects. The Linux OTP artifact needs glibc 2.43 and host `libcrypto.so.3`.
  Linux gem native extensions build against the host C runtime alone (glibc, kernel headers,
  libxcrypt, the compiler's own files): every other host header, `-l` library, static
  archive and pkg-config file is absent from the compiler's and linker's default search
  paths and from pkg-config in that sandbox. Other host shared libraries stay loadable so
  the compiler and linker themselves run: they are moved into a `.tog-host-runtime`
  subdirectory of their library directory, which `ld` does not search, and reached through
  the sandbox's own copy of the loader cache (`/etc/ld.so.cache`), which names them there.
  The loader searches that cache after a program's own `DT_RUNPATH`, so a program a gem
  bundles and runs during its build loads its own copy of a library before the host's
  (#332). A library subdirectory
  with headers, static or libtool archives, `pkgconfig` or `cmake` under it
  (`/usr/lib64/perl5/CORE`, a Python package's CFFI headers, `/usr/lib64/libnl`), or that
  tog cannot list, is curated the same way, so an explicit `-I` or `-L` into it finds no
  header, archive, object, `lib*.so` symlink or linker script (#331); the compiler's own
  `gcc` and `clang` directories, and a versioned LLVM tree (`llvm-<N>`, where Ubuntu
  keeps clang's own headers), are kept whole. Two gaps: a regular ELF `lib*.so` in a
  curated subdirectory stays where it is (plugins and extension modules there are loaded by
  that path), so `-L` into it can link it; and a subdirectory whose only development file
  is a `lib*.so` symlink or linker script is bound whole, as plugin directories such as
  `bfd-plugins`, `sasl2` and `xtables` are full of `lib*.so` symlinks programs load. Kept files are symlinks into
  one read-only bind of each whole curated host directory under `/.tog-host-files` (#334),
  so every file the view hides is still readable there by that path: no default search
  path, pkg-config directory or symlink in the view names it, but a build that names
  `/.tog-host-files` on purpose reads the host's development files. A build that
  resolves a kept file's real path reaches that copy too: `readlink -f
  /usr/lib64/libssl.so.3` names it under `/.tog-host-files`, and a `-L` into that
  directory finds `libssl.so`. For the same reason `find -type f` in a curated directory
  does not list the libraries it kept, which are symlinks there (#559). Native
  gems also build with tog's pinned native library set mounted (zlib, openssl, libffi,
  libxml2, sqlite, ncurses and the rest of `nativelibs.rs`), and load it at run time through
  their rpath (#329); every Linux gems object with a native gem names that set, so those
  objects rebuild once after the change. An extconf that ignores pkg-config, `CPATH`,
  `LIBRARY_PATH` and mkmf's flags does not see the set. A gem
  that needs another host library fails that build, is rebuilt against the whole host, and
  records `host-build-inputs`, which a policy can deny. The build that failed may only have
  left its own gem and extension directories behind; anything else it changed in the gem
  home refuses the retry, and its HOME and TMPDIR are deleted before the retry starts. The
  object is then committed under its own `build_view = "host-fallback/1"` identity, keyed by
  which gems fell back and by a fingerprint of the host build inputs (`host_inputs`): every
  header, library, `pkgconfig` or `cmake` entry the C-runtime-only view hides or relocates,
  for each such symlink the file its chain finally resolves to (so a dropped `liblzma.so`
  covers the kept `liblzma.so.5.8.1` behind it), where `/usr/bin/cc` and `/usr/bin/c++`
  resolve, and every file under `/usr/lib/gcc` and `/usr/libexec/gcc`. The fingerprint is
  stat-based, never a hash of file contents: each entry counts by path, type, size,
  modification time and symlink target, and a resolved target by its inode and device too.
  A development package installed, removed or upgraded is detected through those file
  details; a file rewritten with bytes of the same size and its modification time put back
  is not. A directory it cannot read fails the sync rather than counting as empty. It is
  taken right before and right after each build against the whole host (about 12 ms on a
  Fedora 44 workstation); if the two differ, or two gems of one object fell back against
  different host states, the sync fails ("host development files changed during the build
  of <gem>; re-run tog"). A store record keyed by the runtime-only id and that build-time
  fingerprint lets a later sync over the same store, on any host whose build inputs
  fingerprint the same, reuse the object instead of rebuilding; the lookup fingerprints the
  host again, only when the runtime-only object is missing, and a host in another state
  misses the record and builds. What the fingerprint cannot see (file contents, anything
  outside the curated directories and the compiler) can still make two hosts with the same
  fingerprint build different bytes.
  Pure-Ruby gems compile nothing and install against the whole host. Setting the view up
  costs about a quarter of a second per native gem on a Fedora 44 workstation (about 300
  mounts), against about ten milliseconds for the whole host.
  Python sdist builds that compile Rust or mount the native-library set, and npm install
  scripts, follow the same rule (#328): they run against the C runtime alone first and fall
  back to the whole host with a `host-build-inputs` exception. A failed sdist attempt's
  output, log and (for Rust) unpacked source are reset before the retry; a failed npm
  attempt's package tree and scratch HOME go back to their snapshots. The wheel, and the
  Python or Node environment holding it, are committed under `host-fallback/1` identities
  that name what fell back (the sdist; `pkg:` entries for the environment). Every Linux
  Python environment with such an sdist and every Linux Node environment carries
  `build_view = "runtime-only/2"`, as does every Linux gems object (`/2` since the view
  curated library subdirectories, #331), so each rebuilds once after either change.
  One gap: when a build-requirement sdist falls back, its build environment is committed
  under a host-fallback id, and the wheel built in that environment names that realized id
  in its own `build_env` input. The parent environment is planned before any build runs, so
  its `pkg:` entry for the wheel names the planned sdist id, whose `build_env` is the build
  environment's runtime-only id: no committed wheel has that id. Unless the wheel's own
  build also fell back, the parent is committed under its runtime-only id, which does not
  change with the host state the build environment fell back against. Python
  sdists with no native or Rust input, and macOS builds, still see the whole host.
- **Pinned native-library objects are store-root-specific**: `native-libs/libset/3` includes
  the canonical `TOG_STORE` root in its identity; moving a store requires re-realizing the
  libset. **Linux sandbox roots are canonical paths** (a symlink alias root is invisible).
  Both matter only to new callers.
- **Tog's security claim is provenance, not runtime containment.** Acquisition and build
  happen behind one door, builds cannot reach the network, and every closure lists what went
  in and every exception waved through. A hostile package can still put its payload in its
  build output and run it at `tog run` time with full network. Do not describe tog
  as stopping malicious code from running.
- **Sandboxes are cooperative hermeticity, not hostile-code containment.** On Linux, tog scans
  every declared root, the cwd, the scratch and the fixed `/etc` entries it binds for Unix
  sockets before invoking bubblewrap, but not `/usr`, which is trusted, and a socket created
  after the scan is not caught (the fmt host-socket scan is Linux-only too); build daemons can
  outlive a run. **Store objects are trusted from permissions + metadata, and all
  toolchain pins are TOFU** (pin-time hashes, not signed manifests): same-user content
  replacement after commit is undetected.
- **Delegated planning runs unsandboxed with user privileges** (uv, bundler):
  a hostile manifest executes code at PLAN time. Go's, Cargo's, and Node's run in the
  sandbox.
- **Every tar archive is unpacked through the pre-materialization extractor**
  (`src/kernel/archive.rs`, #236). It reads every entry from the
  archive's own headers (ustar names and the POSIX prefix field, PAX `path`/`linkpath`/`size`,
  GNU long names), cross-checks that listing against `tar -t`, refuses the whole archive on an
  absolute name, `..`, a special file, an escaping symlink, a hard link to anything but an
  earlier regular file that survives `--strip-components` (#317), a hard link to itself, a hard
  link or link target whose name is written twice (#542), a name that is not
  UTF-8 or carries a control, bidirectional-override or zero-width character, two names that
  APFS would fold into one (by case or by Unicode normalization; for a per-platform build such
  as a toolchain or conda package, only on macOS, since Linux CPython and ncurses ship
  terminfo names like `2621A` beside `2621a`), or a layout it cannot model
  (sparse members, a global header that renames, a PAX key it does not know, unknown type
  letters, bad checksums), refuses past a 1 GiB running member-data budget before anything
  is written, and extracts with `TAR_OPTIONS` unset and tar told to restore no
  extended attributes, ACLs, file flags or AppleDouble metadata: an object holds names, bytes
  and the executable bit, nothing else. The one `tar -c` in the tree (git-source packing)
  lives there too, so no other production code names `/usr/bin/tar` at all — an
  architecture test fails the build if it does. PAX values other than `path`, `linkpath` and `size`
  may be any bytes and are never read. The `tar -t` listing carries only `--numeric-owner`:
  it writes nothing, and bsdtar documents the restore flags for other modes, so on `-t`
  they could only fail. That leaves a Mac-packed tarball's `._name` companions refused on
  macOS by the cross-check, as before, rather than extracted as the wrong tree (#307 stays
  open until a macOS run shows whether `--no-mac-metadata` on `-t` lifts it). Single
  manifests read out of an sdist come from the same validated in-process stream, never a
  second tar child. The Elixir release zip and Hex's own `.ez` archive are
  unpacked by `/usr/bin/unzip`, inheriting the user's `UNZIP`/`UNZIPOPT`. Wheels, zip sdists
  and the outer zip of a `.conda` package are read in process with the `zip` crate.

## Python

Selection covers every patch of each maintained CPython minor that python-build-standalone
  published a checksummed build of for both platforms. A few patches never got one (3.10.0,
  3.10.1, 3.10.10, 3.11.0, 3.11.2; `tools/catalog.py python` reports them) and are refused. A
  two-part `.python-version` picks the default (3.12.14) on its minor, else the newest pinned
  patch; a three-part request must match a pin exactly.
- **RECORD files are left as shipped**: not verified on install; importlib listings can lie;
  project-local/editable and direct requirements are skipped (`requirement-skipped`). **Sdists
  with dynamic build requirements** (PEP 517 `get_requires_for_build_wheel`) are unsupported —
  inspection is non-executing. Static backends are supported; `setup_requires` in legacy
  setup.py is unhandled — declare it in `pyproject.toml`. Rust sdists without a shipped
  `Cargo.lock` get a store-Cargo lock recorded `unattested-cargo-lock`; that lock is
  generated confined, through the resolution proxy, like a project's.
- **Immutable venvs are not drop-in venvs**: no activate scripts, and pip cannot mutate them.
  `tog run pip ...` and `tog run activate` are refused with the verb that replaces them
  (`tog add`, `tog run <command>`) rather than left to report a missing file, but **no pip
  shim and no `activate` script are planned**: a shim that accepted `pip install` would have
  to either mutate a read-only store object or silently rewrite the manifest, and an
  `activate` script inside the projection would have to be written into a read-only object.
  For a shell, `tog env` prints the environment as exports and `eval "$(tog env)"` applies
  it; that environment is then **ambient** for that shell — every later command sees it,
  tog's or not, and it outlives a `cd` out of the project. direnv is the way to scope it back
  to a directory (`echo 'eval "$(tog env)"' > .envrc && direnv allow`), which is why tog
  prints the environment instead of activating anything itself.
  No bytecode precompilation — slower cold starts.
- **macOS deployment-target wheel tags are not compared** — theoretical silent wrong-wheel
  risk. Markers/extras in a pinned file trigger a full uv re-lock; versions can shift.
  **Project-level `uv pip compile` in `src/commands/shared.rs` can still execute resolve-time metadata
  builds outside the sandbox** — sdist build-requirement resolution rejects build-time sdists
  instead.
- **Lock markers are read as PEP 508 and `packaging` 25 read them, with these
  refusals.** Each is a marker tog will not guess at, so a lock that uses one fails
  to import, naming it:
  - `platform_release` and `platform_version` are the running kernel's `uname -r` and
    `uname -v`, so a marker using them is evaluated only when the target is this host,
    and refused for a cross target. A project whose `uv.lock` names either records the
    kernel in its closure, so `tog status` reports a change and the next sync re-reads
    the lock after a kernel update. A Linux release such as `6.8.0-45-generic` is not a
    PEP 440 version, so ordering it (`platform_release >= '5.0'`) is refused by the next
    rule. `==`, `!=` and `in` work.
  - An ordering operator (`<`, `>=`, `~=`, ...) on a value that is not a PEP 440 version
    (`sys_platform > 'darwin'`) is refused, where `packaging` compares the strings.
  - A backslash or control character in a quoted value is refused, where `packaging`
    decodes it as a Python escape (`'lin\x75x'` is `linux`). No lock generator emits one.
  - A version segment past 2^64 (`18446744073709551616`) is refused.
  - A non-ASCII local version (`1.0+K` with the Kelvin sign) is refused, where
    `packaging`'s case-insensitive match folds some of them.
  - `extra` compares by normalized name with `==` and `!=` only, as uv does
    (`extra == '01'` does not match the extra `1`, where `packaging` compares versions).
    Every other operator on `extra`, `in` and `not in` included, is refused. uv ignores
    them with a warning, so ignoring one could install what the marker excludes.

  One divergence evaluates differently: `python_full_version ~= '3.12.0c1'` follows
  PEP 440 (`>=3.12.0c1, ==3.12.*`) and is true for 3.12.5, where `packaging` 25 keeps an
  extra release component for the `c`/`pre`/`preview` spellings and answers false.
- **Entry-point names are checked against tog's Unicode version, not the interpreter's.** The
  identifier tables come from the ICU data tog is built with, so a letter added in a newer
  Unicode than the target CPython knows is accepted by tog and is a SyntaxError in the
  generated launcher.

## JavaScript / npm

- **`npm install` is refused, not prevented.** `tog run npm install` is refused with an
  explanation, but npm run directly in the project still replaces the `node_modules` symlink
  with a real directory. Nothing enforces the projection at the filesystem level. `tog status`
  reports it as a real directory written over the projection and the next sync moves it
  aside and re-projects, so it is recoverable, not prevented.
- **Install scripts needing network for logic** are permissive with `install-script-failed`
  (declared-artifacts covers only matching cache locations; Electron-class needs per-version
  declarations). **Git sources are realized only when pinned to a full commit.**
  Branch/tag/bare URLs and ambient Git config fail closed. npm runs a git dep's `prepare`
  script; tog does not. Python and Cargo git deps work the same way, but Cargo's are not
  re-verified against the project's Cargo.lock at `run` — a post-sync lock edit is caught by
  cargo, not tog.
- **A required package for another platform is installed only from a pnpm lock.** pnpm
  installs a non-optional package whose `os`/`cpu`/`libc` excludes the host (with a warning);
  npm refuses the same lock with `EBADPLATFORM`, and tog follows whichever tool wrote the
  lock. From a pnpm lock the package is placed as verified files, recorded as
  `foreign-platform-package`, and its install scripts are not run. From a `package-lock.json`
  the sync stops and says to make the dependency optional. `yarn.lock` records no
  restrictions, so nothing is filtered there at all. pnpm's `supportedArchitectures` setting
  (install optional packages for other platforms too) is not read: an optional package for
  another platform is always left out.
- **A `pnpm-workspace.yaml` whose `packages` tog cannot read refuses sync, edits, and
  `attest`** (an anchor, an alias, a block scalar, a mapping item): a resolution record names
  every workspace member's `package.json`, so a members list tog cannot read would leave a
  member uncovered. The refusal comes in preflight, before anything is realized; write
  `packages` as a plain list of patterns.
- **A pnpm lock is checked against the manifests, but not through `.pnpmfile.cjs`.** Before
  planning, tog refuses a `pnpm-lock.yaml` that is missing a workspace member
  `pnpm-workspace.yaml` names, or whose importers disagree with a package.json, applying the
  lock's `overrides` by pnpm's selector rules (`name@range`, `parent>name`). A
  `.pnpmfile.cjs` `readPackage` hook that rewrites a project's own dependencies is not run,
  since that is project code, so such a lock reads as stale. A member that has only a
  `package.yaml` or `package.json5` is not found by the member check. A `pnpm-workspace.yaml`
  with no `packages` key (one that only holds settings) is read as naming no members, and a
  `packages` value that is not a plain list (an anchor, an alias) skips the member check with
  a note.
- **A workspace member whose `node_modules` holds files git tracks is not projected.** Some
  repositories commit a fixture `node_modules` (vite does). tog moves an npm-made
  `node_modules` into the store's backups before projecting, but moving a tracked one would
  delete committed source, so that member keeps its directory, gets no projected
  dependencies, and the sync prints a warning naming it (`tog status` counts that member
  synced while its directory is there). A tracked `node_modules` at the project root stops
  the sync instead, even when the only tracked file is a `.gitkeep` or `.gitignore`: untrack
  it (`git rm -r --cached node_modules`) and sync again. Each workspace's own repository
  is checked, including submodules and repositories inside `node_modules`. A failed index
  read stops sync before projection.
  Outside a repository nothing counts as tracked, including when Git is unavailable.
- **A registry package that depends on a workspace package makes `node_modules` a copy.**
  A plugin whose peer dependency is the package the repository itself develops has to
  resolve that package from the project's own source. Node looks dependencies up from a
  package's real path, and a store object cannot hold a link into a project, so for such a
  project the whole tree is copied into the projection (copy-on-write where the filesystem
  has reflinks: XFS, Btrfs, APFS; a full copy on ext4) instead of linked. The copy is
  writable and tog does not re-verify it, so each such package records
  `unattested-mutable-state`, which the company policy template denies. Copying only the
  packages that need it is not built.
- **Skipped install-time downloads are not in the closure**: puppeteer- and cypress-class
  packages record `artifact-not-provisioned`, fetched unverified only when the user runs that
  command. Electron's zip is provisioned instead, and a failed provisioning fails the sync.
- **Prebuilt binaries are compiled instead of downloaded; the result can differ from what npm
  would install. Wheel file-path collisions (`file-collision`), SHA-1 npm integrity, and pnpm 9
  MD5 patch hashes (`weak-integrity`) are permissive; strict via policy. Lifecycle scripts run in lockfile
  order, not dependency order (rarely bites, silent), and process-tree quiescence is not
  enforced: a postinstall daemon can outlive realization.

## Rust / cargo

- **Cargo resolves in the sandbox, through TLS interception** (`add`/`remove`/`update`, a
  missing `Cargo.lock`, `attest`, and an sdist's missing lock). Cargo has no network of its
  own: tog's proxy answers the crates.io index and download hosts and pinned git fetches,
  and records each request. Known edges: a project `.cargo/config.toml` that sets
  `registry.global-credential-providers` or a `credential-provider` as an array stops cargo
  with a config merge error, because tog forces string forms so no project provider can run
  (set them as strings or drop them). Authenticated alternative registries fail, as the
  sandbox gets no token. Path dependencies outside the workspace root are found from the
  manifests (dependency tables, `[patch]`, `[replace]`, `target.*`, `[workspace]`) and
  snapshotted read-only; one named only through a `[lib] path`, a build script or a
  symlinked directory is not, and cargo reports it missing. They must lie inside the
  project's repository (the nearest directory holding `.git`), or beside the workspace when
  there is no repository, never in a hidden directory, and that bound may not be `/` or the
  home directory: anything else is refused before cargo starts, naming the manifest. A
  resolution record names files inside the workspace only, so a workspace with a path
  dependency outside it is not attested (`tog attest` refuses it by name) and its edits and
  generated lock carry no record (`unrecorded-resolution` at sync). `attest` runs at the
  workspace root only. tog finds that root itself, reading the manifests the way cargo does;
  no cargo runs on the host. A project file that is the signing key under another name (a
  symlink, a hard link, an `include`) is refused before cargo reads it, and no message tog
  prints carries the key. A workspace member reached through a symlinked directory is refused
  for lock generation, edits and attest: the confined cargo would not see it. A `members`
  entry outside the workspace root (`../x`, an absolute path elsewhere) is treated like a
  path dependency outside it: the same location rules, `tog attest` refuses it by name, and
  edits and generated locks carry no record. Config `include`s are followed for the registries they declare and recorded as inputs; one
  that leads out of the workspace is refused. A git dependency resolved through the proxy
  has no offline test yet (the fixture registry holds no upload-pack body), only the git
  row's unit test.
- **Pinned Git dependencies work for standalone crates**; workspace-inherited manifests and
  escaping symlinks fail closed, and workspace metadata is not rewritten into vendor
  manifests. **Fail-closed rows**: alternative registries; beta/nightly channels. Loud.
  Cross `targets` get their standard library from the release's signed channel manifest,
  but tog provides no linker or C sysroot for them, so a crate that links for another
  platform still needs one on the machine. A custom toolchain works as a local directory
  (`path =` in rust-toolchain.toml), below.
- **A local toolchain (`[toolchain] path`) is trusted by content, not by origin.** The lock
  records its `rustc -vV`/`cargo -V` lines and a hash of the whole tree, so it proves the
  tree did not change, not who built it; every use records `external-toolchain`, which the
  company template denies. Locking runs the tree's own `bin/rustc` and `bin/cargo` for their
  versions (in the build sandbox, so it needs bubblewrap on Linux). The tree is re-hashed on every sync, build and
  fmt: the walk and link checks run in full, but a file whose device, inode, size and times
  are unchanged is not read again (its sum is cached in the store), so only the first
  hash of a full toolchain costs seconds. That key is the file's device, inode, size,
  mtime and ctime (seconds and nanoseconds), so a write that leaves all of them as they
  were (an NFS mount with coarse or cached attributes, or a write through a shared `mmap`
  that never updates the times) is not seen until the import's copy, hashed from the
  bytes, disagrees. That refusal re-reads the whole tree and rewrites the cache. Locking
  (`tog update --toolchain rust`) always reads every file. The lock row names
  an absolute path on one machine and one host platform, so a checkout elsewhere needs
  `tog update --toolchain rust`. As in rustup, a path cannot be combined with a channel,
  components, targets or a profile. A symlink in the tree is resolved against the tree
  itself, through any links it passes, and a tree with one that leads outside is refused.
- **No `profile` in rust-toolchain means rustc, cargo and the host std** (rustup's
  `minimal`), not rustup's configured default; ask for `profile = "default"` to get
  clippy, rustfmt and the docs. **No channel means the catalog's default release**
  (rustup's would be its configured default toolchain).
- **`profile = "complete"` fails on releases that did not build all of it** (1.96.1 lists
  `miri` and `rustc-codegen-cranelift` for Linux and macOS and marks both unavailable), as
  rustup's does; name the components instead.
  **`tog build` covers `build` only** — no sandboxed test/clippy/doc; those run via
  `tog run cargo ...` offline but unsandboxed. target/ is unmanaged scratch (no shared
  build cache). **`cargo install` through the wrapper is unmanaged** (lands in
  `.tog/cargo-home/bin`, outside the closure).

## Go

- **Only the Go lines go.dev lists as supported are realizable** (every release of each). An
  unmatched `go.mod` selection fails before store or network access. A non-default
  `toolchain` directive is exact; `go` alone is a minimum that takes the default (1.27.0) when
  it satisfies, else the newest release, where go itself would take the lowest.
  **Fail-closed rows**: go.work workspaces (including ancestor detection);
  local-path replace directives. Loud.
- **Graph-only modules are excluded from the closure**, so modgraph introspection can hit
  GOPROXY=off errors. **Private modules are unsupported**: GOPROXY forced to proxy.golang.org,
  GOVCS off, GOPRIVATE scrubbed.
- **The planner runs `go mod tidy` on out-of-sync manifests automatically**, mutating
  go.mod/go.sum. **`tog build` stages outputs then moves them**: `-o`-dependent workflows
  differ from plain `go build`; `-mod`/`-toolexec`/`-o` are rejected. The plan-cache key
  includes only `*.go` sources — go:embed and non-.go inputs do not invalidate it.

## Ruby

- **git and path gems fail closed; non-rubygems.org sources fail closed.** So do gems whose
  installers need network or absent host libraries (mysql2/rmagick-class) — no
  declared-artifacts mechanism for gems yet. **Default/bundled-gem preactivation edge**: a
  locked json/psych/openssl older than the toolchain's default can Gem::LoadError if something
  activates the default before Bundler setup. Untested matrix; potentially silent.
- **`bundle exec` compatibility is unproven**: env-based GEM_HOME activation works for
  `tog run ruby/rake`; full bundler runtime activation has not been exercised on a real
  Rails-class app.
- **System /etc/gemrc is still read** (GEMRC=/dev/null blocks only the user file).
  **Portable-ruby is a Homebrew-internal artifact**: relocation is probed to work but is not a
  contract, and its builds trail ruby-lang: the newest 3.4 build (3.4.6, the default) lacks
  the 3.4.10 security fixes in bundled gems, and Ruby 4.0 has no build at all. **CHECKSUMS-section locks fail closed if bundler's checksum registry API
  drifts**; new bundler formats need code updates.

## Elixir

- **Two OTP steps run outside the sandbox on Linux**: the `Install -cross -minimal` relocation
  and the OTP runtime probe (`src/tailors/elixir/mod.rs`). They touch only the staged object — the one
  non-sandboxed build step in the kernel. **OTP cache hits skip the runtime probe**: the OTP
  object was built on Fedora 44 (glibc 2.43 floor, OpenSSL 3.x); a store copied to an
  incompatible host fails only at execution time. Loud, but late.
- **Fail-closed rows**: git deps; non-hexpm repos; legacy mix.lock entry shapes (3/6/7-field —
  "refresh the lock"). **Umbrella projects are untested**. **Only OTP releases with a Linux build in
  `tog-toolchains` are realizable** (OTP 29.0.5 today, with each Elixir 1.20 patch); erlef
  publishes the Darwin builds for many more. **No rebar3 build for OTP 29 exists
  yet**: the pinned otp-28 escript runs on the 29 VM — a version-skew impurity until upstream
  ships otp-29 builds. **Mix's compilation lock is disabled in-sandbox**, so concurrent
  unsandboxed `mix compile` against one build root is unprotected; `tog build` runs
  MIX_ENV=dev only. **mix.exs elixir requirements are not consulted**: the OTP and Elixir
  entries in `.tool-versions` are the declarative sources the toolchain lock reads, because
  reading mix.exs means evaluating an Elixir program. **The deps projection is whole-tree
  writable**: one
  dep's build can modify a sibling dep, recorded unattested in the closure.

## .NET

- **Only an exact `global.json` selects the SDK.** `sdk.rollForward` must be `"disable"`;
  there is no second source and no roll-forward, so a mismatch is a hard error rather than a
  quiet upgrade.
- **Strictest v0 boundary of any tailor** (all loud): one SDK-style .csproj only — no .sln, no
  ProjectReference lock entries, no Central Package Management, no
  packages.config/PackageDownload, no workloads, no custom MSBuild SDKs, nuget.org only.
  Ancestor SDK inputs (global.json, Directory.Packages.props, Directory.Build.rsp,
  packages.config) fail closed.
- **Build-capable dotnet verbs are refused at `tog run`**; everything compiling goes
  through `tog build dotnet`, which covers build only (no test/publish verbs). The guard
  is advisory — `sh -c` can bypass it. **Restore-time MSBuild evaluation runs unsandboxed
  during missing-lock generation** (delegated-planning trust; the project's MSBuild code runs
  on the host). **Preflight is a fail-closed text scan, not an XML parse**:
  exotic-but-legitimate projects can be refused; nothing banned can hide (XML cannot
  entity-encode element names) — the build sandbox, not preflight, is the security boundary.
- **Output publication has a microsecond non-atomic window**: a reader during the rename sees
  no output; the last good build survives a failed publication. `/tmp/.dotnet` is a bounded,
  local-only sandbox write allowance. **releases.json is a checksum channel, not signed
  metadata.** **The lock does not cover asset selection**: project.assets.json is re-derived
  and attested but not diffed; a NuGet behavior change across SDK pins changes builds under
  the same lock, silently.

## Real-project proof gaps (all ecosystems)

- Python/npm were proven on Ethan's real projects (CX-Games, deja, Financial-Filing…). Cargo
  was proven on tog itself. **Go and Ruby have only been proven on small
  synthetic-but-real-dependency projects** — Go on a hello-world module pulling `rsc.io/quote`
  plus a cgo build; Ruby on rake/racc/nokogiri with nokogiri's native build. No large
  real-world Go service or Rails app has run under tog yet.

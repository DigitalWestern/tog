# Blanket — working notes

*One tool that replaces every package manager, toolchain installer, and task runner. Working name: **blanket**.*

## The core ideas

1. **One binary, every language.** Instead of pip + npm + cargo + homebrew + version managers, one tool: `blanket install`, `blanket run`, `blanket test`, `blanket build` — in any project, any language.

2. **Don't rewrite the languages — own their distribution.** We never reimplement Python or the Rust compiler. Blanket downloads its own vetted, reproducible builds of them (the compilers are open source and redistributable — this is how uv ships Python and how Zig ships a C compiler). The user never installs a language again; blanket makes the right one appear. From the user's chair, blanket *is* the runtime.

3. **Steal Nix's architecture, not its interface.** Nix proved the right model 20 years ago and failed only on usability (its custom language, terrible errors, cliff-shaped learning curve, no product leadership). The model:
   - Every package lives at a path named by a **hash of everything that made it** (source, flags, all dependencies). Two versions of the same library never conflict — they're different paths.
   - The store is **immutable**: installs never modify existing files, so nothing running can break.
   - Your environment is just **symlinks into the store** — upgrades and rollbacks are instant and atomic.
   - Builds are **pure functions**: same inputs → same output. A binary cache is just memoized builds.
   - The full dependency graph of anything (its "closure") is exactly knowable.

4. **Kernel + adapters.** One shared kernel (the store, the build engine, the environment/symlink layer — built once, the moat) plus one adapter per ecosystem that speaks its native registry and formats (PyPI, npm's registry, crates.io, plus a system-packages adapter that replaces Homebrew). "Every language" isn't one product — it's a sequence the architecture makes cheap.

5. **Cheat early:** an adapter may wrap an existing tool (embed uv, shell out to cargo) before being replaced natively. One binary from day one; go native ecosystem by ecosystem, like bun did.

6. **The enterprise sell is supply-chain security.** Today software enters a company through fifty doors (pip, npm, brew, curl | bash), none with a full inventory. Blanket is one door with a perfect manifest: "what is on this machine and where did every byte come from" becomes a query. Post-SolarWinds / xz-backdoor, that's a budget line. Nix had this and never sold it.

## Decisions made

- **Language: Rust.** (uv, cargo, and every serious new tool in this space agree.)
- macOS is a fine first platform; not dogmatic about it.
- Runtime rewrites (bun-style) stay possible later as an optimization, but are not the foundation.

## Known hard parts (eyes open)

- Making real-world builds truly reproducible is grinding work — nixpkgs spent 20 years on it.
- macOS sandboxing/codesigning is the roughest platform for pure builds.
- Each native adapter is a uv-sized project (uv ≈ one funded team, one year, one ecosystem).
- Existing "Nix without Nix" players to study: Devbox, Flox, Determinate Systems. None has broken out; understand why before assuming we're different.

## Design review with Codex (Sol), 2026-08-30

Sol's verdict: **pursue it**, but with three revisions to our premises.

### Revision 1 — the five questions collapse to three phases
The five-operation contract "describes a workflow, not a stable interface" — real ecosystems leak across it (Python source packages must *run code* just to reveal their build dependencies; npm packages can need multiple copies of the same version depending on neighbors; Rust build scripts change the plan mid-build). The sturdier boundary:
1. **Plan** — the adapter turns the project's native files into a fully locked, typed plan (may run small sandboxed jobs to discover metadata, then resume).
2. **Realize** — the kernel fetches, verifies, builds, caches, and records provenance. Universal.
3. **Project** — the adapter describes the folder layout its language expects; the kernel builds it atomically out of the store.

Don't freeze this as a public interface yet — build Python first, npm second, and extract the contract from what survives both.

### Revision 2 — own the *contract*, not every toolchain build
Don't commit to rebuilding every CPython/Node/JDK release ourselves (CVE rebuilds, signing infra, Apple licensing…). Blanket owns **selection, identity, invocation, policy, provenance**; the actual toolchain bytes can come from vetted upstream providers (python-build-standalone etc.), locked by digest and signature. Same user experience, fraction of the liability. Also dropped: "every adapter eventually goes native" as a goal — wrapping cargo hermetically may be permanently correct.

### Revision 3 — prior art reassessment
Devbox/Flox/Determinate aren't failed versions of this product — they're shells *around* Nix for dev environments. Their real limitation: once you're inside their environment and run pip/npm, the application dependency graph **escapes the unified inventory**. Blanket's differentiation is abstraction depth — managing the application-level graphs too. Also noted: mise already occupies the "outer shell" (tools + tasks) space; the task runner is not differentiated early.

### The first thing to build: a locked-plan realizer (not a resolver)
1. Import an existing Python lockfile (don't write a version-solver yet).
2. Materialize pinned CPython + wheel dependencies into the immutable store.
3. Build one real source package in a network-disabled sandbox.
4. Project a virtual-environment-shaped result; run the project through it.
5. Emit the full closure + provenance as JSON.

**Acceptance tests:** conflicting versions coexist across two projects; second install is a true cache hit; environment reconstructs offline after deletion; rollback is atomic; undeclared network access during a build fails; non-reproducible rebuilds get detected and quarantined.

Then: an npm lockfile importer against the *same kernel* (peer-aware node_modules projection). If both work, the thesis survives. Critically: uv/npm may resolve, but blanket must materialize and project — otherwise we've only proven orchestration.

### v0 decisions (from round 2)
- **Store root: `/opt/blanket/store`**, created by a one-time privileged installer; everything after runs unprivileged. Near-irreversible decision — binary caches only work if everyone shares the same logical path (same reason Nix is wedded to `/nix/store`). No per-user stores, no path rewriting.
- **Sandbox: `sandbox-exec`** (deprecated but functional), deny-by-default profile, no network, scrubbed environment. It's a hermeticity tool, not a defense against hostile build code. VMs/Endpoint Security only if it dies.
- **Python scope for v0:** wheels + source packages whose build requirements are fully declared. Fail loudly on anything dynamic. Editable installs deferred to an explicit mutable overlay.
- **Projection: one immutable venv-shaped store object** (real merged site-packages via APFS clones, `bin/python` symlink to stored interpreter), activated by a single `.venv → store` symlink. No per-package symlinks, no PYTHONPATH games.
- **macOS-first client ≠ macOS-first builder:** ship UX on macOS, but Linux can be the reference hermetic builder while macOS matures.

### Sharpened risk list
- Purity ≠ reproducibility (clocks, randomness, compiler nondeterminism) → cache trust needs signatures + builder provenance, not just hashes.
- A hash proves integrity, not trustworthiness → still need signature policy, revocation, yanked versions, malware response.
- Promise "complete **managed** closure," not "complete inventory" — programs can still load bytes via plugins, runtime downloads, system frameworks.
- "One door" for enterprises is only true if *enforced* (CI admission, registry proxies, device management) — otherwise blanket is door #51.
- Immutable store needs explicit mutable companions (editable installs, incremental build caches, workspaces).
- System packages (GUI apps, services, privileged installers) are a **different product** — model "host effects" separately, defer.
- Gradle/JVM is effectively unadaptable without embedding Gradle itself. Known dragon; route around it early.

### Reframed positioning
Not "one package manager that natively replaces everything" (destination, not architecture) but:
**a universal realization and environment kernel with ecosystem-native planners.**

## Open question (next grind)

The Plan format — the typed, locked description that every ecosystem compiles down to (Sol sketched required fields: source digests, package-instance context like features/peers/extras, build vs host vs target platforms, typed dependency edges, toolchain identity, sandbox capabilities, projection instructions).

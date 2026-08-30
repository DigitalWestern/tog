# Blanket — north star & follow-ups

*Written 2026-08-30 to re-orient future sessions. The MVP works (see
README/ARCHITECTURE); this document is about where it's pointed.*

## The frame: enterprise first

Blanket is posed for the **company's** benefit, with individual developers
advantaged by extension. The pitch in one line:

> Today software enters a company through fifty doors — pip, npm, brew,
> curl|bash — none with a complete inventory. Blanket is one door, with a
> perfect manifest of everything that came through it.

### What "one door" already means, today, in the MVP

- Every artifact is fetched through one code path, verified against a
  pinned hash, and re-verified on every cache hit.
- Every environment (comforter) records its complete closure — exact
  inputs, hash-level — in the closet's metadata and `.blanket/closure.json`.
  "What is on this machine and where did every byte come from" is already
  a query, not a forensic investigation.
- Builds run in a network-denied sandbox: a dependency cannot phone home
  or pull surprise inputs during install. (Proven by acceptance test.)
- Toolchains (CPython, Node) are pinned and verified — no developer-shell
  drift.

### The enterprise security model to build (the real follow-up)

The trust question Ethan raised: *who runs the security checks?* The
answer that fits blanket's shape: **blanket is the data plane, not the
security vendor.** Companies don't outsource judgment; they buy
enforcement points and evidence. So:

1. **SBOM export** (`blanket sbom`): emit the closure as standard
   CycloneDX/SPDX so companies' *existing* scanners (Snyk, Grype, Trivy,
   internal tooling) can vet what blanket installed. We produce evidence;
   their tools render verdicts. Cheap to build — the closure JSON already
   holds everything; this is a format translation.
2. **Policy hooks** (`blanket sync --policy <file>` or a policy server):
   allow/deny by registry host, package name/version, license, max age,
   CVE feed. Sync fails closed if policy says no. The company writes the
   policy; blanket enforces it at the door.
3. **Registry allowlist**: today a lockfile can point `resolved` at any
   https host (documented trust gap). Policy should be able to pin
   registries to the company mirror.
4. **Signed toolchain manifests**: replace trust-on-first-use pins with a
   signed provider manifest so toolchain provenance is verifiable.
5. **Central closet**: a shared/binary cache so the company builds an
   artifact once, signs it, and every laptop and CI runner reuses it.
   This is where the `/opt/blanket/store` fixed-path decision (Sol) comes
   back into scope.
6. **Honesty constraints** (from Sol's review, keep these in the pitch):
   - Promise the **complete managed closure**, never "complete inventory"
     — programs can still load bytes via plugins/runtime downloads.
   - "One door" is only true **if enforced** — without CI admission
     checks, registry proxies, or device management, blanket is door
     fifty-one. Enforcement integrations are part of the product, not an
     afterthought.

## The four pillars (all of them — don't shrink the ambition)

The goal was never "a better pip." Blanket does all four jobs, one
binary:

| pillar | status | next step |
|---|---|---|
| **Package manager** | ✅ built for Python + npm (hash-pinned lockfile realizer) | third ecosystem (cargo wrap is cheapest); native resolver later |
| **Toolchain manager** | ✅ built (pinned CPython 3.12/3.13, Node 24) | more versions + languages; signed manifests; `.python-version`-style selection per project everywhere |
| **Task runner** | ⬜ not started | `blanket test` / `blanket build` / `blanket <script>` reading package.json scripts + a `blanket.toml` for cross-language tasks. Sol's caution: mise already owns this shape — differentiate by running tasks *inside the projected env* with provenance, or wait for a real polyglot workspace need |
| **Runtime manager** | 🟡 partial | today blanket owns *distribution + invocation* of runtimes (the uv/zig model, deliberately chosen over bun-style engine rewrites). A native runtime remains a possible later optimization, per-ecosystem, where it buys speed or security — the interface already allows it |

Boiling the ocean is the point; the architecture (kernel + tailors) is
what makes the ocean boilable one pot at a time.

## Standing follow-up list

- [ ] `blanket sbom` — CycloneDX export of a project's closure(s)
- [ ] Policy engine v0 — registry allowlist + package allow/deny, fail closed
- [ ] Task runner v0 — `blanket run <script>` from package.json scripts
- [ ] Third tailor — cargo (wrap, hermetically)
- [ ] M5 hardening backlog (ARCHITECTURE.md): RECORD rewrite, Mach-service
      allowlist, deployment-target tags, streaming extractors, `blanket gc`
- [ ] Central closet / binary cache + fixed store path decision
- [ ] Friendlier CLI errors (e.g. `node.js` typo → "did you mean node?")
- [ ] Linux support (also unlocks the "Linux as reference hermetic
      builder" idea)

## Open questions for Ethan + Claude to chew on together

1. Which enterprise proof-of-concept is most convincing: SBOM export
   feeding an off-the-shelf scanner, or the policy-blocked `sync` demo
   ("watch blanket refuse a denied package at the door")?
2. Does the task runner earn its place before a third language does, or
   after? (What would *you* use first, day to day?)
3. When blanket meets a package needing install scripts (native addons),
   do we extend the sandboxed-build story to npm next, or keep Python the
   deep ecosystem and go wide instead?

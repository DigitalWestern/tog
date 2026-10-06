# What tog is, as a product

Written 2026-10-05 for the owner and for agents. STATUS.md says where the
code is; this page says what the code is *for*, who each part serves,
where the money is meant to come from, and where the open code stops.
Nothing here is a plan of record: the ordered work list stays in
FOLLOW-UPS.md.

## In one paragraph

Every language has a ritual: get the right runtime, install the right
packages, keep them apart from other projects. Python calls its folder
`.venv`, Node calls it `node_modules`. tog does that ritual for seven
languages in one binary. It downloads the official runtime and checks its
hash, keeps one read-only copy of everything in a store, points the
project at the store with a symlink, and writes a receipt (the closure)
saying exactly what went in and what it could not fully vouch for (the
exceptions). `tog audit` reads the receipt and passes or fails the project
against a policy. The receipt is the product. The CLI exists to write it.

## The deliverables

One binary, three things a buyer sees as separate, one more designed.

| # | Deliverable | Who it is for | What they see | State |
|---|---|---|---|---|
| 1 | The developer CLI | A developer at a laptop | Bare `tog`, `add`, `remove`, `update`, `run`, `env`, `x`, `build`, `fmt`, `tog <script>`, `tog <file>`. Terminal output, exit codes | Shipped, Linux x86_64 |
| 2 | The CI admission gate | A security or platform team | `tog audit` and `.tog/policy.toml`, closure signing (`keygen`, `attest`), the GitHub Action (`action.yml`): two workflow lines that sync, audit and write an SBOM. A green check or a red X on the pull request | Shipped. The Action can be pinned to a release from the next tag on |
| 3 | The compliance artifacts | An auditor, or whoever answers a customer's security questionnaire | `tog sbom` (CycloneDX 1.5, one JSON file), `tog ls`, `tog status`, and the committed closure files a reviewer diffs in a pull request | Shipped |
| 4 | The company layer | A company with many repositories | One policy pushed to every repository, package allow and deny lists, private registries, publisher trust, a view across every repository | Designed only: `docs/agent/DESIGNS.md` §2 and §4 |

Everything in rows 1 to 3 is terminal text and files in the repository.
There is no server, no web page and no generated document anywhere in
tog today.

## Who pays, and for what

Nobody pays for a command-line tool. Comparable tools (uv, pnpm, mise,
Bun) are free, and a developer does not switch for a tool that is ten
percent better. Companies pay for the thing their auditor has to see.

Demand for that is being created by regulation and by customers'
security questionnaires, not by tog:

- The EU Cyber Resilience Act requires a software bill of materials for
  products sold in the EU, applying from 2027.
- United States federal vendors face SBOM requirements under the 2021
  executive order on cybersecurity.
- SOC 2 and customer questionnaires ask "how do you control what goes
  into your builds."

tog's receipts are worthless one repository at a time. They are worth
money when a company has three hundred repositories and one person has to
answer "which builds pulled in package X, who signed off, and does every
repository follow the same rule." That answer needs a server: collect the
receipts, keep history, push one policy everywhere, hold the signing
keys, alert when a rule breaks. That server is the product to sell. The
free CLI is the channel: every developer who installs it writes receipts,
and every company whose developers write receipts has evidence with
nowhere to look at it.

## What is open and what is not

Decided 2026-10-05, recorded for agents in AGENTS.md and CLAUDE.md.

**Open, in this repository, Apache-2.0:** the whole CLI, and everything a
developer or a CI job runs on its own machine. Every ecosystem, the store,
the sandbox, the policy gate, signing, the SBOM, the GitHub Action, the
toolchain catalogs as shipped data. A security tool that downloads runtimes
and runs code on every developer's laptop does not get past a security
team unless they can read it, and no developer installs a closed binary
from an unknown solo author. Open is the price of the channel.

**Closed, in a separate repository, not yet started:**

1. Anything that receives closures from many customers over a network:
   the cross-repository dashboard.
2. The hosted toolchain catalog and publisher-key service: the signed
   answer to "which Python and Node releases exist and who published
   them," which every install would trust.
3. A hosted package mirror, once the CLI can go through a company's own
   registry.

The CLI may grow the client side of each (a command that posts a closure
to a configured address, a configurable catalog source) as long as it
keeps working with no hosted service at all.

## Why a dashboard alone is not a business, and what is

Another company's agent can build a dashboard against tog's receipts in
an afternoon. Nothing legal stops it, and the receipt format is public.
What a company will not do is run that dashboard for three years, so a
hosted dashboard is a product. It is a weak moat on its own, though.

The things that accrue trust to whoever runs them are the real moat:

- **The trusted catalog.** If tog's catalog service signs the list of
  real toolchain releases, every install trusts that key. A fork has to
  persuade companies to trust a different one. This makes the release
  catalog and publisher trust work (`docs/agent/DESIGNS.md` §2) the
  business, not plumbing.
- **The receipt and policy formats.** The CLI writes them, so the server
  that understands them first is the one written beside the CLI.
- **The company mirror.** A hosted registry the CLI already knows how to
  talk to.

## The closest existing tools

| Job | Tool | How tog differs |
|---|---|---|
| Scan a lockfile for known vulnerabilities | Snyk, Dependabot, Socket | They read the lockfile from outside and guess. tog did the install, so it records from inside |
| Write an SBOM | Syft, Trivy, GitHub's export | Same guess from the lockfile. tog's SBOM comes from the closure it built |
| Gate what gets downloaded | JFrog Artifactory, Sonatype Nexus | A company-run mirror in the network path, with a six-figure price. tog gates inside the install step and writes a signed receipt per build, which a mirror cannot. tog cannot yet go *through* a company's mirror: it forces public PyPI and the public Go proxy today (DESIGNS.md §4) |
| Manage toolchains across languages | mise, Nix | Same job, no receipt and no gate |
| One fast package manager | uv, pnpm, Bun | Same shared-cache idea, one ecosystem each, no receipt |

A company already on Artifactory cannot adopt tog until the private
registry work lands. Companies with no gate at all, which is every startup
under a few hundred people, are the first market.

## What a buyer will find first

Honest gaps, in the order a security reviewer meets them:

1. Dependency resolution for Python, npm, Ruby, Elixir and .NET still runs
   the ecosystem's own tool unsandboxed with network (`add`, `remove`,
   `update`, missing-lock generation). Go and Cargo resolve through tog's
   proxy. The receipt covers the install, not yet the step that chose what
   to install. This is the current work track (#68, FOLLOW-UPS.md).
2. Linux x86_64 only in releases. macOS has been run by hand; there is no
   Windows.
3. Real-project hit rate is about 27 of 30 for Python and 29 of 30 for npm
   (`docs/agent/HITRATE.md`). A customer meets the other one.
4. No private registry support.
5. The name `tog` belongs to an unrelated crate on crates.io.

## Still being thought about

Questions with no decision yet, kept here so they are not lost:

- The smallest sellable thing: a GitHub App that reads committed closures
  from a company's repositories, keeps history, shows one page across all
  of them, and charges per repository per month. Is it worth building
  before the trusted catalog service, or after?
- Whether the public website should be Rust too (Zola, Leptos). A separate
  repository either way, and not before there is something to show.
- The trademark on the name, which is the one legal lever that works with
  a permissive license: a fork cannot be called tog.
- Self-hosted versus hosted for the closed layer. Hosted first; banks and
  defense buyers will ask for self-hosted later.
- What going public buys now: users, feedback and outside trust. Not
  revenue, which under any model is two or more years and one outside
  company away.

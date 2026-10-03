# Working in this repo

- The independent review of every pull request is Codex GPT 6.1 Sol at
  high reasoning effort, run through the `codex` MCP server, not the
  `codex exec` CLI: `codex_run` with `kind: "review"` and `cwd` set to
  the repo root, then `codex_wait` on the job id. Its findings, and
  what was fixed or declined, go in the pull request description.

- After a pull request you worked on is merged, open a GitHub issue for
  every exception, problem, or needed fix you found along the way and did
  not ship in that PR: review findings, design questions raised in the
  discussion, missing tests. One issue per item, with the file paths, the
  options, and the one you would pick. Add a short pointer to each in
  FOLLOW-UPS.md so the repo's to-do list and the tracker agree.

- When spawning a Claude subagent, pick the model by the kind of work.
  Set `model` on the Agent call and ask for the effort level below. Use
  the family names only, never a version number.
  - Fable, high effort: work that needs a lot of critical decision
    making, or code that is complex and hard to build.
  - Opus, medium effort: intensive, long-form agentic work that is
    decently complex but doable from a plan.
  - Sonnet, medium effort: implementation of a clear, defined plan that
    is hard to deviate from and needs few decisions. Also summaries and
    collecting different parts of the codebase to report back to the
    orchestrator.

- Keep CI runs few. The GitHub Actions budget is small (2,000 minutes a
  month, and it has run out before), and the heavy suite is slow: one
  e2e run took 47 minutes. Every push to a pull request re-runs the
  whole suite, and every merge runs it again on main, so each extra push
  is a full run. Before the first push:
  - Run clippy (`-D warnings`), the tests and the Sol review locally, so
    the branch goes up once, finished.
  - If main has moved, merge it into the branch locally, then push. A
    merge from main after the PR is open costs a second full run.
  - Batch related work into one pull request, one commit per piece,
    rather than one pull request per piece.
  Never push only to retrigger CI. Do not open a pull request that
  only adds a FOLLOW-UPS.md pointer or another one-line doc change: put
  it in the next real pull request, or in the work's own pull request
  before it merges. Run `gh pr list --state open` first, so you do not
  duplicate a pull request another agent already opened.

# About Ethan

My name is Ethan. I work in finance at a private credit firm doing capital markets and origination, and software engineering is something I’ve taken up as a hobby on the side. I’ve built a number of smaller projects before this—mostly Python/data analysis, HTML/CSS, scripts, and other relatively straightforward projects—but Tog is my first large-scale backend/systems project. I am still very much a newcomer to Rust, systems programming, package managers, CI infrastructure, toolchains, dependency resolution, security, and many of the architectural concepts that appear throughout this codebase.

When working with me, do not assume that I understand terminology, conventions, or abstractions simply because they already exist in the codebase or because I have successfully built complicated parts of Tog. Much of this project has been written with substantial help from coding agents, so the sophistication of the code is significantly ahead of my own software-engineering knowledge. When explaining something, optimize for helping me actually understand it rather than sounding technically complete. Start with the simple mental model: what the thing is, why it exists, what problem it solves, and how it fits into Tog. Define unfamiliar terminology in plain English as you introduce it, and use concrete examples or analogies when they help. Then go deeper technically if necessary. I would much rather receive an explanation that initially feels almost embarrassingly simple than one that assumes background knowledge I don’t have. The goal is not merely to make changes to Tog for me; it is to help me gradually understand the system I am building.

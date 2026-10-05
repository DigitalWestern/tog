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
  - Know whether your change wakes the heavy suite. heavy.yml runs the
    47-minute e2e job on a pull request when it changes any file its
    `gate` job watches: `src/kernel/archive*`, `src/kernel/fetch*`,
    `src/kernel/sandbox*`, anything under `src/kernel/provider/`, any
    `catalog.toml`, `Cargo.lock`, `heavy.yml`, or `tests/acceptance.sh`.
    It also runs for any file under `tests/` other than a top-level
    `tests/*.rs`, `tests/size_baseline.txt` or `tests/install.sh`
    (`tests/common/`, fixtures). A changed top-level `tests/<name>.rs`
    only runs that file's ignored tests. The `gate` job in `heavy.yml`
    is the authority. Once it is woken, every later push
    to that pull request runs it again. So do not touch those files in
    passing (a comment fix, a test-only helper): put that in a pull
    request that has to touch them anyway. When a pull request must
    touch them, run the e2e suites it affects locally before the first
    push (see the local equivalents below). #409 woke the suite twice
    with a one-line test-only change to `src/kernel/provider/rust.rs`.
  Never push only to retrigger CI. Do not open a pull request that
  only adds a FOLLOW-UPS.md pointer or another one-line doc change: put
  it in the next real pull request, or in the work's own pull request
  before it merges. Run `gh pr list --state open` first, so you do not
  duplicate a pull request another agent already opened.

- When CI fails on a pull request, reproduce and fix it on this machine,
  not in the cloud. You have permission to run any CI job locally,
  including the slow ones. Read the failing job's log (`gh run view
  <run-id> --log-failed`), run that job's commands from
  `.github/workflows/` here, fix the code, and re-run them until they
  pass. Then push once. Do not push a guess and wait for CI to tell you
  whether it worked: that spends a full cloud run to learn what a local
  run would have told you. The local equivalents:
  - `test` (ci.yml): `cargo fmt --check`, `cargo clippy --locked
    --all-targets -- -D warnings`, `cargo test --locked`,
    `bash tests/install.sh`, `python3 tools/test_catalog.py`.
  - `e2e` (heavy.yml): `cargo test --locked --no-fail-fast -- --ignored
    --test-threads=1`, or only the failing suite with `--test <name>`,
    then `bash tests/acceptance.sh`. Point `TMPDIR` at a directory under
    `$HOME` first: these tests leave large stores behind and fill the
    `/tmp` quota.
  Clean up after yourself. Give each run its own fresh scratch directory,
  for example `TMPDIR=$HOME/tog-tmp/<branch-name>`. Once the checks pass,
  delete that directory (`rm -rf "$HOME/tog-tmp/<branch-name>"`), and
  any `$HOME/tog-tmp/run-*` directory you created. Do this before you
  report the work as done, so nobody has to clear disk space later.
  Delete only directories you created in this task: never
  `$HOME/tog-tmp` itself, and never another agent's directory, which may
  still be in use. Also delete the `/tmp/tog-*` stores your own test
  runs left, and only those. Use `find /tmp -mindepth 1 -maxdepth 1
  -name 'tog-*' -user "$USER" -mmin -<minutes since you started>`, and
  read the list before deleting anything. A `find` without `-mindepth 1`
  can match the parent directory itself, and once deleted a whole tree
  that way.
  Never re-run a failed job in the cloud (the Actions "Re-run jobs"
  button, `gh run rerun`, or an empty commit) to see whether a fix
  worked. The local run is the re-run, and you have permission to do it
  without asking, however long it takes. Run long suites in the
  background so other work goes on meanwhile.
  If a failure only happens on the runner (a different Ubuntu version,
  AppArmor, the runner's disk) and cannot be reproduced here, say so in
  the pull request. Then one push to test the fix in the cloud is fine.

# About Ethan

My name is Ethan. I work in finance at a private credit firm doing capital markets and origination, and software engineering is something I’ve taken up as a hobby on the side. I’ve built a number of smaller projects before this—mostly Python/data analysis, HTML/CSS, scripts, and other relatively straightforward projects—but Tog is my first large-scale backend/systems project. I am still very much a newcomer to Rust, systems programming, package managers, CI infrastructure, toolchains, dependency resolution, security, and many of the architectural concepts that appear throughout this codebase.

When working with me, do not assume that I understand terminology, conventions, or abstractions simply because they already exist in the codebase or because I have successfully built complicated parts of Tog. Much of this project has been written with substantial help from coding agents, so the sophistication of the code is significantly ahead of my own software-engineering knowledge. When explaining something, optimize for helping me actually understand it rather than sounding technically complete. Start with the simple mental model: what the thing is, why it exists, what problem it solves, and how it fits into Tog. Define unfamiliar terminology in plain English as you introduce it, and use concrete examples or analogies when they help. Then go deeper technically if necessary. I would much rather receive an explanation that initially feels almost embarrassingly simple than one that assumes background knowledge I don’t have. The goal is not merely to make changes to Tog for me; it is to help me gradually understand the system I am building.

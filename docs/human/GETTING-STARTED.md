# Getting started

Install tog, check the host, and take one Python project and one npm project
from a bare checkout to a running command. Half an hour, most of it reading.

Every block below is real output from tog 0.1.0 on Linux x86_64, captured in
one session. Two notes on what you will see in it. The session pointed
`TOG_STORE` at a throwaway directory so it could show a genuinely first
sync; on your machine that path reads `~/.tog/store`. And the two projects
are this repository's own test fixtures: `tests/fixtures/proj-a` (a
uv-compiled `requirements.txt` pinning markupsafe) copied to `api/`, and
`tests/fixtures/proj-npm` (is-odd and wrappy, with a `package-lock.json`)
copied to `web/`. Object ids are hashes of the inputs, so yours will differ.

The words below — store, realize, project, closure, exception, permissive —
are defined in the six-row table at the top of [the README](../../README.md).

## 1. Install

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalWestern/tog/main/install.sh | sh
```

It downloads the release binary for your machine, checks its sha256, puts it
in `~/.local/bin`, installs bash/zsh/fish completions, and tells you where
the store will be and roughly how large it gets. A script cannot change the
PATH of the terminal that ran it, so the last thing it prints is the one
command that fixes that terminal:

```sh
source "$HOME/.tog/env"
```

New terminals have `tog` without it. To undo the whole thing later, run the
same script with `--uninstall`: it removes the binary, the env file, the
completions and the PATH blocks it added, and leaves the store, which is
downloaded data rather than part of the program.

On Linux you also want bubblewrap and a C toolchain, because the build
sandbox and native builds need them; the
[README](../../README.md#host-prerequisites) has the package list, and
`doctor` tells you if one is missing.

## 2. Check the host

```
$ tog doctor
ok    platform     x86_64-unknown-linux-gnu
ok    store        /tmp/tog-demo/store (0 objects, 0 cached artifacts)
ok    disk         11.2 GiB free under the store
ok    toolchains   none realized yet; the first 'tog sync' downloads what the project needs
ok    sandbox      bubblewrap at /usr/bin/bwrap
ok    c-toolchain  cc, c++, make, pkg-config, patch on PATH
ok    policy       permissive (no policy file, TOG_STRICT unset)
ok    project      python found; not synced yet: python (run 'tog sync')
```

Eight rows, exit 0 when all eight say `ok`. This is the command to run
before you file a bug and the output to paste into it. The `store` row
answers "where does all this go": one directory per machine, shared by every
project on it, created the first time something needs it.

## 3. A Python project

Nothing to configure and nothing to initialize. A directory with a
`requirements.txt` is already a tog project:

```
$ cd api
$ tog sync
tog: python inputs: requirements.txt
synced: .venv -> /tmp/tog-demo/store/objects/4002574e4e21aab52a9e4abe4ff2b2c6e9158b48-env-3.12.14
tog: closures unsigned; tog audit reports them outdated (set TOG_SIGNING_KEY=<key file> to sign; 'tog keygen' makes one)
```

5.4 seconds from an empty store, most of it downloading CPython. You did not
install Python: tog fetched a pinned, hash-verified 3.12.14 into the store
and built the venv out of it. The third line is about CI, not about this
sync — records are written unsigned until you hand tog a key, and `tog
audit` is the only command that minds. Ignore it until you set up a gate.

Inside a project, a bare `tog` means `tog sync`, so from here on it is one
word.

Run something in it:

```
$ tog run python -c "import markupsafe; print(markupsafe.escape('<b>'))"
&lt;b&gt;
$ tog run sh -c 'command -v python'
/tmp/tog-demo/api/.venv/bin/python
```

`run` puts the projected environment on PATH for one command. The venv is a
real venv and activating it the usual way works, but `tog run` is the form
that means the same thing in every ecosystem.

See what is in it:

```
$ tog ls
python  (cpython 3.12.14; 2 packages)
  markupsafe  3.0.2
  six         1.17.0
```

## 4. An npm project

Same command. A `package-lock.json` is enough:

```
$ cd ../web
$ tog sync
synced: node_modules -> /tmp/tog-demo/store/objects/9d0333722d78ff1fa9a845b3693f9794be556d7c-env-24.20.0
```

3.8 seconds, including downloading Node 24.20.0. A directory holding both a
`requirements.txt` and a `package-lock.json` gets both ecosystems out of one
`tog sync`, with no flags and no ordering.

Scripts in `package.json` run without the `run`:

```
$ tog dev
tog: > dev: node index.js
is-odd(3): true
```

`tog <script>` is the short form of `tog run <script>` for any script whose
name is not one of tog's own commands. Arguments after the name go to the
script unchanged, so there is no npm-style separator to remember: `tog test
--watch`, not `tog test -- --watch`. A built-in always wins, which means
`tog build` is the sandboxed build; `tog run build` reaches a script called
build.

## 5. What is on disk now

Three things, in three places.

**`.venv` and `node_modules` are symlinks**, not directories:

```
$ readlink api/.venv
/tmp/tog-demo/store/objects/4002574e4e21aab52a9e4abe4ff2b2c6e9158b48-env-3.12.14
$ readlink web/node_modules
/tmp/tog-demo/store/forests/476f1751b2805ac57131c269d4a83bd7/c7b7235a2865f09767fa5aeb81256888/node_modules
```

What they point at is read-only. Switching locks, or rolling back to an old
one, is a symlink swap, which is why a sync you have done before is instant
instead of a reinstall. (Node gets a per-project forest rather than a plain
object so that scratch writes inside `node_modules` have somewhere to go;
package contents are still read-only store objects.)

**`.tog/` is small, and part of the project:**

```
$ find .tog          # in api/
.tog
.tog/closures
.tog/closures/python.json
.tog/plan.json
```

`closures/python.json` is the record of this sync — which inputs, which
objects, which exceptions — and it is meant to be committed. `plan.json` is
a cache keyed by the hash of your inputs, so an unchanged lock never touches
the network again; it is machine-local, so ignore it. The README has the
[full table and the matching `.gitignore`
stanza](../../README.md#what-tog-holds-and-what-to-commit); `tog audit`
cannot pass in a repository that ignores all of `.tog/`.

**The store holds everything else.** Both projects above, from nothing:

```
$ tog store path
/tmp/tog-demo/store
$ du -sh /tmp/tog-demo/store
706M	/tmp/tog-demo/store
```

That is two toolchains plus the verified download cache they came from. It
does not grow per project: a second project on the same lock is a store hit
on the same object id, in a seventh of a second.

```
$ cd ../api2 && tog
tog: python inputs: requirements.txt
synced: .venv -> /tmp/tog-demo/store/objects/4002574e4e21aab52a9e4abe4ff2b2c6e9158b48-env-3.12.14
```

`tog gc --dry-run` shows what could be reclaimed and changes nothing:

```
$ tog gc --dry-run
tog: gc would free 0 MB (0 objects, 0 cached artifacts)
```

## 6. Day two

`tog status` answers one question: is what is projected still what the files
on disk say? Offline, read-only, exit 0 only when every detected ecosystem
is synced — which is what makes it usable as a "did you commit the lock" CI
gate.

```
$ tog status
node  synced      (node 24.20.0; 3 packages)

1 of 1 synced.
```

Edit `package.json` and it says so, and names the file:

```
$ tog status
node  changed     package.json since the last sync; run 'tog sync'

0 of 1 synced; 1 changed.
Exit status is 0 only when every ecosystem is synced.
```

Exit 1. Run `tog`, and it is back to `synced`. Add and remove dependencies
through tog so that the manifest, the lock and the closure move together:

```sh
tog add requests          # uv, npm, cargo, go, bundler: whichever owns this project
tog remove requests
tog update                # re-lock within the manifest's constraints
```

`--json` is there on `status`, `ls`, `audit`, `doctor` and `plan` for when
something other than a person reads the answer.

## 7. When it goes wrong

Two errors you will hit first. Neither is a usage error, so both exit 1.

```
$ tog
tog: no project in /tmp/tog-demo/scratch: nothing to sync here.
```

No manifest here. Tog prints its usage after that line so you can see what
else it does; the full list of files it looked for is in `tog help sync`.

```
$ tog run python --version
tog: error: no environment projected here for command 'python'; run `tog sync` first
```

A manifest exists, but nothing has been synced yet, or the projection was
deleted. Run `tog`.

For anything else: `tog doctor` first, `-v` second. Verbose mode prints
every decision and every subprocess command line, which is what a bug report
needs.

## Next

- [CLI.md](CLI.md) — every command, and the conventions that hold across all
  of them: stdout is results, stderr is narration, pass-through is sacred.
- [LIMITATIONS.md](LIMITATIONS.md) — what tog honestly cannot do yet. Read
  it before adopting tog for something that matters.
- [ARCHITECTURE.md](ARCHITECTURE.md) — the store model, and why the rest is
  shaped the way it is.

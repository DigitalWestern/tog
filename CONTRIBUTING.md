# Contributing

## License

tog is licensed under the Apache License 2.0 ([LICENSE](LICENSE)). Every
contribution is accepted under that license, as section 5 of the license
says; there is no separate contributor license agreement to sign.

## Sign your commits

Each commit carries a `Signed-off-by` line with your name and email:

```sh
git commit -s
```

That line is your statement of the
[Developer Certificate of Origin](https://developercertificate.org): you
wrote the change, or have the right to submit it under the project's
license. The `dco` job in `.github/workflows/dco.yml` checks every commit
a pull request adds, with `tools/dco.sh`; a commit without the line fails
the check, and so does one authored or signed off by an agent's address
(`noreply@anthropic.com`): the sign-off is a person's. A `Co-Authored-By`
trailer needs no sign-off of its own.

## Before you push

Run what CI runs, so a pull request goes up once, finished:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash tests/install.sh
python3 tools/test_catalog.py
```

The rest of how work happens here, including the review every pull
request gets and when the slow network suite runs, is in
[AGENTS.md](AGENTS.md) and [STATUS.md](STATUS.md).

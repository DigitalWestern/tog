#!/bin/bash
# One run on a Mac fills in the Mach allow-list table of docs/agent/DESIGNS.md §6
# (PR 0, "pending: needs a macOS host"). From the repository root:
#
#   tools/proxy_spike/macos_mach.sh [work dir, default ~/tog-pr0-mach]
#
# It builds tog, provisions every census toolchain into a scratch store by
# syncing the test fixtures, installs mitmproxy in a venv, runs the census
# under `sandbox-exec` with a `(deny mach-lookup (with report))` profile
# (spike.py --engine seatbelt, which iterates each run to the smallest
# passing allow-list), and prints the table with mach_report.py. The exit
# status is non-zero when a run failed or a list names a forbidden service.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=${1:-$HOME/tog-pr0-mach}
store=$work/store
tog=$repo/target/release/tog
mkdir -p "$work/prov"
export TOG_STORE=$store

cargo build --release --locked --manifest-path "$repo/Cargo.toml"

for fixture in cargo-hello go-hello ruby-hello elixir-hello dotnet-hello proj-npm proj-a proj-pnpm; do
  rm -rf "${work:?}/prov/$fixture"
  cp -R "$repo/tests/fixtures/$fixture" "$work/prov/$fixture"
done
# pnpm is realized per packageManager, uv on the first compile.
python3 - "$work/prov/proj-pnpm/package.json" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data["packageManager"] = "pnpm@9.15.4"
json.dump(data, open(path, "w"), indent=2)
PY
for fixture in cargo-hello go-hello ruby-hello elixir-hello dotnet-hello proj-npm proj-a; do
  (cd "$work/prov/$fixture" && "$tog" >/dev/null)
done
(cd "$work/prov/proj-a" && "$tog" add iniconfig >/dev/null)
(cd "$work/prov/proj-pnpm" && "$tog" add is-number >/dev/null)

if [ ! -x "$work/venv/bin/mitmdump" ]; then
  python3 -m venv "$work/venv"
  "$work/venv/bin/pip" install --quiet mitmproxy
fi

rm -rf "$work/run"
python3 "$repo/tools/proxy_spike/spike.py" --engine seatbelt --work "$work/run" --store "$store" \
  --mitmdump "$work/venv/bin/mitmdump" census python npm pnpm cargo go ruby elixir dotnet git \
  | tee "$work/census.log"
python3 "$repo/tools/proxy_spike/mach_report.py" "$work/run"

#!/usr/bin/env bash
# Every commit in <base>..<head> carries a Signed-off-by line naming its
# author's email: the Developer Certificate of Origin (CONTRIBUTING.md).
# Merge commits are skipped, and a Co-Authored-By trailer needs no
# sign-off of its own. The `dco` job in .github/workflows/ci.yml runs this
# on a pull request; locally: tools/dco.sh origin/main HEAD
set -euo pipefail
base=${1:?usage: tools/dco.sh <base> <head>}
head=${2:?usage: tools/dco.sh <base> <head>}
bad=0
while read -r commit; do
  email=$(git show -s --format=%ae "$commit")
  if ! git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$commit" \
    | grep -qiF "<$email>"; then
    echo "$(git show -s --format='%h %s' "$commit"): no Signed-off-by for <$email>; commit with 'git commit -s'" >&2
    bad=1
  fi
done < <(git rev-list --no-merges "$base..$head")
exit "$bad"

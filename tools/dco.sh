#!/usr/bin/env bash
# Every commit in <base>..<head> carries a Signed-off-by line naming its
# author's email: the Developer Certificate of Origin (CONTRIBUTING.md).
# The sign-off is a person's: a commit whose author or sign-off is an
# agent's address (noreply@anthropic.com) fails. Merge commits are
# skipped, and a Co-Authored-By trailer needs no sign-off of its own. The
# `dco` job in .github/workflows/dco.yml runs this on a pull request's merge
# ref as `tools/dco.sh HEAD^1 HEAD^2`; locally: tools/dco.sh origin/main HEAD
set -euo pipefail
base=${1:?usage: tools/dco.sh <base> <head>}
head=${2:?usage: tools/dco.sh <base> <head>}
agent='noreply@anthropic.com'
git rev-parse --verify -q "$base^{commit}" > /dev/null
git rev-parse --verify -q "$head^{commit}" > /dev/null
commits=$(git rev-list --no-merges "$base..$head")
bad=0
while read -r commit; do
  [ -n "$commit" ] || continue
  subject=$(git show -s --format='%h %s' "$commit")
  email=$(git show -s --format=%ae "$commit")
  trailers=$(git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$commit")
  if [ "$email" = "$agent" ]; then
    echo "$subject: authored by $agent; a person commits, with 'git commit -s'" >&2
    bad=1
  elif grep -qiF "<$agent>" <<< "$trailers"; then
    echo "$subject: signed off by $agent; the sign-off is a person's" >&2
    bad=1
  elif ! grep -qiF "<$email>" <<< "$trailers"; then
    echo "$subject: no Signed-off-by for <$email>; commit with 'git commit -s'" >&2
    bad=1
  fi
done <<< "$commits"
exit "$bad"

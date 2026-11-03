#!/usr/bin/env bash
# Cut a release:  ./release.sh 1.2.0
# Bumps VERSION, moves "Unreleased" notes in CHANGELOG.md under the new version, commits and tags.
# Then:  git push && git push --tags   (GitHub Actions builds the release tarball)
set -euo pipefail
NEW="${1:-}"
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: ./release.sh X.Y.Z (current: $(cat VERSION))"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "commit or stash your changes first"; exit 1; }
git rev-parse "v$NEW" >/dev/null 2>&1 && { echo "tag v$NEW already exists"; exit 1; }
OLD=$(cat VERSION)
echo "$NEW" > VERSION
TODAY=$(date +%F)
python3 - "$NEW" "$OLD" "$TODAY" <<'PY'
import re, sys
new, old, today = sys.argv[1:]
p = "CHANGELOG.md"; s = open(p).read()
s = s.replace("## [Unreleased]\n", f"## [Unreleased]\n\n## [{new}] - {today}\n", 1)
s = re.sub(r"\[Unreleased\]: \.\./\.\./compare/v[\d.]+\.\.\.HEAD",
           f"[Unreleased]: ../../compare/v{new}...HEAD\n[{new}]: ../../compare/v{old}...v{new}", s, count=1)
open(p, "w").write(s)
PY
git add VERSION CHANGELOG.md
git commit -m "Release v$NEW"
git tag -a "v$NEW" -m "v$NEW"
echo "Tagged v$NEW ($OLD -> $NEW). Now: git push && git push --tags"

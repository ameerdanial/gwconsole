#!/usr/bin/env bash
# Cut a release:  ./release.sh 1.3.0
# Bumps VERSION, moves the "Unreleased" notes in CHANGELOG.md under the new version, makes
# one commit per file (so GitHub shows what each file is for) and creates the vX.Y.Z tag.
# Then:  git push && git push --tags   (GitHub Actions builds the release tarball)
set -euo pipefail
NEW="${1:-}"
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: ./release.sh X.Y.Z (current: $(cat VERSION))"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "commit or stash your changes first"; exit 1; }
git rev-parse "v$NEW" >/dev/null 2>&1 && { echo "tag v$NEW already exists"; exit 1; }
OLD=$(cat VERSION)
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
git add CHANGELOG.md
git commit -q -m "CHANGELOG.md: Release notes for every version (adds v$NEW)"
echo "$NEW" > VERSION
git add VERSION
git commit -q -m "VERSION: Current release version shown in the UI and CLI ($NEW)"
git tag -a "v$NEW" -m "v$NEW"
echo "Tagged v$NEW ($OLD -> $NEW). Now: git push && git push --tags"

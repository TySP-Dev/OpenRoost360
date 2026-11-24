#!/usr/bin/env bash
# Update OpenRoost360 (Docker): fetch the newest release from git, rebuild the image, restart the container.
#   ./update.sh            newest release tag (vX.Y.Z)
#   ./update.sh main       newest commit on main (development)
#   ./update.sh v0.2.0     a specific release
# Data in ./data is kept. Make a backup first (Settings → System → Backup) if you like.
set -euo pipefail
cd "$(dirname "$0")"
git fetch --tags --prune origin
target="${1:-$(git tag -l 'v*' --sort=-v:refname | head -n1)}"
if [ -z "$target" ]; then echo "No release tags yet; using main"; target=main; fi
if [ "$target" = main ]; then git checkout -q main && git pull -q --ff-only origin main
else git -c advice.detachedHead=false checkout -q "$target"; fi
export GIT_COMMIT="$(git rev-parse --short HEAD)"
echo "Building OpenRoost360 $target ($GIT_COMMIT)…"
docker compose build --pull
docker compose up -d
docker image prune -f >/dev/null
echo "Done. $(docker compose ps --format '{{.Name}}: {{.Status}}')"

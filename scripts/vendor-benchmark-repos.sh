#!/usr/bin/env bash
# SEC-38 - vendor the external benchmark projects as frozen snapshots.
#
# Each repo is cloned (shallow, default branch) into a temp dir, its exact HEAD
# commit is captured, and its working tree is copied into benchmark/<name>/ WITHOUT
# the nested .git directory - so no foreign git history is vendored into this repo.
# The existing .gitkeep in each target folder is preserved.
#
# These are deliberately-vulnerable measurement projects. They live under benchmark/,
# which is guarded by .no-ingest and must NEVER be embedded into the RAG knowledge base.
#
# Re-runnable: each target is cleared (except its .gitkeep) before the snapshot is laid down.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
BENCH_DIR="$REPO_ROOT/benchmark"

# name | upstream URL
REPOS=(
  "terragoat|https://github.com/bridgecrewio/terragoat.git"
  "kubernetes-goat|https://github.com/madhuakula/kubernetes-goat.git"
  "cfngoat|https://github.com/bridgecrewio/cfngoat.git"
)

vendor_one() {
  local name="$1" url="$2"
  local target="$BENCH_DIR/$name"
  local tmp
  tmp="$(mktemp -d)"
  # Clean up the temp clone no matter how this function exits.
  trap 'rm -rf "$tmp"' RETURN

  echo ">>> $name : cloning $url"
  git clone --quiet --depth 1 "$url" "$tmp/repo"

  local sha
  sha="$(git -C "$tmp/repo" rev-parse HEAD)"

  mkdir -p "$target"
  # Wipe the target (except its .gitkeep) so a re-run is a clean snapshot, not a merge.
  find "$target" -mindepth 1 -not -path "$target/.gitkeep" -exec rm -rf {} + 2>/dev/null || true

  # Copy the whole working tree, dotfiles included, but exclude the nested .git so no
  # foreign history is vendored. tar-piping preserves the existing .gitkeep in the target.
  ( cd "$tmp/repo" && tar --exclude='./.git' -cf - . ) | ( cd "$target" && tar -xf - )

  # Strip the upstream's own .gitignore files. A frozen snapshot must track its entire
  # working tree; leaving these in place makes THIS repo's git silently drop the vendored
  # files the upstream ignored (e.g. build output committed anyway), so the committed
  # snapshot would not match the pinned commit. SEC-38.
  local stripped
  stripped="$(find "$target" -name .gitignore -type f | wc -l | tr -d ' ')"
  find "$target" -name .gitignore -type f -delete

  local count
  count="$(find "$target" -type f | wc -l | tr -d ' ')"

  echo "    pinned commit    : $sha"
  echo "    .gitignore stripped: $stripped"
  echo "    files vendored   : $count (into benchmark/$name/, incl. .gitkeep)"
  echo
}

echo "Vendoring benchmark repos into $BENCH_DIR"
echo
for spec in "${REPOS[@]}"; do
  name="${spec%%|*}"
  url="${spec#*|}"
  vendor_one "$name" "$url"
done

echo "Done. Reminder: benchmark/ is a measurement corpus - never ingest it into RAG."

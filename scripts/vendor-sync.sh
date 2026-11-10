#!/usr/bin/env bash
# Keep vendored verified libraries (see vendored.toml) identical to upstream.
#
#   scripts/vendor-sync.sh check                      # all libs: files + spec lock entry == upstream rev
#   scripts/vendor-sync.sh update <lib> <rev>         # re-vendor <lib> from upstream commit <rev>
#
# `update` copies the files and records the rev. It does NOT touch
# specs.lock.json: review the upstream intent/spec diff, then run
#   tools/vc.py lock <lib>
# and `check` confirms your lock entry equals upstream's.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Print "<repo>\t<rev>" and then "<upstream>\t<local>" lines for one lib.
lib_config() {
  python3 -I - "$1" <<'EOF'
import sys, tomllib
cfg = tomllib.load(open("vendored.toml", "rb"))
lib = cfg.get(sys.argv[1]) or sys.exit(f"vendor-sync: {sys.argv[1]!r} not in vendored.toml")
print(lib["repo"], lib["rev"], sep="\t")
for up, local in lib["files"]:
    print(up, local, sep="\t")
EOF
}

libs() { python3 -I -c 'import tomllib; print("\n".join(tomllib.load(open("vendored.toml","rb"))))'; }

fetch() { # fetch <repo> <rev> <dir>
  git init -q "$3"
  git -C "$3" fetch -q --depth 1 "$1" "$2"
  git -C "$3" checkout -q FETCH_HEAD
}

lock_entry() { # lock_entry <specs.lock.json> <lib>
  python3 -I -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["katas"].get(sys.argv[2]), sort_keys=True))' "$1" "$2"
}

check_lib() {
  local lib="$1" repo rev up local failed=0
  { IFS=$'\t' read -r repo rev; mapfile -t pairs; } < <(lib_config "$lib")
  local src="$tmp/$lib"
  fetch "$repo" "$rev" "$src"
  for pair in "${pairs[@]}"; do
    IFS=$'\t' read -r up local <<<"$pair"
    if ! diff -r -x target "$src/$up" "$local" >/dev/null 2>&1; then
      echo "  ✗ $local differs from $repo@${rev:0:12}:$up" >&2
      diff -r -x target "$src/$up" "$local" | head -20 >&2 || true
      failed=1
    fi
  done
  if [[ "$(lock_entry "$src/specs.lock.json" "$lib")" != "$(lock_entry specs.lock.json "$lib")" ]]; then
    echo "  ✗ specs.lock.json entry for $lib differs from upstream (review, then: tools/vc.py lock $lib)" >&2
    failed=1
  fi
  if ((failed)); then
    echo "vendor-sync: $lib FAILED" >&2
    return 1
  fi
  echo "vendor-sync: $lib == $repo@${rev:0:12}"
}

update_lib() {
  local lib="$1" rev="$2" repo up local
  { IFS=$'\t' read -r repo _; mapfile -t pairs; } < <(lib_config "$lib")
  local src="$tmp/$lib"
  fetch "$repo" "$rev" "$src"
  rev="$(git -C "$src" rev-parse HEAD)"
  for pair in "${pairs[@]}"; do
    IFS=$'\t' read -r up local <<<"$pair"
    rm -rf "$local"
    mkdir -p "$(dirname "$local")"
    cp -r "$src/$up" "$local"
  done
  python3 -I - "$lib" "$rev" <<'EOF'
import re, sys
lib, rev = sys.argv[1:]
text = open("vendored.toml").read()
pat = re.compile(r'(\[' + re.escape(lib) + r'\][^\[]*?\nrev = ")[0-9a-f]+(")', re.S)
text, n = pat.subn(lambda m: m[1] + rev + m[2], text)
assert n == 1, "could not update rev in vendored.toml"
open("vendored.toml", "w").write(text)
EOF
  echo "vendor-sync: $lib updated to $repo@$rev"
  echo "next: review the diff (git diff), then run: tools/vc.py lock $lib && scripts/vendor-sync.sh check"
}

case "${1:-}" in
  check)
    rc=0
    while read -r lib; do check_lib "$lib" || rc=1; done < <(libs)
    exit "$rc" ;;
  update)
    [[ $# -eq 3 ]] || { echo "usage: $0 update <lib> <rev>" >&2; exit 2; }
    update_lib "$2" "$3" ;;
  *)
    echo "usage: $0 check | update <lib> <rev>" >&2; exit 2 ;;
esac

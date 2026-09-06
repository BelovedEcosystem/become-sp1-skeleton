#!/usr/bin/env bash
# Reproducible SP1 guest ELF via cargo prove build --docker.
# Exit non-zero with a clear message when Docker/rootless/podman is unavailable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROGRAM_DIR="${ROOT}/program"

die() {
  echo "docker-build.sh: ERROR: $*" >&2
  exit 1
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_container() {
  if have_cmd docker; then
    if docker info >/dev/null 2>&1; then
      echo "docker"
      return 0
    fi
    die "docker binary present but daemon unreachable (no sudo / rootless socket?). Install rootless Docker or grant access, then retry."
  fi
  if have_cmd podman; then
    if podman info >/dev/null 2>&1; then
      echo "podman"
      return 0
    fi
    die "podman present but not usable without root."
  fi
  die "Docker/podman not installed (blocked-no-root). This box has no docker.io and the user cannot sudo. Use local: (cd ${PROGRAM_DIR} && cargo prove build). Current vkey from SP1 6.6.0 local ELF: see jobs/skeleton-commit/sp1/vkey.txt"
}

echo "docker-build.sh: probing container runtime…"
RUNTIME="$(detect_container)"
echo "docker-build.sh: using ${RUNTIME}"

cd "${PROGRAM_DIR}"
echo "docker-build.sh: running: cargo prove build --docker"
exec cargo prove build --docker

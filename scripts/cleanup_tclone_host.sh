#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Clean a Gensee tclone host and rebuild the Gensee CLI.

Run this from a host shell, not from inside a Gensee source or fork container.

Usage:
  scripts/cleanup_tclone_host.sh [options]

Options:
  --all-podman-data  Remove every container in the configured Podman store,
                     then prune unused volumes and dangling image layers.
                     Tagged images, including GENSEE_TCLONE_IMAGE, are kept.
  --dry-run          Print the cleanup and rebuild commands without running them.
  --yes              Skip the destructive-action confirmation.
  --install-to PATH  Install the rebuilt binary at PATH. The default is the
                     current gensee on PATH, or $HOME/.cargo/bin/gensee.
  --no-cargo-clean   Keep the existing Cargo target directory before rebuilding.
  -h, --help         Show this help.

Environment:
  GENSEE_HOME           Defaults to $HOME/.gensee.
  GENSEE_TCLONE_PODMAN  Defaults to podman.
  GENSEE_TCLONE_IMAGE   Displayed as the image that cleanup preserves.
EOF
}

die() {
  printf 'cleanup-tclone-host: %s\n' "$*" >&2
  exit 1
}

quote_command() {
  printf '  '
  printf '%q ' "$@"
  printf '\n'
}

dry_run=0
assume_yes=0
all_podman_data=0
cargo_clean=1
install_to=""

while (($#)); do
  case "$1" in
    --all-podman-data)
      all_podman_data=1
      ;;
    --dry-run)
      dry_run=1
      ;;
    --yes)
      assume_yes=1
      ;;
    --install-to)
      (($# >= 2)) || die "--install-to requires a path"
      install_to=$2
      shift
      ;;
    --no-cargo-clean)
      cargo_clean=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1 (run with --help for usage)"
      ;;
  esac
  shift
done

[[ -z ${GENSEE_RUN_ID:-} ]] || die \
  "refusing to clean the host from inside Gensee run $GENSEE_RUN_ID"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
gensee_home=${GENSEE_HOME:-$HOME/.gensee}
podman_command=${GENSEE_TCLONE_PODMAN:-${PODMAN_TFORK:-podman}}
tclone_image=${GENSEE_TCLONE_IMAGE:-gensee-tclone-webtop:tmux}
[[ $gensee_home = /* ]] || die "GENSEE_HOME must be an absolute path"

if [[ -z $install_to ]]; then
  install_to=$(command -v gensee 2>/dev/null || true)
  install_to=${install_to:-$HOME/.cargo/bin/gensee}
fi
[[ $install_to = /* ]] || die "--install-to must be an absolute path"

tmp_root=${TMPDIR:-/tmp}
tmp_root=${tmp_root%/}
gensee_tmp="$tmp_root/gensee-agent-guard"
home_async_tmp="$gensee_home/tmp/tclone-async"

case "$gensee_tmp" in
  /tmp/gensee-agent-guard|/private/tmp/gensee-agent-guard|/var/tmp/gensee-agent-guard) ;;
  *) die "refusing unexpected Gensee temporary path: $gensee_tmp" ;;
esac
case "$home_async_tmp" in
  "$gensee_home"/tmp/tclone-async) ;;
  *) die "refusing unexpected Gensee home temporary path: $home_async_tmp" ;;
esac

host_env=(env "PATH=$PATH" "HOME=$HOME" "GENSEE_HOME=$gensee_home")
[[ -z ${TERM:-} ]] || host_env+=("TERM=$TERM")
[[ -z ${TMUX:-} ]] || host_env+=("TMUX=$TMUX")
[[ -z ${GENSEE_TCLONE_IMAGE:-} ]] || host_env+=("GENSEE_TCLONE_IMAGE=$GENSEE_TCLONE_IMAGE")
[[ -z ${GENSEE_TCLONE_PODMAN:-} ]] || host_env+=("GENSEE_TCLONE_PODMAN=$GENSEE_TCLONE_PODMAN")

if ((EUID == 0)); then
  privileged=()
else
  command -v sudo >/dev/null 2>&1 || die "sudo is required to clean the host Podman store"
  privileged=(sudo)
fi

run() {
  quote_command "$@"
  ((dry_run)) || "$@"
}

run_privileged() {
  run "${privileged[@]}" "${host_env[@]}" "$@"
}

remove_named_tclone_containers() {
  local list_command=("${privileged[@]}" "${host_env[@]}" "$podman_command" ps -a --format '{{.Names}}')
  local names

  if ((dry_run)); then
    quote_command "${list_command[@]}"
    printf '  # remove any remaining container whose name starts with gensee-tclone-\n'
    return
  fi

  quote_command "${list_command[@]}"
  if ! names=$("${list_command[@]}"); then
    printf 'cleanup-tclone-host: warning: could not list Podman containers\n' >&2
    return
  fi

  while IFS= read -r name; do
    [[ $name == gensee-tclone-* ]] || continue
    run_privileged "$podman_command" rm --force "$name"
  done <<<"$names"
}

remove_path() {
  local path=$1
  if ((dry_run)) || [[ -e $path ]]; then
    run "${privileged[@]}" rm -rf -- "$path"
  fi
}

printf 'Gensee tclone host cleanup\n'
printf '  repository:       %s\n' "$repo_root"
printf '  GENSEE_HOME:       %s\n' "$gensee_home"
printf '  Podman command:    %s\n' "$podman_command"
printf '  preserved image:   %s\n' "$tclone_image"
printf '  install target:    %s\n' "$install_to"
printf '  all Podman data:   %s\n' "$([[ $all_podman_data == 1 ]] && printf yes || printf no)"

if command -v df >/dev/null 2>&1; then
  printf '\nDisk usage before cleanup:\n'
  df -h "$tmp_root" "$repo_root" | awk 'NR == 1 || !seen[$1]++'
fi

if ((!assume_yes && !dry_run)); then
  printf '\nThis removes Gensee tclone containers, %s, %s, and Cargo build artifacts.\n' \
    "$gensee_tmp" "$home_async_tmp"
  if ((all_podman_data)); then
    printf 'It also removes every container and unused volume in the configured Podman store.\n'
  fi
  read -r -p 'Continue? [y/N] ' reply
  [[ $reply = y || $reply = Y || $reply = yes || $reply = YES ]] || {
    printf 'Cancelled.\n'
    exit 0
  }
fi

printf '\nRemoving tracked and orphaned Gensee tclone containers:\n'
cleanup_gensee=$(command -v gensee 2>/dev/null || true)
if [[ -z $cleanup_gensee && -x $repo_root/target/release/gensee ]]; then
  cleanup_gensee=$repo_root/target/release/gensee
fi
if [[ -n $cleanup_gensee ]]; then
  if ((dry_run)); then
    run_privileged "$cleanup_gensee" run delete --all
  elif ! run_privileged "$cleanup_gensee" run delete --all; then
    printf 'cleanup-tclone-host: warning: gensee run delete --all failed; continuing with Podman cleanup\n' >&2
  fi
else
  printf '  no existing gensee binary found; skipping run-record cleanup\n'
fi
remove_named_tclone_containers

if ((all_podman_data)); then
  printf '\nRemoving all containers and unused Podman storage:\n'
  run_privileged "$podman_command" rm --all --force
  run_privileged "$podman_command" volume prune --force
  run_privileged "$podman_command" image prune --force
else
  printf '\nThe default cleanup leaves non-Gensee containers and tagged images intact.\n'
fi

printf '\nRemoving Gensee temporary state:\n'
remove_path "$gensee_tmp"
remove_path "$home_async_tmp"

printf '\nRebuilding the Gensee executable:\n'
if ((cargo_clean)); then
  run cargo clean --manifest-path "$repo_root/Cargo.toml"
fi
run cargo build --release -p gensee-crate-cli --manifest-path "$repo_root/Cargo.toml"

release_binary="$repo_root/target/release/gensee"
if ((dry_run)); then
  if [[ $install_to != "$release_binary" ]]; then
    run "${privileged[@]}" install -m 0755 "$release_binary" "$install_to"
  fi
else
  [[ -x $release_binary ]] || die "release build did not create $release_binary"
  if [[ $install_to != "$release_binary" ]]; then
    install_parent=$(dirname -- "$install_to")
    if [[ -d $install_parent && -w $install_parent && (! -e $install_to || -w $install_to) ]]; then
      run install -m 0755 "$release_binary" "$install_to"
    else
      run "${privileged[@]}" install -m 0755 "$release_binary" "$install_to"
    fi
  fi
fi

if command -v df >/dev/null 2>&1; then
  printf '\nDisk usage after cleanup and rebuild:\n'
  df -h "$tmp_root" "$repo_root" | awk 'NR == 1 || !seen[$1]++'
fi

printf '\nCleanup complete. Rebuilt gensee is installed at %s.\n' "$install_to"

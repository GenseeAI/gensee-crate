#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${GENSEE_REPO_URL:-https://github.com/GenseeAI/gensee-crate}"
if [ -n "${GENSEE_INSTALL_REF:-}" ]; then
  INSTALL_REF="$GENSEE_INSTALL_REF"
elif [[ "$REPO_URL" == file://* ]] && command -v git >/dev/null 2>&1; then
  REPO_PATH="${REPO_URL#file://}"
  INSTALL_REF="$(git -C "$REPO_PATH" branch --show-current 2>/dev/null || true)"
  INSTALL_REF="${INSTALL_REF:-main}"
else
  INSTALL_REF="main"
fi
VERSION="0.1.0"

print_banner() {
  local color=""
  local reset=""
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    color=$'\033[38;5;51m'
    reset=$'\033[0m'
  fi
  printf '%b' "$color"
  cat <<'EOF'

  ██████╗ ███████╗███╗   ██╗███████╗███████╗███████╗     ██████╗██████╗  █████╗ ████████╗███████╗
 ██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔════╝██╔════╝    ██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝
 ██║  ███╗█████╗  ██╔██╗ ██║███████╗█████╗  █████╗      ██║     ██████╔╝███████║   ██║   █████╗
 ██║   ██║██╔══╝  ██║╚██╗██║╚════██║██╔══╝  ██╔══╝      ██║     ██╔══██╗██╔══██║   ██║   ██╔══╝
 ╚██████╔╝███████╗██║ ╚████║███████║███████╗███████╗    ╚██████╗██║  ██║██║  ██║   ██║   ███████╗
  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

  long-horizon agent safety runtime

EOF
  printf '%b' "$reset"
  printf '  Version      %s\n' "$VERSION"
  printf '  Get started  gensee watch\n\n'
}

info() {
  printf '==> %s\n' "$1"
}

warn() {
  printf 'warning: %s\n' "$1" >&2
}

choose_gensee_home() {
  local default_home="${GENSEE_HOME:-$HOME/.gensee}"
  local chosen_home="${GENSEE_HOME:-}"

  if [ -z "$chosen_home" ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
    printf 'Choose GENSEE_HOME for local policy, hooks, and timeline data [%s]: ' "$default_home" >/dev/tty
    IFS= read -r chosen_home </dev/tty || chosen_home=""
  fi

  chosen_home="${chosen_home:-$default_home}"
  case "$chosen_home" in
    "~") chosen_home="$HOME" ;;
    "~/"*) chosen_home="$HOME/${chosen_home#"~/"}" ;;
  esac
  export GENSEE_HOME="$chosen_home"
  info "Using GENSEE_HOME=$GENSEE_HOME"
}

configure_claude_code_hooks() {
  local gensee_home="${GENSEE_HOME:-$HOME/.gensee}"
  local should_configure="${GENSEE_CONFIGURE_CLAUDE:-}"

  if [ "$should_configure" = "0" ]; then
    return 0
  fi

  if [ "$should_configure" != "1" ]; then
    if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
      return 0
    fi
    printf 'Configure Claude Code hooks now? This is needed to enforce safety rules and will not affect normal Claude Code usage. It updates ~/.claude/settings.json and writes a backup. [Y/n] ' >/dev/tty
    IFS= read -r should_configure </dev/tty || should_configure=""
  fi

  case "$should_configure" in
    "" | 1 | y | Y | yes | YES)
      info "Configuring Claude Code hooks"
      GENSEE_HOME="$gensee_home" gensee setup claude-code --yes --gensee-home "$gensee_home"
      CLAUDE_HOOKS_CONFIGURED=1
      ;;
    *)
      ;;
  esac
}

configure_codex_hooks() {
  local gensee_home="${GENSEE_HOME:-$HOME/.gensee}"
  local should_configure="${GENSEE_CONFIGURE_CODEX:-}"

  if [ "$should_configure" = "0" ]; then
    return 0
  fi

  if [ "$should_configure" != "1" ]; then
    if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
      return 0
    fi
    printf 'Configure Codex hooks now? This is needed to enforce safety rules and will not affect normal Codex usage. It updates ~/.codex/hooks.json and writes a backup. [Y/n] ' >/dev/tty
    IFS= read -r should_configure </dev/tty || should_configure=""
  fi

  case "$should_configure" in
    "" | 1 | y | Y | yes | YES)
      info "Configuring Codex hooks"
      GENSEE_HOME="$gensee_home" gensee setup codex --yes --gensee-home "$gensee_home"
      CODEX_HOOKS_CONFIGURED=1
      ;;
    *)
      ;;
  esac
}

configure_policy() {
  local gensee_home="${GENSEE_HOME:-$HOME/.gensee}"
  local policy_choice="${GENSEE_POLICY_SETUP:-}"
  local policy_path="$gensee_home/policy.json"

  if [ "$policy_choice" = "default" ] || [ "$policy_choice" = "0" ]; then
    POLICY_SETUP="default"
    return 0
  fi

  if ! GENSEE_HOME="$gensee_home" gensee policy setup --help >/dev/null 2>&1; then
    warn "installed gensee does not support guided policy setup; using the bundled default policy"
    POLICY_SETUP="default"
    return 0
  fi

  if [ -z "$policy_choice" ]; then
    if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
      POLICY_SETUP="default"
      return 0
    fi
    printf 'Policy setup: press Enter to use the bundled default safety policy, or type e to edit policy settings, artifact definitions, and decision rules now at %s. [Default/e] ' "$policy_path" >/dev/tty
    IFS= read -r policy_choice </dev/tty || policy_choice=""
  fi

  case "$policy_choice" in
    e | E | edit | EDIT | editable | EDITABLE | customize | CUSTOMIZE | custom | CUSTOM | init | INIT | 1)
      if [ -f "$policy_path" ]; then
        info "Policy already exists at $policy_path"
      else
        info "Creating editable policy at $policy_path"
      fi
      GENSEE_HOME="$gensee_home" gensee policy setup
      POLICY_SETUP="editable"
      ;;
    *)
      POLICY_SETUP="default"
      ;;
  esac
}

print_banner

if [ "$(uname -s)" != "Darwin" ]; then
  printf 'Gensee Crate v0.1 currently supports macOS only.\n' >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  printf 'curl is required to install Gensee Crate.\n' >&2
  exit 1
fi

if ! xcode-select -p >/dev/null 2>&1; then
  info "Installing Xcode Command Line Tools"
  xcode-select --install || true
  printf 'After the Xcode Command Line Tools installer finishes, rerun this command.\n'
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  info "Installing Rust toolchain"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

if ! command -v cargo >/dev/null 2>&1; then
  printf 'cargo was not found after installing Rust. Open a new terminal or source ~/.cargo/env, then rerun this command.\n' >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    info "Installing jq"
    brew install jq
  else
    warn "jq is not installed. Install Homebrew and run 'brew install jq' before configuring agent hooks."
  fi
fi

info "Installing gensee from ${REPO_URL} (${INSTALL_REF})"
cargo install --git "$REPO_URL" --branch "$INSTALL_REF" --locked gensee-crate-cli --force

info "Installed $(command -v gensee)"
gensee --help >/dev/null

choose_gensee_home

CLAUDE_HOOKS_CONFIGURED=0
CODEX_HOOKS_CONFIGURED=0
configure_claude_code_hooks
configure_codex_hooks
POLICY_SETUP="default"
configure_policy
INSTALL_GENSEE_HOME="$GENSEE_HOME"

cat <<'EOF'

Gensee Crate installed successfully.

Protection levels: hooks check tool intent; watch audits file effects; run adds sandbox + staging.

Start watching a workspace:
EOF
printf '  export GENSEE_HOME="%s"\n' "$INSTALL_GENSEE_HOME"
cat <<'EOF'
  gensee watch --workspace . --duration-seconds 10

Or launch an agent with managed runtime safety:
  gensee run --sandbox mac --profile cautious --workspace-mode staged -- claude
  gensee run --sandbox mac --profile cautious --workspace-mode staged -- codex

Inspect activity and policy any time:
  gensee timeline
  gensee policy path

EOF

if [ "$POLICY_SETUP" = "editable" ]; then
  printf 'Policy setup completed at %s.\n' "${GENSEE_HOME:-$HOME/.gensee}/policy.json"
  printf 'Run the full setup flow again any time with:\n  gensee policy setup\n\n'
else
  cat <<'EOF'
Using the bundled default safety policy. Edit policy settings any time with:
  gensee policy setup

EOF
fi

if [ "$CLAUDE_HOOKS_CONFIGURED" = "1" ]; then
  cat <<'EOF'
Claude Code hooks are configured. Fully restart Claude Code before testing enforcement.
EOF
else
  cat <<'EOF'
Configure Claude Code hooks any time:
  gensee setup claude-code
EOF
fi

if [ "$CODEX_HOOKS_CONFIGURED" = "1" ]; then
  cat <<'EOF'
Codex hooks are configured. Open /hooks in Codex to review and trust the hook command before testing enforcement.
EOF
else
  cat <<'EOF'
Configure Codex hooks any time:
  gensee setup codex
EOF
fi

cat <<'EOF'
For non-interactive installs:
  curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh | GENSEE_CONFIGURE_CLAUDE=1 GENSEE_CONFIGURE_CODEX=1 bash
EOF

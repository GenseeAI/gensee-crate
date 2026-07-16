#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${GENSEE_REPO_URL:-https://github.com/GenseeAI/gensee-crate}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
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

warn_unwritable_gensee_files() {
  local gensee_home="${GENSEE_HOME:-$HOME/.gensee}"
  [ -d "$gensee_home" ] || return 0

  local unwritable
  unwritable="$(find "$gensee_home" -maxdepth 1 -type f ! -w -printf '%f ' 2>/dev/null || true)"
  if [ -n "$unwritable" ]; then
    warn "Some GENSEE_HOME files are not writable by $(id -un): $unwritable"
    warn "This commonly happens after running gensee with sudo and can prevent telemetry recording. Fix ownership before continuing, for example: sudo chown -R $(id -un):$(id -gn) $gensee_home"
  fi
}

configure_claude_code_hooks() {
  local gensee_home="${GENSEE_HOME:-$HOME/.gensee}"
  local should_configure="${GENSEE_CONFIGURE_CLAUDE:-}"
  local settings_path="$HOME/.claude/settings.json"

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
      # A prior `sudo claude` or manual edit can leave this file root-owned.
      # Detect it before `gensee setup` creates a backup then fails to write.
      if [ -e "$settings_path" ] && [ ! -w "$settings_path" ]; then
        warn "Cannot configure Claude Code hooks: $settings_path is not writable by $(id -un)."
        warn "Fix ownership (for example: sudo chown $(id -un):$(id -gn) $settings_path) and rerun GENSEE_CONFIGURE_CLAUDE=1."
        return 0
      fi
      if [ ! -d "$HOME/.claude" ] || [ ! -w "$HOME/.claude" ]; then
        warn "Cannot configure Claude Code hooks: $HOME/.claude is missing or not writable by $(id -un)."
        return 0
      fi
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

configure_antigravity_hooks() {
  local gensee_home="${GENSEE_HOME:-$HOME/.gensee}"
  local should_configure="${GENSEE_CONFIGURE_ANTIGRAVITY:-}"

  if [ "$should_configure" = "0" ]; then
    return 0
  fi

  if [ "$should_configure" != "1" ]; then
    if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
      return 0
    fi
    printf 'Configure Antigravity global hooks now? This is needed to enforce safety rules and will not affect normal Antigravity usage. It updates ~/.gemini/config/hooks.json and writes a backup. [Y/n] ' >/dev/tty
    IFS= read -r should_configure </dev/tty || should_configure=""
  fi

  case "$should_configure" in
    "" | 1 | y | Y | yes | YES)
      info "Configuring Antigravity global hooks"
      GENSEE_HOME="$gensee_home" gensee setup antigravity --yes --gensee-home "$gensee_home"
      ANTIGRAVITY_HOOKS_CONFIGURED=1
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

configure_dashboard() {
  local should_configure="${GENSEE_CONFIGURE_DASHBOARD:-}"
  local dashboard_dir="${GENSEE_DASHBOARD_SOURCE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/gensee/dashboard}"
  local dashboard_source

  if [ "$should_configure" = "0" ]; then
    return 0
  fi

  if [ "$should_configure" != "1" ]; then
    if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
      return 0
    fi
    printf 'Set up the native Gensee dashboard now? This installs Tauri and Node dependencies. [y/N] ' >/dev/tty
    IFS= read -r should_configure </dev/tty || should_configure=""
  fi

  case "$should_configure" in
    1 | y | Y | yes | YES)
      ;;
    *)
      return 0
      ;;
  esac

  if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    warn "Node.js 18+ and npm are required for the native dashboard. Install them, then rerun with GENSEE_CONFIGURE_DASHBOARD=1."
    return 0
  fi

  local node_major
  node_major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  if [ "$node_major" -lt 18 ]; then
    warn "The native dashboard requires Node.js 18+ (found $(node --version))."
    return 0
  fi

  if [ "$OS_NAME" = "Linux" ] && command -v apt-get >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1; then
      info "Installing Linux Tauri WebView prerequisites"
      sudo apt-get update
      sudo apt-get install -y \
        libwebkit2gtk-4.1-dev libgtk-3-dev \
        libayatana-appindicator3-dev librsvg2-dev
    else
      warn "sudo is unavailable. Install Tauri prerequisites manually: libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev"
      return 0
    fi
  elif [ "$OS_NAME" = "Linux" ]; then
    warn "Automatic Tauri prerequisite installation supports apt-get only. Install WebKitGTK, GTK3, AppIndicator, and librsvg development packages for your distribution."
    return 0
  fi

  if ! command -v cargo-tauri >/dev/null 2>&1; then
    info "Installing Tauri CLI"
    cargo install tauri-cli --version "^2" --locked
  fi

  # When invoked from a repository checkout, use that exact checkout. This
  # makes branch/local development setup reliable and avoids cloning `main`
  # when the dashboard implementation exists only on the checked-out branch.
  if [ -f "$LOCAL_REPO_ROOT/dashboards/package.json" ]; then
    dashboard_source="$LOCAL_REPO_ROOT"
    info "Using dashboard source from local checkout at $dashboard_source"
  else
    dashboard_source="$dashboard_dir"
    info "Preparing dashboard source at $dashboard_source"
    if [ -d "$dashboard_source/.git" ]; then
      git -C "$dashboard_source" fetch --depth 1 origin "$INSTALL_REF"
      git -C "$dashboard_source" checkout --force FETCH_HEAD
    else
      mkdir -p "$(dirname "$dashboard_source")"
      git clone --depth 1 "$REPO_URL" "$dashboard_source"
      git -C "$dashboard_source" checkout --force "$INSTALL_REF"
    fi
  fi

  if [ ! -f "$dashboard_source/dashboards/package.json" ]; then
    warn "The selected source ref ($INSTALL_REF) does not contain the native dashboards/ application. Use a release/ref that includes it, or set GENSEE_REPO_URL and GENSEE_INSTALL_REF explicitly."
    return 0
  fi

  info "Installing dashboard frontend dependencies"
  npm --prefix "$dashboard_source/dashboards" install --legacy-peer-deps
  info "Validating dashboard frontend build"
  npm --prefix "$dashboard_source/dashboards" run build

  DASHBOARD_CONFIGURED=1
  DASHBOARD_DIR="$dashboard_source/dashboards"
}

print_banner

OS_NAME="$(uname -s)"

if ! command -v curl >/dev/null 2>&1; then
  printf 'curl is required to install Gensee Crate.\n' >&2
  exit 1
fi

if [ "$OS_NAME" = "Darwin" ]; then
  if ! xcode-select -p >/dev/null 2>&1; then
    info "Installing Xcode Command Line Tools"
    xcode-select --install || true
    printf 'After the Xcode Command Line Tools installer finishes, rerun this command.\n'
    exit 1
  fi
elif [ "$OS_NAME" = "Linux" ]; then
  warn "Linux support is experimental. The installer will install the CLI, but privileged fanotify/nftables controls may need additional host setup."
  if command -v apt-get >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1; then
      info "Installing Linux build and runtime prerequisites"
      sudo apt-get update
      sudo apt-get install -y build-essential pkg-config libssl-dev jq nftables git
    else
      warn "sudo is not available. Install prerequisites manually: apt-get install build-essential pkg-config libssl-dev jq nftables git"
    fi
  else
    warn "Automatic Linux prerequisite install currently supports apt-get only. Install Rust build tools, pkg-config, OpenSSL headers, jq, nftables, and git with your distro package manager."
  fi
else
  printf 'Gensee Crate currently supports macOS and experimental Linux hosts.\n' >&2
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
  if [ "$OS_NAME" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    info "Installing jq"
    brew install jq
  else
    warn "jq is not installed. Install jq before configuring agent hooks."
  fi
fi

info "Installing gensee from ${REPO_URL} (${INSTALL_REF})"
cargo install --git "$REPO_URL" --branch "$INSTALL_REF" --locked gensee-crate-cli --force

info "Installed $(command -v gensee)"
gensee --help >/dev/null

choose_gensee_home
warn_unwritable_gensee_files

CLAUDE_HOOKS_CONFIGURED=0
CODEX_HOOKS_CONFIGURED=0
ANTIGRAVITY_HOOKS_CONFIGURED=0
DASHBOARD_CONFIGURED=0
DASHBOARD_DIR=""
configure_claude_code_hooks
configure_codex_hooks
configure_antigravity_hooks
POLICY_SETUP="default"
configure_policy
configure_dashboard
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
EOF
  printf '  GENSEE_HOME="%s" gensee setup claude-code --gensee-home "%s"\n' "$INSTALL_GENSEE_HOME" "$INSTALL_GENSEE_HOME"
fi

if [ "$CODEX_HOOKS_CONFIGURED" = "1" ]; then
  cat <<'EOF'
Codex hooks are configured. Open /hooks in Codex to review and trust the hook command before testing enforcement.
EOF
else
  cat <<'EOF'
Configure Codex hooks any time:
EOF
  printf '  GENSEE_HOME="%s" gensee setup codex --gensee-home "%s"\n' "$INSTALL_GENSEE_HOME" "$INSTALL_GENSEE_HOME"
fi

if [ "$ANTIGRAVITY_HOOKS_CONFIGURED" = "1" ]; then
  cat <<'EOF'
Antigravity hooks are configured globally. Fully restart Antigravity before testing enforcement.
EOF
else
  cat <<'EOF'
Configure Antigravity global hooks any time:
EOF
  printf '  GENSEE_HOME="%s" gensee setup antigravity --gensee-home "%s"\n' "$INSTALL_GENSEE_HOME" "$INSTALL_GENSEE_HOME"
fi

if [ "$DASHBOARD_CONFIGURED" = "1" ]; then
  cat <<EOF

Native dashboard dependencies are installed. Launch it with:
  cd "$DASHBOARD_DIR"
  GENSEE_HOME="$INSTALL_GENSEE_HOME" cargo tauri dev
EOF
else
  cat <<'EOF'

Set up the native dashboard later with:
  GENSEE_CONFIGURE_DASHBOARD=1 scripts/install_oss.sh
EOF
fi

cat <<'EOF'
For non-interactive installs:
  curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh | GENSEE_CONFIGURE_CLAUDE=1 GENSEE_CONFIGURE_CODEX=1 GENSEE_CONFIGURE_ANTIGRAVITY=1 GENSEE_CONFIGURE_DASHBOARD=1 bash
EOF

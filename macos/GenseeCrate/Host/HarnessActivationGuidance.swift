import Darwin
import Foundation

struct HarnessActivationInstruction: Equatable {
    let title: String
    let detail: String
    let actionTitle: String?
}

enum HarnessActivationGuidance {
    static func instruction(for provider: String) -> HarnessActivationInstruction {
        switch provider {
        case "codex":
            HarnessActivationInstruction(
                title: "Review the hook, then start a new task",
                detail: "Codex requires you to trust non-managed hooks before they run. Open the Codex CLI, enter /hooks, and trust the Gensee commands. The ChatGPT app does not expose /hooks, so Gensee opens its bundled Codex CLI for this one-time review and closes the review window after approval.",
                actionTitle: "Open Codex Hook Review"
            )
        case "claude-code":
            HarnessActivationInstruction(
                title: "Restart Claude Code, then send a prompt",
                detail: "Fully quit Claude Code and reopen it so the updated hooks load. Start a new task; Gensee will verify the first event automatically.",
                actionTitle: nil
            )
        case "antigravity":
            HarnessActivationInstruction(
                title: "Restart Antigravity, then send a prompt",
                detail: "Fully quit Antigravity and reopen it so the global hooks load. Start a new task to verify protection.",
                actionTitle: nil
            )
        case "cursor":
            HarnessActivationInstruction(
                title: "Restart Cursor, then start an agent turn",
                detail: "Fully quit Cursor and reopen it. Gensee will verify protection when Cursor emits its first hook event.",
                actionTitle: nil
            )
        case "vscode":
            HarnessActivationInstruction(
                title: "Start a new Copilot agent turn",
                detail: "VS Code reloads its hook file automatically. Start a new GitHub Copilot agent turn to verify protection.",
                actionTitle: nil
            )
        case "omnigent":
            HarnessActivationInstruction(
                title: "Use a Gensee-managed launch",
                detail: "Omnigent does not yet expose a first-class hook bridge. Launch it with gensee run so Gensee can monitor its process tree and apply policy.",
                actionTitle: "Copy Managed Launch"
            )
        default:
            HarnessActivationInstruction(
                title: "Start a new agent turn",
                detail: "Gensee will verify protection after receiving the first event from this harness.",
                actionTitle: nil
            )
        }
    }

    static func eventMatches(provider: String, source: String) -> Bool {
        let normalizedProvider = provider.lowercased()
        let normalizedSource = source.lowercased()
        if normalizedProvider == normalizedSource { return true }
        if normalizedProvider == "claude-code" {
            return normalizedSource == "claude" || normalizedSource == "claude_code"
        }
        if normalizedProvider == "vscode" {
            return normalizedSource == "github-copilot" || normalizedSource == "copilot"
        }
        return false
    }

    static func configurationTimestampMS(path: String, now: Date = Date()) -> Int64 {
        let attributes = try? FileManager.default.attributesOfItem(atPath: path)
        let modified = attributes?[.modificationDate] as? Date
        return Int64((modified ?? now).timeIntervalSince1970 * 1_000)
    }
}

enum CodexExecutableResolver {
    static func orderedCandidates(home: URL, applicationURLs: [URL]) -> [URL] {
        let applicationCandidates = applicationURLs.flatMap { application in
            [
                application.appendingPathComponent("Contents/Resources/codex"),
                application.appendingPathComponent("Contents/MacOS/codex"),
            ]
        }
        let installedApplications = [
            URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex"),
            URL(fileURLWithPath: "/Applications/Codex.app/Contents/Resources/codex"),
            home.appendingPathComponent("Applications/ChatGPT.app/Contents/Resources/codex"),
            home.appendingPathComponent("Applications/Codex.app/Contents/Resources/codex"),
        ]
        let commandLineInstalls = [
            home.appendingPathComponent(".local/bin/codex"),
            URL(fileURLWithPath: "/opt/homebrew/bin/codex"),
            URL(fileURLWithPath: "/usr/local/bin/codex"),
            home.appendingPathComponent(".cargo/bin/codex"),
        ]

        var seen = Set<String>()
        return (applicationCandidates + installedApplications + commandLineInstalls).filter { url in
            seen.insert(url.standardizedFileURL.path).inserted
        }
    }

    static func firstRunnable(
        candidates: [URL],
        isRunnable: (URL) -> Bool
    ) -> URL? {
        candidates.first(where: isRunnable)
    }

    static func respondsToVersionProbe(
        _ executable: URL,
        timeout: TimeInterval = 1.0
    ) -> Bool {
        let process = Process()
        let completed = DispatchSemaphore(value: 0)
        process.executableURL = executable
        process.arguments = ["--version"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { _ in completed.signal() }
        do {
            try process.run()
        } catch {
            return false
        }

        if completed.wait(timeout: .now() + max(0.05, timeout)) == .timedOut {
            process.terminate()
            if completed.wait(timeout: .now() + 0.2) == .timedOut {
                Darwin.kill(process.processIdentifier, SIGKILL)
                _ = completed.wait(timeout: .now() + 0.5)
            }
            return false
        }
        return process.terminationReason == .exit && process.terminationStatus == 0
    }
}

enum CodexHookReviewScript {
    static func render(codexURL: URL) -> String {
        let quotedCodex = shellSingleQuote(codexURL.path)
        return """
        #!/bin/zsh
        clear
        echo 'Gensee configured Codex hooks.'
        echo 'Open /hooks and trust all Gensee hook commands.'
        echo 'This review window will close automatically after approval.'
        echo

        codex_home="${CODEX_HOME:-$HOME/.codex}"
        config_path="$codex_home/config.toml"
        hooks_path="$codex_home/hooks.json"
        review_tty=$(/usr/bin/tty)
        approval_marker=$(/usr/bin/mktemp -t gensee-codex-hook-review)
        initial_checksum=$(/usr/bin/cksum "$config_path" 2>/dev/null || true)

        cleanup_review() {
          /bin/rm -f "$approval_marker"
        }
        trap cleanup_review EXIT HUP INT TERM

        close_review_window() {
          local close_result
          close_result=$(/usr/bin/osascript - "$review_tty" <<'APPLESCRIPT'
        on run argv
          set targetTTY to item 1 of argv
          tell application "Terminal"
            repeat with terminalWindow in windows
              repeat with terminalTab in tabs of terminalWindow
                if tty of terminalTab is targetTTY then
                  close terminalWindow
                  return "closed"
                end if
              end repeat
            end repeat
          end tell
          return "not-found"
        end run
        APPLESCRIPT
          )
          if [[ "$close_result" != "closed" ]]; then
            echo 'Hook approval is complete. You can close this terminal window.'
          fi
        }

        hooks_are_trusted() {
          local expected trusted
          expected=$(/usr/bin/grep -c 'gensee hook codex' "$hooks_path" 2>/dev/null || true)
          [[ "$expected" -gt 0 ]] || return 1
          trusted=$(/usr/bin/awk -v hook_path="$hooks_path" '
            /^\\[hooks\\.state\\."/ {
              in_gensee_section = index($0, hook_path ":") > 0
              next
            }
            in_gensee_section && /^[[:space:]]*trusted_hash[[:space:]]*=/ {
              count++
              in_gensee_section = 0
            }
            END { print count + 0 }
          ' "$config_path" 2>/dev/null)
          [[ "$trusted" -ge "$expected" ]]
        }

        if [[ "$config_path" -nt "$hooks_path" ]] && hooks_are_trusted; then
          echo 'Gensee hooks are already approved. Closing this review window…'
          /bin/sleep 0.4
          close_review_window
          exit 0
        fi

        setopt MONITOR
        \(quotedCodex) &
        codex_pid=$!
        (
          trap - EXIT HUP INT TERM
          while /bin/kill -0 "$codex_pid" 2>/dev/null; do
            current_checksum=$(/usr/bin/cksum "$config_path" 2>/dev/null || true)
            if [[ "$current_checksum" != "$initial_checksum" ]] && hooks_are_trusted; then
              /usr/bin/printf 'approved\\n' > "$approval_marker"
              /bin/kill -TERM "$codex_pid" 2>/dev/null || true
              exit 0
            fi
            /bin/sleep 0.25
          done
        ) &
        watcher_pid=$!

        fg %1 >/dev/null 2>&1 || true
        if [[ -s "$approval_marker" ]]; then
          wait "$watcher_pid" 2>/dev/null || true
          echo
          echo 'Gensee hooks approved. Closing this review window…'
          /bin/sleep 0.4
          close_review_window
        else
          /bin/kill -TERM "$watcher_pid" 2>/dev/null || true
        fi
        """
    }

    static func shellCommand(codexURL: URL) -> String {
        let payload = Data(render(codexURL: codexURL).utf8).base64EncodedString()
        return "/usr/bin/printf '%s' \(shellSingleQuote(payload)) | /usr/bin/base64 -D | /bin/zsh"
    }

    private static func shellSingleQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

enum CodexHookReviewLauncher {
    static func appleScriptSource(shellCommand: String) -> String {
        let escaped = shellCommand
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return """
        tell application "Terminal"
          activate
          do script "\(escaped)"
        end tell
        """
    }
}

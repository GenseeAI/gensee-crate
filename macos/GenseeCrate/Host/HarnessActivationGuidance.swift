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
                detail: "Codex requires you to trust non-managed hooks before they run. Open the Codex CLI, enter /hooks, and trust the Gensee command. The ChatGPT app does not expose /hooks, so Gensee can open its bundled Codex CLI for this one-time review.",
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
}

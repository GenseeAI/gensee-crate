import Foundation

struct HarnessConfigurationInspection: Equatable {
    let configured: Bool
    let issue: String?
    let note: String?
    let canRepair: Bool
    let backendPath: String?

    var isHealthy: Bool { configured && issue == nil }
    var requiresRepair: Bool { configured && issue != nil && canRepair }

    init(
        configured: Bool,
        issue: String?,
        note: String? = nil,
        canRepair: Bool = true,
        backendPath: String? = nil
    ) {
        self.configured = configured
        self.issue = issue
        self.note = note
        self.canRepair = canRepair
        self.backendPath = backendPath
    }
}

enum HarnessConfigurationHealth {
    static func expectedCommand(provider: String, homeURL: URL, backendURL: URL) -> String {
        "GENSEE_HOME=\(shellQuote(homeURL.path)) \(shellQuote(backendURL.path)) hook \(provider)"
    }

    static func inspect(
        provider: String,
        contents: String,
        expectedCommand: String?,
        eventStorePath: String
    ) -> HarnessConfigurationInspection {
        guard !contents.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return HarnessConfigurationInspection(configured: false, issue: nil)
        }

        guard let data = contents.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            let appearsConfigured = contents.localizedCaseInsensitiveContains("hook \(provider)")
                && contents.localizedCaseInsensitiveContains("gensee")
            return HarnessConfigurationInspection(
                configured: appearsConfigured,
                issue: appearsConfigured
                    ? "The harness configuration is invalid JSON. Fix its syntax before Gensee can manage these hooks."
                    : nil,
                canRepair: false
            )
        }

        let allOwnedCommands = commands(in: root)
            .filter { isGenseeCommand($0, provider: provider) }
        guard !allOwnedCommands.isEmpty else {
            return HarnessConfigurationInspection(configured: false, issue: nil)
        }

        var issues: [String] = []
        if provider == "claude-code", root["disableAllHooks"] as? Bool == true {
            issues.append("Claude Code has all hooks disabled. Repair will enable them while preserving its other settings.")
        }

        let containerKey: String
        if provider == "antigravity" {
            containerKey = "gensee-policy"
        } else {
            containerKey = "hooks"
        }
        guard root[containerKey] == nil || root[containerKey] is [String: Any] else {
            return HarnessConfigurationInspection(
                configured: true,
                issue: "The \(containerKey) setting has an unsupported shape. Fix it manually before Gensee can repair these hooks.",
                canRepair: false
            )
        }
        let eventContainer = root[containerKey] as? [String: Any]

        let missingEvents = expectedEvents(for: provider).filter { eventName in
            guard let event = eventContainer?[eventName] else { return true }
            return !commands(in: event).contains { isGenseeCommand($0, provider: provider) }
        }
        if !missingEvents.isEmpty {
            issues.append("Gensee hooks are incomplete (missing \(missingEvents.joined(separator: ", "))). Repair will restore full coverage.")
        }

        guard let expectedCommand,
              let expected = parsedHookCommand(expectedCommand),
              !expected.home.isEmpty
        else {
            issues.append("The Gensee backend is unavailable. Rebuild or reinstall the app before repairing this harness.")
            return HarnessConfigurationInspection(
                configured: true,
                issue: issues.joined(separator: " "),
                canRepair: false
            )
        }

        let eventCommands = expectedEvents(for: provider).flatMap { eventName in
            guard let event = eventContainer?[eventName] else { return [String]() }
            return commands(in: event).filter { isGenseeCommand($0, provider: provider) }
        }
        let parsedCommands = eventCommands.compactMap(parsedHookCommand)
        guard parsedCommands.count == eventCommands.count,
              parsedCommands.allSatisfy({ !$0.home.isEmpty && !$0.backend.isEmpty })
        else {
            return HarnessConfigurationInspection(
                configured: true,
                issue: "Gensee found a custom or malformed hook command that it cannot safely rewrite. Update that command manually or remove it before enabling protection again.",
                canRepair: false
            )
        }

        if parsedCommands.contains(where: { normalizedPath($0.home) != normalizedPath(expected.home) }) {
            issues.append("Hooks point to a different event store. Repair will route events to \(eventStorePath).")
        }

        let configuredBackendPaths = Set(parsedCommands.map(\.backend))
        let backendPaths = Set(parsedCommands.map { normalizedPath($0.backend) })
        let missingBackend = configuredBackendPaths.first { !FileManager.default.isExecutableFile(atPath: $0) }
        if let missingBackend {
            issues.append("The configured Gensee backend is unavailable at \(missingBackend). Repair will install a stable backend command.")
        }
        let alternateBackends = backendPaths.filter { $0 != normalizedPath(expected.backend) }
        let note = issues.isEmpty && !alternateBackends.isEmpty
            ? "Hooks use another valid Gensee installation at \(alternateBackends.sorted().joined(separator: ", "))."
            : nil

        return HarnessConfigurationInspection(
            configured: true,
            issue: issues.isEmpty ? nil : issues.joined(separator: " "),
            note: note,
            // Preserve the hook's stable spelling (for example
            // /opt/homebrew/bin/gensee). Symlink resolution is comparison-only;
            // repairing to a versioned Cellar target would break on upgrade.
            backendPath: backendPaths.count == 1 ? configuredBackendPaths.sorted().first : nil
        )
    }

    static func expectedEvents(for provider: String) -> [String] {
        switch provider {
        case "codex":
            return ["UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop"]
        case "claude-code", "vscode":
            return ["UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"]
        case "antigravity":
            return ["PreToolUse", "PostToolUse", "PreInvocation"]
        case "cursor":
            return ["preToolUse", "postToolUse", "beforeShellExecution", "beforeSubmitPrompt", "stop"]
        default:
            return []
        }
    }

    private static func commands(in value: Any) -> [String] {
        if let dictionary = value as? [String: Any] {
            var result: [String] = []
            if let command = dictionary["command"] as? String {
                result.append(command)
            }
            for (key, child) in dictionary where key != "command" {
                result += commands(in: child)
            }
            return result
        }
        if let array = value as? [Any] {
            return array.flatMap(commands(in:))
        }
        return []
    }

    private static func isGenseeCommand(_ command: String, provider: String) -> Bool {
        let suffix = " hook \(provider)"
        return command.contains("GENSEE_HOME=")
            && command.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix(suffix)
    }

    private static func parsedHookCommand(_ command: String) -> (home: String, backend: String, provider: String)? {
        let words = shellWords(command)
        guard words.count == 4,
              words[0].hasPrefix("GENSEE_HOME="),
              words[2] == "hook"
        else { return nil }

        return (
            home: String(words[0].dropFirst("GENSEE_HOME=".count)),
            backend: words[1],
            provider: words[3]
        )
    }

    /// Parses the small, shell-quoted command shape emitted by the Rust setup command.
    /// This deliberately does not execute or expand shell syntax.
    private static func shellWords(_ command: String) -> [String] {
        var result: [String] = []
        var word = ""
        var wordStarted = false
        var inSingleQuote = false
        var escaping = false

        for character in command {
            if escaping {
                word.append(character)
                wordStarted = true
                escaping = false
            } else if character == "\\" && !inSingleQuote {
                escaping = true
                wordStarted = true
            } else if character == "'" {
                inSingleQuote.toggle()
                wordStarted = true
            } else if character.isWhitespace && !inSingleQuote {
                if wordStarted {
                    result.append(word)
                    word = ""
                    wordStarted = false
                }
            } else {
                word.append(character)
                wordStarted = true
            }
        }

        guard !inSingleQuote, !escaping else { return [] }
        if wordStarted { result.append(word) }
        return result
    }

    private static func standardizedPath(_ path: String) -> String {
        var normalized = URL(fileURLWithPath: path).standardizedFileURL.path
        // macOS exposes these directories through root-level symlinks. A child
        // process may report either spelling for the same executable or store.
        for (alias, canonical) in [
            ("/tmp", "/private/tmp"),
            ("/var", "/private/var"),
            ("/etc", "/private/etc"),
        ] {
            if normalized == alias {
                normalized = canonical
                break
            }
            if normalized.hasPrefix(alias + "/") {
                normalized = canonical + normalized.dropFirst(alias.count)
                break
            }
        }
        return normalized
    }

    private static func normalizedPath(_ path: String) -> String {
        URL(fileURLWithPath: standardizedPath(path))
            .resolvingSymlinksInPath()
            .standardizedFileURL.path
    }

    private static func shellQuote(_ value: String) -> String {
        let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+=")
        if !value.isEmpty, value.unicodeScalars.allSatisfy({ safe.contains($0) }) {
            return value
        }
        return "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

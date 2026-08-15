import Foundation

struct HarnessConfigurationInspection: Equatable {
    let configured: Bool
    let issue: String?

    var isHealthy: Bool { configured && issue == nil }
    var requiresRepair: Bool { configured && issue != nil }
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
                    ? "The harness configuration is invalid JSON. Fix its syntax, then run Repair again."
                    : nil
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

        let eventContainer: [String: Any]?
        if provider == "antigravity" {
            eventContainer = root["gensee-policy"] as? [String: Any]
        } else {
            eventContainer = root["hooks"] as? [String: Any]
        }

        let missingEvents = expectedEvents(for: provider).filter { eventName in
            guard let event = eventContainer?[eventName] else { return true }
            return !commands(in: event).contains { isGenseeCommand($0, provider: provider) }
        }
        if !missingEvents.isEmpty {
            issues.append("Gensee hooks are incomplete (missing \(missingEvents.joined(separator: ", "))). Repair will restore full coverage.")
        }

        if let expectedCommand {
            let eventCommands = expectedEvents(for: provider).flatMap { eventName in
                guard let event = eventContainer?[eventName] else { return [String]() }
                return commands(in: event).filter { isGenseeCommand($0, provider: provider) }
            }
            if eventCommands.contains(where: {
                !hookCommandsAreEquivalent($0, expectedCommand, provider: provider)
            }) {
                issues.append("Hooks point to a different event store or Gensee backend. Repair will route events to \(eventStorePath).")
            }
        } else {
            issues.append("The Gensee backend is unavailable. Rebuild or reinstall the app before repairing this harness.")
        }

        return HarnessConfigurationInspection(
            configured: true,
            issue: issues.isEmpty ? nil : issues.joined(separator: " ")
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
        let suffix = "hook \(provider)"
        return command.contains("GENSEE_HOME=")
            && command.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix(suffix)
    }

    private static func hookCommandsAreEquivalent(
        _ command: String,
        _ expectedCommand: String,
        provider: String
    ) -> Bool {
        guard let actual = parsedHookCommand(command),
              let expected = parsedHookCommand(expectedCommand),
              actual.provider == provider,
              expected.provider == provider
        else { return false }

        return normalizedPath(actual.home) == normalizedPath(expected.home)
            && normalizedPath(actual.backend) == normalizedPath(expected.backend)
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

    private static func normalizedPath(_ path: String) -> String {
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
        return URL(fileURLWithPath: normalized).resolvingSymlinksInPath().standardizedFileURL.path
    }

    private static func shellQuote(_ value: String) -> String {
        let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+=")
        if !value.isEmpty, value.unicodeScalars.allSatisfy({ safe.contains($0) }) {
            return value
        }
        return "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

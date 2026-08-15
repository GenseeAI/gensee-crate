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
            if eventCommands.contains(where: { $0 != expectedCommand }) {
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

    private static func shellQuote(_ value: String) -> String {
        let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+=")
        if !value.isEmpty, value.unicodeScalars.allSatisfy({ safe.contains($0) }) {
            return value
        }
        return "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

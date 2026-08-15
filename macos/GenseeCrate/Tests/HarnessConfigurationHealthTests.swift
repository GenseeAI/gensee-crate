import Foundation
import XCTest

final class HarnessConfigurationHealthTests: XCTestCase {
    private let homeURL = URL(fileURLWithPath: "/Users/test/.gensee")
    private let backendURL = URL(fileURLWithPath: "/Applications/Gensee Crate.app/Contents/Resources/bin/gensee")

    func testHealthyClaudeConfigurationRequiresEveryCurrentHook() throws {
        let command = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code",
            homeURL: homeURL,
            backendURL: backendURL
        )
        let contents = try nestedConfiguration(
            events: HarnessConfigurationHealth.expectedEvents(for: "claude-code"),
            command: command
        )

        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code",
            contents: contents,
            expectedCommand: command,
            eventStorePath: homeURL.path
        )

        XCTAssertTrue(inspection.configured)
        XCTAssertTrue(inspection.isHealthy)
        XCTAssertNil(inspection.issue)
    }

    func testStaleEventStoreOrBackendNeedsRepair() throws {
        let currentCommand = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code",
            homeURL: homeURL,
            backendURL: backendURL
        )
        let staleCommand = "GENSEE_HOME=/private/tmp/old-store /Users/test/.cargo/bin/gensee hook claude-code"
        let contents = try nestedConfiguration(
            events: HarnessConfigurationHealth.expectedEvents(for: "claude-code"),
            command: staleCommand
        )

        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code",
            contents: contents,
            expectedCommand: currentCommand,
            eventStorePath: homeURL.path
        )

        XCTAssertTrue(inspection.requiresRepair)
        XCTAssertTrue(inspection.issue?.contains("different event store or Gensee backend") == true)
        XCTAssertTrue(inspection.issue?.contains(homeURL.path) == true)
    }

    func testMissingHookEventNeedsRepair() throws {
        let command = HarnessConfigurationHealth.expectedCommand(
            provider: "codex",
            homeURL: homeURL,
            backendURL: backendURL
        )
        let contents = try nestedConfiguration(
            events: ["UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"],
            command: command
        )

        let inspection = HarnessConfigurationHealth.inspect(
            provider: "codex",
            contents: contents,
            expectedCommand: command,
            eventStorePath: homeURL.path
        )

        XCTAssertTrue(inspection.requiresRepair)
        XCTAssertTrue(inspection.issue?.contains("PermissionRequest") == true)
        XCTAssertFalse(inspection.issue?.contains("different event store") == true)
    }

    func testClaudeGlobalHookDisableNeedsRepair() throws {
        let command = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code",
            homeURL: homeURL,
            backendURL: backendURL
        )
        let contents = try nestedConfiguration(
            events: HarnessConfigurationHealth.expectedEvents(for: "claude-code"),
            command: command,
            additions: ["disableAllHooks": true]
        )

        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code",
            contents: contents,
            expectedCommand: command,
            eventStorePath: homeURL.path
        )

        XCTAssertTrue(inspection.requiresRepair)
        XCTAssertTrue(inspection.issue?.contains("all hooks disabled") == true)
    }

    func testNoGenseeHooksIsReadyToEnable() throws {
        let contents = try nestedConfiguration(events: ["PreToolUse"], command: "./unrelated-hook.sh")
        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code",
            contents: contents,
            expectedCommand: "unused",
            eventStorePath: homeURL.path
        )

        XCTAssertFalse(inspection.configured)
        XCTAssertNil(inspection.issue)
    }

    func testExpectedCommandQuotesAppPathLikeRustBackend() {
        let command = HarnessConfigurationHealth.expectedCommand(
            provider: "vscode",
            homeURL: homeURL,
            backendURL: backendURL
        )

        XCTAssertEqual(
            command,
            "GENSEE_HOME=/Users/test/.gensee '/Applications/Gensee Crate.app/Contents/Resources/bin/gensee' hook vscode"
        )
    }

    func testHealthyConfigurationLayoutsForEveryDirectHookProvider() throws {
        for provider in ["codex", "claude-code", "antigravity", "cursor", "vscode"] {
            let command = HarnessConfigurationHealth.expectedCommand(
                provider: provider,
                homeURL: homeURL,
                backendURL: backendURL
            )
            let contents = try configuration(provider: provider, command: command)
            let inspection = HarnessConfigurationHealth.inspect(
                provider: provider,
                contents: contents,
                expectedCommand: command,
                eventStorePath: homeURL.path
            )

            XCTAssertTrue(inspection.isHealthy, "Expected healthy \(provider) configuration: \(inspection.issue ?? "no issue")")
        }
    }

    private func nestedConfiguration(
        events: [String],
        command: String,
        additions: [String: Any] = [:]
    ) throws -> String {
        var root = additions
        root["hooks"] = Dictionary(uniqueKeysWithValues: events.map { event in
            (
                event,
                [[
                    "matcher": "*",
                    "hooks": [["type": "command", "command": command]],
                ]]
            )
        })
        let data = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private func configuration(provider: String, command: String) throws -> String {
        let events = HarnessConfigurationHealth.expectedEvents(for: provider)
        if provider == "codex" || provider == "claude-code" {
            return try nestedConfiguration(events: events, command: command)
        }

        var entries: [String: Any] = [:]
        for event in events {
            if provider == "antigravity", event != "PreInvocation" {
                entries[event] = [[
                    "matcher": "*",
                    "hooks": [["type": "command", "command": command]],
                ]]
            } else {
                entries[event] = [["type": "command", "command": command]]
            }
        }
        let root: [String: Any] = provider == "antigravity"
            ? ["gensee-policy": entries]
            : ["hooks": entries]
        let data = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }
}

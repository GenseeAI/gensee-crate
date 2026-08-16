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
        XCTAssertTrue(inspection.issue?.contains("different event store") == true)
        XCTAssertTrue(inspection.issue?.contains(homeURL.path) == true)
    }

    func testTmpAndPrivateTmpCommandsAreEquivalent() throws {
        let name = "gensee-health-alias-\(UUID().uuidString)"
        let privateTmpHome = URL(fileURLWithPath: "/private/tmp/\(name)/home")
        let privateTmpBackend = URL(fileURLWithPath: "/private/tmp/\(name)/bin/gensee")
        try FileManager.default.createDirectory(
            at: privateTmpBackend.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: URL(fileURLWithPath: "/private/tmp/\(name)")) }
        try Data("#!/bin/sh\n".utf8).write(to: privateTmpBackend)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: privateTmpBackend.path)
        let expectedCommand = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code",
            homeURL: privateTmpHome,
            backendURL: privateTmpBackend
        )
        let installedCommand = "GENSEE_HOME=/tmp/\(name)/home /tmp/\(name)/bin/gensee hook claude-code"
        let contents = try nestedConfiguration(
            events: HarnessConfigurationHealth.expectedEvents(for: "claude-code"),
            command: installedCommand
        )

        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code",
            contents: contents,
            expectedCommand: expectedCommand,
            eventStorePath: privateTmpHome.path
        )

        XCTAssertTrue(inspection.isHealthy, inspection.issue ?? "Expected equivalent commands")
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

    func testAlternateExecutableBackendIsHealthy() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("gensee-harness-health-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let alternateBackend = directory.appendingPathComponent("gensee")
        try Data("#!/bin/sh\n".utf8).write(to: alternateBackend)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: alternateBackend.path)

        let expected = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code", homeURL: homeURL, backendURL: backendURL
        )
        let alternate = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code", homeURL: homeURL, backendURL: alternateBackend
        )
        let contents = try nestedConfiguration(
            events: HarnessConfigurationHealth.expectedEvents(for: "claude-code"),
            command: alternate
        )
        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code",
            contents: contents,
            expectedCommand: expected,
            eventStorePath: homeURL.path
        )

        XCTAssertTrue(inspection.isHealthy, inspection.issue ?? "Expected healthy alternate backend")
        XCTAssertEqual(inspection.backendPath, alternateBackend.path)
        XCTAssertTrue(inspection.note?.contains(alternateBackend.path) == true)
    }

    func testAlternateBackendPreservesUnresolvedSymlinkForRepair() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("gensee-harness-symlink-\(UUID().uuidString)")
        let cellar = directory.appendingPathComponent("Cellar/gensee/0.2.1/bin", isDirectory: true)
        let stableBin = directory.appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: cellar, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: stableBin, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let versionedBackend = cellar.appendingPathComponent("gensee")
        let stableBackend = stableBin.appendingPathComponent("gensee")
        try Data("#!/bin/sh\n".utf8).write(to: versionedBackend)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: versionedBackend.path)
        try FileManager.default.createSymbolicLink(at: stableBackend, withDestinationURL: versionedBackend)

        let expected = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code", homeURL: homeURL, backendURL: backendURL
        )
        let alternate = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code", homeURL: homeURL, backendURL: stableBackend
        )
        let contents = try nestedConfiguration(
            events: HarnessConfigurationHealth.expectedEvents(for: "claude-code"),
            command: alternate
        )
        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code",
            contents: contents,
            expectedCommand: expected,
            eventStorePath: homeURL.path
        )

        XCTAssertTrue(inspection.isHealthy, inspection.issue ?? "Expected healthy symlink backend")
        XCTAssertEqual(inspection.backendPath, stableBackend.path)
        XCTAssertNotEqual(inspection.backendPath, versionedBackend.path)
    }

    func testMalformedHooksContainerRequiresManualFix() throws {
        let command = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code", homeURL: homeURL, backendURL: backendURL
        )
        let data = try JSONSerialization.data(withJSONObject: ["hooks": [["command": command]]])
        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code",
            contents: String(decoding: data, as: UTF8.self),
            expectedCommand: command,
            eventStorePath: homeURL.path
        )

        XCTAssertTrue(inspection.configured)
        XCTAssertNotNil(inspection.issue)
        XCTAssertFalse(inspection.canRepair)
        XCTAssertFalse(inspection.requiresRepair)
    }

    func testUnparseableOwnedCommandRequiresManualFix() throws {
        let expected = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code", homeURL: homeURL, backendURL: backendURL
        )
        let custom = "env GENSEE_HOME=/Users/test/.gensee gensee hook claude-code"
        let contents = try nestedConfiguration(
            events: HarnessConfigurationHealth.expectedEvents(for: "claude-code"),
            command: custom
        )
        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code", contents: contents, expectedCommand: expected,
            eventStorePath: homeURL.path
        )

        XCTAssertTrue(inspection.configured)
        XCTAssertFalse(inspection.canRepair)
        XCTAssertTrue(inspection.issue?.contains("cannot safely rewrite") == true)
    }

    func testEmptyGenseeHomeRequiresManualFix() throws {
        let expected = HarnessConfigurationHealth.expectedCommand(
            provider: "claude-code", homeURL: homeURL, backendURL: backendURL
        )
        let contents = try nestedConfiguration(
            events: HarnessConfigurationHealth.expectedEvents(for: "claude-code"),
            command: "GENSEE_HOME= /usr/local/bin/gensee hook claude-code"
        )
        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code", contents: contents, expectedCommand: expected,
            eventStorePath: homeURL.path
        )

        XCTAssertTrue(inspection.configured)
        XCTAssertFalse(inspection.canRepair)
    }

    func testSimilarCommandNameIsNotClaimedByGensee() throws {
        let contents = try nestedConfiguration(
            events: HarnessConfigurationHealth.expectedEvents(for: "claude-code"),
            command: "GENSEE_HOME=/Users/test/.gensee /tmp/myhook claude-code"
        )
        let inspection = HarnessConfigurationHealth.inspect(
            provider: "claude-code", contents: contents, expectedCommand: "unused",
            eventStorePath: homeURL.path
        )

        XCTAssertFalse(inspection.configured)
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

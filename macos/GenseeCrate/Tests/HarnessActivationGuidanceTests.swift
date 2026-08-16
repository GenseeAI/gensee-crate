import XCTest

final class HarnessActivationGuidanceTests: XCTestCase {
    func testProviderEventsMatchTheirHarness() {
        XCTAssertTrue(HarnessActivationGuidance.eventMatches(provider: "codex", source: "codex"))
        XCTAssertTrue(HarnessActivationGuidance.eventMatches(provider: "claude-code", source: "claude"))
        XCTAssertTrue(HarnessActivationGuidance.eventMatches(provider: "vscode", source: "github-copilot"))
        XCTAssertFalse(HarnessActivationGuidance.eventMatches(provider: "codex", source: "claude-code"))
    }

    func testCodexGuidanceUsesCLITrustFlow() {
        let instruction = HarnessActivationGuidance.instruction(for: "codex")
        XCTAssertTrue(instruction.detail.contains("/hooks"))
        XCTAssertTrue(instruction.detail.contains("ChatGPT app"))
        XCTAssertEqual(instruction.actionTitle, "Open Codex Hook Review")
    }

    func testOmnigentExplainsManagedLaunch() {
        let instruction = HarnessActivationGuidance.instruction(for: "omnigent")
        XCTAssertTrue(instruction.detail.contains("gensee run"))
        XCTAssertEqual(instruction.actionTitle, "Copy Managed Launch")
    }

    func testCodexResolverPrefersBundledApplicationBeforeCommandLineWrappers() {
        let home = URL(fileURLWithPath: "/Users/example")
        let application = URL(fileURLWithPath: "/Applications/ChatGPT.app")
        let candidates = CodexExecutableResolver.orderedCandidates(
            home: home,
            applicationURLs: [application]
        )

        XCTAssertEqual(
            candidates.first?.path,
            "/Applications/ChatGPT.app/Contents/Resources/codex"
        )
        XCTAssertLessThan(
            candidates.firstIndex(of: URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex"))!,
            candidates.firstIndex(of: URL(fileURLWithPath: "/usr/local/bin/codex"))!
        )
    }

    func testCodexResolverSkipsAnExecutableThatFailsItsLaunchProbe() {
        let broken = URL(fileURLWithPath: "/usr/local/bin/codex")
        let working = URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex")

        XCTAssertEqual(
            CodexExecutableResolver.firstRunnable(candidates: [broken, working]) {
                $0 == working
            },
            working
        )
    }

    func testCodexHookReviewClosesOnlyItsOriginatingTerminalAfterTrustChanges() {
        let script = CodexHookReviewScript.render(
            codexURL: URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex"),
            hooksURL: URL(fileURLWithPath: "/Users/example/.codex/hooks.json")
        )

        XCTAssertTrue(script.contains("current_checksum\" != \"$initial_checksum"))
        XCTAssertTrue(script.contains("hooks_are_trusted"))
        XCTAssertTrue(script.contains("gensee hook codex"))
        XCTAssertTrue(script.contains("if tty of terminalTab is targetTTY"))
        XCTAssertFalse(script.contains("close front window"))
    }

    func testCodexHookReviewScriptHasValidZshSyntax() throws {
        let script = CodexHookReviewScript.render(
            codexURL: URL(fileURLWithPath: "/Applications/ChatGPT.app/Contents/Resources/codex"),
            hooksURL: URL(fileURLWithPath: "/Users/example/.codex/hooks.json")
        )
        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("gensee-codex-review-\(UUID().uuidString).command")
        defer { try? FileManager.default.removeItem(at: scriptURL) }
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-n", scriptURL.path]
        try process.run()
        process.waitUntilExit()

        XCTAssertEqual(process.terminationStatus, 0)
    }
}

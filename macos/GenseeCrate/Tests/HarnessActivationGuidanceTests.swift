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
}

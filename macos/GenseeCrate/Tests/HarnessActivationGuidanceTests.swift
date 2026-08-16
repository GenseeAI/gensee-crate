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
}

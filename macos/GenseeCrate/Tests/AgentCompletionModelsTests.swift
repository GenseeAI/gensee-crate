import XCTest

final class AgentCompletionModelsTests: XCTestCase {
    func testBuildsEvidenceBasedCompletionSummary() throws {
        var snapshot = SecuritySnapshot()
        snapshot.requests = [request(id: 7, started: 1_000, completed: 131_000)]
        snapshot.sessions = [RecordedSession(
            sessionID: "session-1", agentID: "codex", firstEventAt: 1_000,
            lastEventAt: 131_000, flagged: 0, requestCount: 1, eventCount: 4
        )]
        snapshot.agentEvents = [
            event(id: 1, type: "PreToolUse", timestamp: 2_000, tool: "Write", input: #"{"file_path":"/repo/App.swift"}"#, useID: "write"),
            event(id: 2, type: "PostToolUse", timestamp: 3_000, tool: "Write", useID: "write"),
            event(id: 3, type: "PreToolUse", timestamp: 4_000, tool: "Bash", input: #"{"command":"swift test"}"#, useID: "test"),
            event(id: 4, type: "PostToolUse", timestamp: 130_000, tool: "Bash", useID: "test"),
        ]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)

        XCTAssertEqual(summary.harness, "Codex")
        XCTAssertEqual(summary.toolCallCount, 2)
        XCTAssertEqual(summary.commandCount, 1)
        XCTAssertEqual(summary.testCommandCount, 1)
        XCTAssertEqual(summary.affectedFiles, ["/repo/App.swift"])
        XCTAssertEqual(summary.reviewState, .verified)
        XCTAssertTrue(summary.isLargeTask)
    }

    func testHighRiskFindingRequiresAttention() throws {
        var snapshot = SecuritySnapshot()
        snapshot.requests = [request(id: 7, started: 1_000, completed: 2_000)]
        snapshot.alerts = [SecurityAlert(
            alertID: 1, requestID: 7, sessionID: "session-1", severity: "high", action: "warn",
            ruleID: "secret", message: "Secret read", path: "/tmp/key", evidence: nil,
            createdAt: 1_500, originalUserPrompt: nil, eventSource: nil, eventType: nil,
            toolName: nil, toolInput: nil, toolUseID: nil, humanVerdict: nil,
            feedbackLabel: nil, feedbackCreatedAt: nil
        )]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)
        XCTAssertEqual(summary.reviewState, .attention)
        XCTAssertEqual(summary.highRiskAlertCount, 1)
        XCTAssertTrue(AgentCompletionDerivation.notificationBody(for: summary).contains("high-risk finding"))
    }

    func testIncompleteAndSystemRequestsAreNotReviewCards() {
        var snapshot = SecuritySnapshot()
        snapshot.requests = [
            RecordedRequest(requestID: 1, sessionID: "session-1", originalUserPrompt: "Still running", finalResponse: nil, createdAt: 1_000, completedAt: nil),
            RecordedRequest(requestID: 2, sessionID: "system", originalUserPrompt: nil, finalResponse: nil, createdAt: 1_000, completedAt: 2_000),
        ]
        XCTAssertTrue(AgentCompletionDerivation.summaries(from: snapshot).isEmpty)
    }

    private func request(id: Int64, started: Int64, completed: Int64) -> RecordedRequest {
        RecordedRequest(
            requestID: id, sessionID: "session-1", originalUserPrompt: "Implement the feature",
            finalResponse: nil, createdAt: started, completedAt: completed
        )
    }

    private func event(
        id: Int64, type: String, timestamp: Int64, tool: String,
        input: String? = nil, useID: String
    ) -> AgentEvent {
        AgentEvent(
            eventID: id, pid: 1, requestID: 7, timestamp: timestamp, source: "codex",
            type: type, cwd: "/repo", toolName: tool, sessionID: "session-1",
            permissionMode: nil, toolInput: input, toolResponse: nil, durationMS: nil,
            toolUseID: useID
        )
    }
}

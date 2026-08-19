import XCTest

final class TimelineModelsTests: XCTestCase {
    func testPairsToolEventsAndPrefersReportedDuration() {
        let events = [
            event(
                id: 1,
                type: "PreToolUse",
                timestamp: 1_000,
                tool: "Read",
                input: #"{"file_path":"/repo/Sources/App.swift"}"#,
                useID: "tool-1"
            ),
            event(
                id: 2,
                type: "PostToolUse",
                timestamp: 1_600,
                tool: "Read",
                response: #"{"duration_ms":250}"#,
                useID: "tool-1"
            ),
        ]

        let calls = TimelineDerivation.toolCalls(from: events)

        XCTAssertEqual(calls.count, 1)
        XCTAssertEqual(calls[0].durationMS, 250)
        XCTAssertEqual(calls[0].durationSource, .reported)
        XCTAssertEqual(calls[0].detail, "App.swift")
        XCTAssertEqual(calls[0].detailFull, "/repo/Sources/App.swift")
        XCTAssertEqual(calls[0].affectedFiles, ["/repo/Sources/App.swift"])
    }

    func testUsesElapsedDurationAndGroupsOverlappingCallsAsParallel() {
        let events = [
            event(id: 1, type: "PreToolUse", timestamp: 100, tool: "Read", useID: "a"),
            event(id: 2, type: "PostToolUse", timestamp: 300, tool: "Read", useID: "a"),
            event(id: 3, type: "PreToolUse", timestamp: 200, tool: "WebSearch", useID: "b"),
            event(id: 4, type: "PostToolUse", timestamp: 250, tool: "WebSearch", useID: "b"),
            event(id: 5, type: "PreToolUse", timestamp: 300, tool: "Bash", useID: "c"),
            event(id: 6, type: "PostToolUse", timestamp: 450, tool: "Bash", useID: "c"),
        ]

        let calls = TimelineDerivation.toolCalls(from: events)
        let groups = TimelineDerivation.groups(from: calls)

        XCTAssertEqual(calls.map(\.durationMS), [200, 50, 150])
        XCTAssertEqual(calls.map(\.durationSource), [.elapsed, .elapsed, .elapsed])
        XCTAssertEqual(groups.count, 2)
        XCTAssertTrue(groups[0].isParallel)
        XCTAssertEqual(groups[0].calls.map(\.id), ["a", "b"])
        XCTAssertFalse(groups[1].isParallel)
        XCTAssertEqual(groups[1].calls.map(\.id), ["c"])
    }

    func testPostFailureDoesNotCreateAStandaloneToolCall() {
        let events = [
            event(
                id: 1,
                type: "PostToolUseFailure",
                timestamp: 1_000,
                tool: "Bash",
                useID: "post-only"
            ),
        ]

        XCTAssertTrue(TimelineDerivation.toolCalls(from: events).isEmpty)
    }

    private func event(
        id: Int64,
        type: String,
        timestamp: Int64,
        tool: String,
        input: String? = nil,
        response: String? = nil,
        useID: String
    ) -> AgentEvent {
        AgentEvent(
            eventID: id,
            pid: 1,
            requestID: 1,
            timestamp: timestamp,
            source: "test",
            type: type,
            cwd: "/repo",
            toolName: tool,
            sessionID: "session-1",
            permissionMode: nil,
            toolInput: input,
            toolResponse: response,
            durationMS: nil,
            toolUseID: useID
        )
    }
}

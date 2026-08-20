import XCTest

final class AgentCompletionModelsTests: XCTestCase {
    func testFileTouchEvidenceDecodesSQLiteIntegerRiskFlags() throws {
        let touch = try JSONDecoder().decode(
            FileTouchEvidence.self,
            from: Data(#"{"path":"/repo/AGENTS.md","intended_and_verified":true,"last_observed_at":123,"risk_level":"high","is_memory_artifact":0,"is_persistent_target":1,"is_control_plane":1}"#.utf8)
        )

        XCTAssertTrue(touch.intendedAndVerified)
        XCTAssertFalse(touch.isMemoryArtifact)
        XCTAssertTrue(touch.isPersistentTarget)
        XCTAssertTrue(touch.isControlPlane)
        XCTAssertEqual(touch.riskLabels, ["Control plane", "Persistent target"])
    }

    func testBuildsEvidenceBasedCompletionSummary() throws {
        var snapshot = SecuritySnapshot()
        var recordedRequest = request(id: 7, started: 1_000, completed: 131_000)
        recordedRequest.fileTouches = [
            FileTouchEvidence(path: "/repo/App.swift", intendedAndVerified: true),
            FileTouchEvidence(path: "/repo/Unexpected.txt", intendedAndVerified: false),
        ]
        recordedRequest.ignoredFileTouchPaths = ["/repo/.build/cache"]
        snapshot.requests = [recordedRequest]
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
        XCTAssertEqual(summary.affectedFiles, ["/repo/App.swift", "/repo/Unexpected.txt"])
        XCTAssertEqual(summary.verifiedFiles, ["/repo/App.swift"])
        XCTAssertEqual(summary.unmatchedFiles, ["/repo/Unexpected.txt"])
        XCTAssertEqual(summary.ignoredFiles, ["/repo/.build/cache"])
        XCTAssertEqual(summary.ignoredFileTouchEventsOmitted, 0)
        XCTAssertEqual(summary.reviewState, .review)
        XCTAssertEqual(summary.attentionSignal?.kind, .scopeDrift)
        XCTAssertTrue(summary.needsIntervention)
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
        XCTAssertEqual(summary.attentionSignal?.kind, .highRiskActivity)
        XCTAssertTrue(summary.needsIntervention)
        XCTAssertTrue(AgentCompletionDerivation.notificationBody(for: summary).contains("high-risk finding"))
    }

    func testRoutineWarningStaysInHistoryWithoutInterrupting() throws {
        var snapshot = SecuritySnapshot()
        snapshot.requests = [request(id: 7, started: 1_000, completed: 2_000)]
        snapshot.alerts = [SecurityAlert(
            alertID: 1, requestID: 7, sessionID: "session-1", severity: "medium", action: "warn",
            ruleID: "routine", message: "Routine policy warning", path: nil, evidence: nil,
            createdAt: 1_500, originalUserPrompt: nil, eventSource: nil, eventType: nil,
            toolName: nil, toolInput: nil, toolUseID: nil, humanVerdict: nil,
            feedbackLabel: nil, feedbackCreatedAt: nil
        )]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)

        XCTAssertEqual(summary.reviewState, .review)
        XCTAssertNil(summary.attentionSignal)
        XCTAssertFalse(summary.needsIntervention)
    }

    @MainActor
    func testDelayedScopeEvidenceRemainsEligibleForNotification() throws {
        var cleanSnapshot = SecuritySnapshot()
        cleanSnapshot.requests = [request(id: 7, started: 1_000, completed: 2_000)]
        let clean = try XCTUnwrap(AgentCompletionDerivation.summaries(from: cleanSnapshot).first)

        var driftSnapshot = cleanSnapshot
        driftSnapshot.requests[0].fileTouches = [
            FileTouchEvidence(
                path: "/repo/surprise.txt",
                intendedAndVerified: false,
                declaredByHarness: false,
                osVerified: true
            ),
        ]
        let drift = try XCTUnwrap(AgentCompletionDerivation.summaries(from: driftSnapshot).first)

        XCTAssertTrue(
            CompletionNotificationCoordinator.newlyActionableSummaries(
                [clean],
                excluding: []
            ).isEmpty
        )
        XCTAssertEqual(
            CompletionNotificationCoordinator.newlyActionableSummaries(
                [drift],
                excluding: []
            ).map(\.requestID),
            [7]
        )
        XCTAssertTrue(
            CompletionNotificationCoordinator.newlyActionableSummaries(
                [drift],
                excluding: [7]
            ).isEmpty
        )
    }

    func testIncompleteAndSystemRequestsAreNotReviewCards() {
        var snapshot = SecuritySnapshot()
        snapshot.requests = [
            RecordedRequest(requestID: 1, sessionID: "session-1", originalUserPrompt: "Still running", finalResponse: nil, createdAt: 1_000, completedAt: nil),
            RecordedRequest(requestID: 2, sessionID: "system", originalUserPrompt: nil, finalResponse: nil, createdAt: 1_000, completedAt: 2_000),
        ]
        XCTAssertTrue(AgentCompletionDerivation.summaries(from: snapshot).isEmpty)
    }

    func testHarnessDisplayNameCollapsesBinaryPaths() {
        XCTAssertEqual(
            HarnessDisplayName.from("/Applications/Codex.app/Contents/MacOS/Codex"),
            "Codex"
        )
        XCTAssertEqual(
            HarnessDisplayName.from("/Users/test/Library/Application Support/Claude/Claude.app/Contents/MacOS/Claude"),
            "Claude"
        )
        XCTAssertEqual(
            HarnessDisplayName.from("/Applications/Visual Studio Code.app/Contents/MacOS/Electron"),
            "GitHub Copilot"
        )
    }

    func testRequestTitleOnlyAppliesDisplayWhitespaceAndFallback() {
        XCTAssertEqual(RequestPromptDisplay.title(from: "  Fix the request timeline\n"), "Fix the request timeline")
        XCTAssertEqual(RequestPromptDisplay.title(from: " \n "), "Completed agent request")
    }

    func testAnswerOnlyRequestStillBuildsReviewSummary() throws {
        var snapshot = SecuritySnapshot()
        snapshot.requests = [request(id: 9, started: 1_000, completed: 4_000)]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)

        XCTAssertEqual(summary.toolCallCount, 0)
        XCTAssertEqual(summary.durationMS, 3_000)
        XCTAssertEqual(summary.reviewState, .verified)
        XCTAssertNil(summary.attentionSignal)
        XCTAssertFalse(summary.needsIntervention)
    }

    func testRequestRollupsSurviveBoundedGlobalEventArrays() throws {
        var snapshot = SecuritySnapshot()
        var recordedRequest = request(id: 9, started: 1_000, completed: 4_000)
        recordedRequest.toolCallCount = 14
        recordedRequest.alertCount = 6
        recordedRequest.highRiskAlertCount = 2
        recordedRequest.strongestSeverity = "critical"
        recordedRequest.strongestAction = "block"
        snapshot.requests = [recordedRequest]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)

        XCTAssertEqual(summary.toolCallCount, 14)
        XCTAssertEqual(summary.alertCount, 6)
        XCTAssertEqual(summary.highRiskAlertCount, 2)
        XCTAssertEqual(summary.strongestSeverity, "critical")
        XCTAssertEqual(summary.strongestAction, "block")
        XCTAssertEqual(summary.reviewState, .attention)
        XCTAssertEqual(summary.attentionSignal?.kind, .blockedAction)
    }

    func testBoundedFileSummarySupportsSearchAndLargeTaskDetection() throws {
        var snapshot = SecuritySnapshot()
        var recordedRequest = request(id: 9, started: 1_000, completed: 4_000)
        recordedRequest.summaryFileTouchPaths = ["/repo/A.swift", "/repo/B.swift"]
        recordedRequest.summaryFileTouches = [
            FileTouchEvidence(path: "/repo/A.swift", intendedAndVerified: true),
            FileTouchEvidence(path: "/repo/B.swift", intendedAndVerified: false),
        ]
        snapshot.requests = [recordedRequest]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)

        XCTAssertEqual(summary.affectedFiles, ["/repo/A.swift", "/repo/B.swift"])
        XCTAssertEqual(summary.verifiedFiles, ["/repo/A.swift"])
        XCTAssertEqual(summary.unmatchedFiles, ["/repo/B.swift"])
        XCTAssertTrue(summary.isLargeTask)
    }

    func testTestDetectionDoesNotMatchWordsContainingTest() throws {
        var snapshot = SecuritySnapshot()
        snapshot.requests = [request(id: 7, started: 1_000, completed: 4_000)]
        snapshot.agentEvents = [
            event(id: 1, type: "PreToolUse", timestamp: 2_000, tool: "Bash", input: #"{"command":"show latest build"}"#, useID: "latest"),
            event(id: 2, type: "PreToolUse", timestamp: 3_000, tool: "Bash", input: #"{"command":"cargo test"}"#, useID: "test"),
        ]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)
        XCTAssertEqual(summary.testCommandCount, 1)
    }

    func testVerificationDetectionDoesNotTreatWorkspaceNameAsTestCommand() throws {
        var snapshot = SecuritySnapshot()
        var recordedRequest = request(id: 7, started: 1_000, completed: 4_000)
        recordedRequest.fileTouches = [
            FileTouchEvidence(
                path: "/repo/gensee-poc-test/note.txt",
                intendedAndVerified: true,
                lastObservedAt: 3_500
            ),
        ]
        snapshot.requests = [recordedRequest]
        snapshot.agentEvents = [
            event(
                id: 1,
                type: "PreToolUse",
                timestamp: 2_000,
                tool: "Bash",
                input: #"{"command":"cd /repo/gensee-poc-test && printf updated >> note.txt"}"#,
                useID: "write"
            ),
            event(id: 2, type: "PostToolUse", timestamp: 3_000, tool: "Bash", useID: "write"),
        ]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)

        XCTAssertEqual(summary.testCommandCount, 0)
        XCTAssertFalse(summary.testEvidenceIsStale)
        XCTAssertNil(summary.attentionSignal)
    }

    func testVerificationDetectionRecognizesCommonBuildAndLintRecipes() {
        let inputs = [
            #"{"command":"cd /repo && cargo test"}"#,
            #"{"command":"npm run lint"}"#,
            #"{"command":"python3 -m pytest tests/unit"}"#,
            #"{"command":"xcodebuild -scheme App test"}"#,
        ]

        for (index, input) in inputs.enumerated() {
            let call = TimelineToolCall(
                id: String(index),
                toolName: "Bash",
                startTimestamp: 1_000,
                endTimestamp: 2_000,
                durationMS: 1_000,
                durationSource: .elapsed,
                detail: nil,
                detailFull: nil,
                affectedFiles: [],
                input: input,
                response: nil
            )
            XCTAssertNotNil(AgentCompletionDerivation.verificationCommand(for: call), input)
        }
    }

    func testLaterEndpointMutationMakesVerificationStale() throws {
        var snapshot = SecuritySnapshot()
        var recordedRequest = request(id: 7, started: 1_000, completed: 8_000)
        recordedRequest.fileTouches = [
            FileTouchEvidence(
                path: "/repo/App.swift",
                intendedAndVerified: true,
                lastObservedAt: 7_000
            ),
        ]
        snapshot.requests = [recordedRequest]
        snapshot.agentEvents = [
            event(id: 1, type: "PreToolUse", timestamp: 2_000, tool: "Bash", input: #"{"command":"swift test"}"#, useID: "test"),
            event(id: 2, type: "PostToolUse", timestamp: 3_000, tool: "Bash", useID: "test"),
        ]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)

        XCTAssertTrue(summary.testEvidenceIsStale)
        XCTAssertEqual(summary.reviewState, .review)
        XCTAssertEqual(summary.attentionSignal?.kind, .staleVerification)
    }

    func testMutationDuringVerificationDoesNotMakeCompletedVerificationStale() throws {
        var snapshot = SecuritySnapshot()
        var recordedRequest = request(id: 7, started: 1_000, completed: 4_000)
        recordedRequest.fileTouches = [
            FileTouchEvidence(
                path: "/repo/App.swift",
                intendedAndVerified: true,
                lastObservedAt: 2_500
            ),
        ]
        snapshot.requests = [recordedRequest]
        snapshot.agentEvents = [
            event(id: 1, type: "PreToolUse", timestamp: 2_000, tool: "Bash", input: #"{"command":"swift test"}"#, useID: "test"),
            event(id: 2, type: "PostToolUse", timestamp: 3_000, tool: "Bash", useID: "test"),
        ]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)

        XCTAssertEqual(summary.lastTestAt, 3_000)
        XCTAssertFalse(summary.testEvidenceIsStale)
        XCTAssertNil(summary.attentionSignal)
    }

    func testSensitiveFileTouchCarriesDecisionBadges() throws {
        var snapshot = SecuritySnapshot()
        var recordedRequest = request(id: 7, started: 1_000, completed: 8_000)
        recordedRequest.fileTouches = [
            FileTouchEvidence(
                path: "/repo/AGENTS.md",
                intendedAndVerified: false,
                riskLevel: "high",
                isMemoryArtifact: true,
                isPersistentTarget: true,
                isControlPlane: true
            ),
        ]
        snapshot.requests = [recordedRequest]

        let summary = try XCTUnwrap(AgentCompletionDerivation.summaries(from: snapshot).first)

        XCTAssertEqual(summary.sensitiveFiles.first?.riskLabels, ["Control plane", "Agent memory", "Persistent target"])
        XCTAssertEqual(summary.reviewState, .review)
    }

    func testBuildsSessionSummaryAcrossCompletedRequests() throws {
        var snapshot = SecuritySnapshot()
        snapshot.sessions = [RecordedSession(
            sessionID: "session-1",
            agentID: "/Applications/Claude.app/Contents/MacOS/Claude",
            firstEventAt: 1_000,
            lastEventAt: 8_000,
            flagged: 0,
            requestCount: 2,
            eventCount: 0
        )]
        snapshot.requests = [
            RecordedRequest(requestID: 1, sessionID: "session-1", originalUserPrompt: "First", finalResponse: nil, createdAt: 1_000, completedAt: 3_000),
            RecordedRequest(requestID: 2, sessionID: "session-1", originalUserPrompt: "Second", finalResponse: nil, createdAt: 4_000, completedAt: 8_000),
        ]

        let session = try XCTUnwrap(AgentCompletionDerivation.sessionSummaries(from: snapshot).first)
        XCTAssertEqual(session.harness, "Claude")
        XCTAssertEqual(session.requestCount, 2)
        XCTAssertEqual(session.durationMS, 7_000)
        XCTAssertEqual(session.requests.map(\.requestID), [2, 1])
    }

    func testNotificationSeverityThresholdIncludesOnlySelectedLevelAndAbove() {
        XCTAssertTrue(NotificationSeverity.high.includes("critical"))
        XCTAssertTrue(NotificationSeverity.high.includes("HIGH"))
        XCTAssertFalse(NotificationSeverity.high.includes("medium"))
        XCTAssertTrue(NotificationSeverity.info.includes("info"))
        XCTAssertTrue(NotificationSeverity.info.includes("unknown"))
    }

    func testPolicyValueRankTreatsEndpointDenyAsHardBlock() {
        XCTAssertEqual(PolicyValueRank.action("deny"), PolicyValueRank.action("block"))
        XCTAssertGreaterThan(PolicyValueRank.action("deny"), PolicyValueRank.action("ask"))
        XCTAssertLessThan(PolicyValueRank.action("allow"), PolicyValueRank.action("deny"))
    }

    func testSearchMatchesMultipleTermsAcrossPromptAndFileFields() {
        XCTAssertTrue(searchTermsMatch(
            "auth migration",
            fields: ["Refactor the authentication flow", "/repo/db/migrations/2026.sql"]
        ))
        XCTAssertFalse(searchTermsMatch(
            "auth payment",
            fields: ["Refactor the authentication flow", "/repo/db/migrations/2026.sql"]
        ))
    }

    func testRuleReviewOverridesParseForInventoryAndBadges() {
        let policy = #"""
        {
          "review_overrides": [
            {"rule_id":"policy_z", "action":"warn"},
            {"rule_id":"policy_a", "severity":"low", "action":"allow"}
          ]
        }
        """#

        let overrides = RuleReviewOverride.parse(policyDocument: policy)

        XCTAssertEqual(overrides.map(\.ruleID), ["policy_a", "policy_z"])
        XCTAssertEqual(overrides.first?.severity, "low")
        XCTAssertEqual(overrides.first?.action, "allow")
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

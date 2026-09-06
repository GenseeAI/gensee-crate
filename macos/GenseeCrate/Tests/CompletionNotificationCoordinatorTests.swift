import XCTest

@MainActor
final class CompletionNotificationCoordinatorTests: XCTestCase {
    func testSingleAlertDigestInterpolatesSeverityAndMessage() {
        let digest = CompletionNotificationCoordinator.alertDigest(for: [
            alert(id: 7, severity: "high", message: "Credential read blocked", createdAt: 10),
        ])

        XCTAssertEqual(digest?.title, "High finding needs review")
        XCTAssertEqual(digest?.body, "Credential read blocked")
        XCTAssertEqual(digest?.highestAlertID, 7)
    }

    func testMultipleAlertDigestInterpolatesCountAndHighestFinding() {
        let digest = CompletionNotificationCoordinator.alertDigest(for: [
            alert(id: 8, severity: "medium", message: "Unmatched file write", createdAt: 12),
            alert(id: 9, severity: "critical", message: "Protected secret read", createdAt: 11),
        ])

        XCTAssertEqual(digest?.title, "2 new findings need review")
        XCTAssertEqual(digest?.body, "Protected secret read · 1 more")
        XCTAssertEqual(digest?.highestAlertID, 9)
    }

    func testInitialSnapshotSeedsHistoryBeforeFirstCompletionAndDoesNotReseed() throws {
        var baseline = CompletionNotificationBaseline()
        var requestIDs: Set<Int64> = []
        var alertIDs: Set<Int64> = []
        var snapshot = SecuritySnapshot()
        snapshot.requests = [RecordedRequest(
            requestID: 1, sessionID: "session-1", originalUserPrompt: "Old request",
            finalResponse: nil, createdAt: 1, completedAt: 2
        )]
        snapshot.alerts = [alert(id: 1, severity: "high", message: "Old finding", createdAt: 2)]
        XCTAssertTrue(baseline.seed(snapshot, requestIDs: &requestIDs, alertIDs: &alertIDs))
        XCTAssertEqual(requestIDs, [1])
        XCTAssertEqual(alertIDs, [1])

        // The watcher merges this completion before the first periodic process.
        snapshot.requests.append(RecordedRequest(
            requestID: 2, sessionID: "session-1", originalUserPrompt: "New request",
            finalResponse: nil, createdAt: 3, completedAt: 4
        ))
        snapshot.alerts.append(SecurityAlert(
            alertID: 2, requestID: 2, sessionID: "session-1", severity: "high", action: "warn",
            ruleID: "test", message: "New finding", path: nil, evidence: nil, createdAt: 4,
            originalUserPrompt: nil, eventSource: nil, eventType: nil, toolName: nil,
            toolInput: nil, toolUseID: nil, humanVerdict: nil, feedbackLabel: nil,
            feedbackCreatedAt: nil, rawEventCount: nil
        ))
        XCTAssertFalse(baseline.seed(snapshot, requestIDs: &requestIDs, alertIDs: &alertIDs))
        let actionable = CompletionNotificationCoordinator.newlyActionableSummaries(
            AgentCompletionDerivation.summaries(from: snapshot), excluding: requestIDs
        )
        XCTAssertEqual(actionable.map(\.requestID), [2])
        XCTAssertEqual(alertIDs, [1])
    }

    func testRefreshRequestsDuringSuspensionCoalesceAndAllCallersAwaitLatestPass() async {
        let refresh = CoalescingRefresh()
        let firstRead = expectation(description: "First policy read")
        let joined = expectation(description: "Concurrent caller joined")
        var resume: CheckedContinuation<Void, Never>?
        var mode = "observe"
        var applied: [String] = []
        var passes = 0
        let first = Task {
            await refresh.run {
                passes += 1
                let loadedMode = mode
                if passes == 1 {
                    await withCheckedContinuation { continuation in
                        resume = continuation
                        firstRead.fulfill()
                    }
                }
                if !refresh.hasPendingRefresh { applied.append(loadedMode) }
            }
        }
        await fulfillment(of: [firstRead], timeout: 2)
        mode = "enforce"
        let second = Task {
            joined.fulfill()
            await refresh.run { XCTFail("The active refresh closure should drain the request") }
            XCTAssertEqual(applied, ["enforce"])
        }
        await fulfillment(of: [joined], timeout: 2)
        XCTAssertTrue(refresh.hasPendingRefresh)
        resume?.resume()
        await first.value
        await second.value
        XCTAssertEqual(passes, 2)
        XCTAssertEqual(applied, ["enforce"])
        await refresh.run { applied.append("off") }
        XCTAssertEqual(applied, ["enforce", "off"], "A drained refresh must allow a new run")
    }

    private func alert(
        id: Int64,
        severity: String,
        message: String,
        createdAt: Int64
    ) -> SecurityAlert {
        SecurityAlert(
            alertID: id,
            requestID: 1,
            sessionID: "session-1",
            severity: severity,
            action: "warn",
            ruleID: "test",
            message: message,
            path: nil,
            evidence: nil,
            createdAt: createdAt,
            originalUserPrompt: nil,
            eventSource: nil,
            eventType: nil,
            toolName: nil,
            toolInput: nil,
            toolUseID: nil,
            humanVerdict: nil,
            feedbackLabel: nil,
            feedbackCreatedAt: nil,
            rawEventCount: nil
        )
    }
}

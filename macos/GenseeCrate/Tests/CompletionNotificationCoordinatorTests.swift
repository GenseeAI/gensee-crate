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
            feedbackCreatedAt: nil
        )
    }
}

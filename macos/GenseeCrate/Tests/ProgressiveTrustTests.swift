import XCTest

final class ProgressiveTrustTests: XCTestCase {
    func testProtectionLevelsMapToConcretePolicySettings() {
        XCTAssertEqual(ProtectionLevel.observe.endpointMode, "observe")
        XCTAssertFalse(ProtectionLevel.observe.noninteractive)
        XCTAssertEqual(ProtectionLevel.guarded.endpointMode, "protect")
        XCTAssertFalse(ProtectionLevel.guarded.noninteractive)
        XCTAssertEqual(ProtectionLevel.unattended.endpointMode, "strict")
        XCTAssertTrue(ProtectionLevel.unattended.noninteractive)
    }

    func testCurrentLevelPrefersFailClosedConfiguration() {
        XCTAssertEqual(ProtectionLevel.current(endpointMode: "observe", noninteractive: false), .observe)
        XCTAssertEqual(ProtectionLevel.current(endpointMode: "protect", noninteractive: false), .guarded)
        XCTAssertNil(ProtectionLevel.current(endpointMode: "protect", noninteractive: true))
        XCTAssertNil(ProtectionLevel.current(endpointMode: "strict", noninteractive: false))
        XCTAssertEqual(ProtectionLevel.current(endpointMode: "strict", noninteractive: true), .unattended)
    }

    func testSyntheticSnapshotIsInternallyConsistentAndClearlySourced() {
        let snapshot = DemoSnapshotFactory.make(now: Date(timeIntervalSince1970: 1_800_000_000))

        XCTAssertEqual(snapshot.summary.sessionsCount, snapshot.sessions.count)
        XCTAssertEqual(snapshot.summary.requestsCount, snapshot.requests.count)
        XCTAssertEqual(snapshot.summary.agentEventsCount, snapshot.agentEvents.count)
        XCTAssertEqual(snapshot.summary.alertsCount, snapshot.alerts.count)
        XCTAssertEqual(snapshot.summary.artifactsCount, snapshot.artifacts.count)
        XCTAssertEqual(snapshot.dailyActivity.count, 371)
        XCTAssertEqual(snapshot.recentActivity.filter { $0.interval == "hour" }.count, 24)
        XCTAssertEqual(snapshot.recentActivity.filter { $0.interval == "day" }.count, 7)
        XCTAssertTrue(snapshot.agentEvents.allSatisfy { $0.source == "synthetic-demo" })
        XCTAssertTrue(snapshot.alerts.allSatisfy { $0.eventSource == "synthetic-demo" })
        XCTAssertTrue(snapshot.requests.allSatisfy { $0.finalResponse == nil })
        XCTAssertTrue(snapshot.requests.contains { request in
            request.fileTouches.contains { $0.intendedAndVerified }
        })
        XCTAssertTrue(snapshot.requests.contains { request in
            request.fileTouches.contains { !$0.declaredByHarness && $0.osVerified }
        })
        XCTAssertTrue(snapshot.alerts.contains { $0.action.lowercased() == "block" })
        XCTAssertTrue(snapshot.alerts.contains { $0.action.lowercased() == "ask" })
        XCTAssertTrue(snapshot.artifacts.contains { $0.isControlPlane != 0 })
    }

    func testSyntheticDemoIncludesActionableRecoveryPoints() {
        let points = DemoSnapshotFactory.recoveryPoints(now: Date(timeIntervalSince1970: 1_800_000_000))

        XCTAssertEqual(points.count, 3)
        XCTAssertEqual(points[9108]?.workspace, "/Users/demo/AcmeShop")
        XCTAssertEqual(points[9103]?.trigger, "Database migration")
    }
}

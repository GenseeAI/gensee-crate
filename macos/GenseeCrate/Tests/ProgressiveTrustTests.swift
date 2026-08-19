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
        XCTAssertEqual(ProtectionLevel.current(endpointMode: "protect", noninteractive: true), .unattended)
        XCTAssertEqual(ProtectionLevel.current(endpointMode: "strict", noninteractive: false), .unattended)
    }

    func testSyntheticSnapshotIsInternallyConsistentAndClearlySourced() {
        let snapshot = DemoSnapshotFactory.make(now: Date(timeIntervalSince1970: 1_800_000_000))

        XCTAssertEqual(snapshot.summary.sessionsCount, snapshot.sessions.count)
        XCTAssertEqual(snapshot.summary.requestsCount, snapshot.requests.count)
        XCTAssertEqual(snapshot.summary.agentEventsCount, snapshot.agentEvents.count)
        XCTAssertEqual(snapshot.summary.alertsCount, snapshot.alerts.count)
        XCTAssertEqual(snapshot.summary.artifactsCount, snapshot.artifacts.count)
        XCTAssertFalse(snapshot.dailyActivity.isEmpty)
        XCTAssertTrue(snapshot.agentEvents.allSatisfy { $0.source == "synthetic-demo" })
        XCTAssertTrue(snapshot.alerts.allSatisfy { $0.eventSource == "synthetic-demo" })
        XCTAssertTrue(snapshot.requests.allSatisfy { $0.finalResponse == nil })
    }
}

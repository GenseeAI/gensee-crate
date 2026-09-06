import XCTest

final class EndpointSensorHealthTests: XCTestCase {
    func testOutageStallFlappingAndIntentionalOff() {
        let start = Date(timeIntervalSince1970: 2000)
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth()
        XCTAssertNil(tracker.observe(health, now: start))
        XCTAssertEqual(tracker.observe(health, now: start.addingTimeInterval(10)), .unavailable)
        health.mode = "off"
        XCTAssertNil(tracker.observe(health, now: start.addingTimeInterval(80)))
        health.mode = "observe"; health.connected = true; health.running = true
        health.lastSuccessfulPollAt = start
        XCTAssertNil(tracker.observe(health, now: start.addingTimeInterval(20)))
        XCTAssertEqual(tracker.observe(health, now: start.addingTimeInterval(30)), .stalled)
        tracker = MonitoringGapAlarmTracker(); health.lastSuccessfulPollAt = nil
        for second in [0, 2, 4] {
            health.connected = true
            _ = tracker.observe(health, now: start.addingTimeInterval(Double(second)))
            health.connected = false
            let result = tracker.observe(health, now: start.addingTimeInterval(Double(second + 1)))
            if second == 4 { XCTAssertEqual(result, .unavailable) } else { XCTAssertNil(result) }
        }
    }

    func testRuntimeGapAlarmsSeedHistoryCoalesceBurstsAndResetOnBoot() {
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth()
        health.connected = true; health.running = true; health.bootID = "a"; health.kernelDrops = 10000
        let start = Date(timeIntervalSince1970: 1000)
        XCTAssertNil(tracker.observe(health, now: start))
        health.kernelDrops += 100
        XCTAssertEqual(tracker.observe(health, now: start), .events(100))
        health.kernelDrops += 200
        XCTAssertNil(tracker.observe(health, now: start.addingTimeInterval(1)))
        XCTAssertEqual(tracker.observe(health, now: start.addingTimeInterval(60)), .events(200))
        XCTAssertNil(tracker.observe(health, now: start.addingTimeInterval(120)))
        health.bootID = "b"; health.kernelDrops = 0
        XCTAssertNil(tracker.observe(health, now: start.addingTimeInterval(180)))
        health.ringDrops = 100
        XCTAssertEqual(tracker.observe(health, now: start.addingTimeInterval(181)), .events(100))
    }

    func testConfigurationAndIngestionWarningsRemainIndependent() {
        var health = EndpointSensorHealth(connected: true, running: true)
        health.configurationWarning = "Invalid Cowork entries skipped."
        health.ingestionWarning = EndpointIngestBatchPolicy.warning(forRejectedEvents: 3)
        XCTAssertTrue(health.isAvailable)
        XCTAssertTrue(health.needsAttention)
        XCTAssertNil(health.error)
        XCTAssertNotNil(health.configurationWarning)
        XCTAssertNotNil(health.ingestionWarning)

        // A clean ingestion batch must not hide a standing config warning.
        health.ingestionWarning = EndpointIngestBatchPolicy.warning(forRejectedEvents: 0)
        XCTAssertTrue(health.isAvailable)
        XCTAssertTrue(health.needsAttention)
        XCTAssertNotNil(health.configurationWarning)
        health.configurationWarning = nil
        XCTAssertFalse(health.needsAttention)
    }

    func testConfigurationCorrectionDoesNotClearEvidenceWarning() {
        var health = EndpointSensorHealth(connected: true, running: true)
        health.configurationWarning = "Invalid Cowork entries skipped."
        health.ingestionWarning = EndpointIngestBatchPolicy.warning(forRejectedEvents: 1)
        health.configurationWarning = nil
        XCTAssertTrue(health.isAvailable)
        XCTAssertTrue(health.needsAttention)
        XCTAssertNotNil(health.ingestionWarning)

        health.connected = false
        health.error = "Connection interrupted."
        XCTAssertFalse(health.isAvailable)
        XCTAssertTrue(health.needsAttention)
        health.connected = true
        health.running = false
        XCTAssertFalse(health.isAvailable)
    }
}

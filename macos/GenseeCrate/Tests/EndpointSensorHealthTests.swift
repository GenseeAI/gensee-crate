import XCTest

final class EndpointSensorHealthTests: XCTestCase {
    func testRuntimeGapAlarmsSeedHistoryCoalesceBurstsAndResetOnBoot() {
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth()
        health.connected = true; health.running = true; health.bootID = "a"; health.kernelDrops = 10000
        let start = Date(timeIntervalSince1970: 1000)
        XCTAssertNil(tracker.observe(health, now: start))
        health.kernelDrops += 100
        XCTAssertEqual(tracker.observe(health, now: start), 100)
        health.kernelDrops += 200
        XCTAssertNil(tracker.observe(health, now: start.addingTimeInterval(1)))
        XCTAssertEqual(tracker.observe(health, now: start.addingTimeInterval(60)), 200)
        XCTAssertNil(tracker.observe(health, now: start.addingTimeInterval(120)))
        health.bootID = "b"; health.kernelDrops = 0
        XCTAssertNil(tracker.observe(health, now: start.addingTimeInterval(180)))
        health.ringDrops = 100
        XCTAssertEqual(tracker.observe(health, now: start.addingTimeInterval(181)), 100)
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

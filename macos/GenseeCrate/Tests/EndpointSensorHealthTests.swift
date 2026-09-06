import XCTest

final class EndpointSensorHealthTests: XCTestCase {
    func testConfiguredModeControlsAlarmsEvenWhenSensorReportIsStaleOff() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(mode: "off", configuredMode: "off")
        XCTAssertNil(tracker.observe(health, now: start))
        health.configuredMode = "observe"
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(1))))
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(11))), .unavailable)
    }

    func testPersistentOutageLatchesEachKindAndStableRecoveryRearms() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth()
        XCTAssertNil(tracker.observe(health, now: start))
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(10))), .unavailable)
        for second in [70, 300, 3600] {
            XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(second))))
        }
        health.connected = true; health.running = true; health.lastSuccessfulPollAt = start
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(3601))), .stalled)
        for second in [3602, 3633] {
            health.lastSuccessfulPollAt = start.advanced(by: .seconds(second))
            XCTAssertNil(tracker.observe(health, now: health.lastSuccessfulPollAt!))
        }
        health.connected = false
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(3634))))
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(3644))), .unavailable)
    }

    func testIntentionalOffPreservesPendingLosses() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true)
        XCTAssertNil(tracker.observe(health, now: start))
        health.kernelDrops = 60
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(1))))
        health.configuredMode = "off"
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(2))))
        health.configuredMode = "observe"; health.kernelDrops = 120
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(3))), .events(120))
    }

    func testWakeGraceAndConnectionFlappingUseMonotonicDurations() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true)
        health.lastSuccessfulPollAt = start
        _ = tracker.observe(health, now: start)
        tracker.resumeAfterSleep(now: start.advanced(by: .seconds(2)))
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(31))))
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(32))))
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(42))), .stalled)
        tracker = MonitoringGapAlarmTracker(); health.lastSuccessfulPollAt = nil
        for second in [0, 2, 4, 6] {
            health.connected = true
            _ = tracker.observe(health, now: start.advanced(by: .seconds(second)))
            health.connected = false
            let result = tracker.observe(health, now: start.advanced(by: .seconds(second + 1)))
            if second == 4 { XCTAssertEqual(result, .unavailable) } else { XCTAssertNil(result) }
        }
    }

    func testRuntimeGapAlarmsSeedHistoryCoalesceBurstsAndResetOnBoot() {
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth()
        health.connected = true; health.running = true; health.bootID = "a"; health.kernelDrops = 10000
        let start = SuspendingClock.now
        XCTAssertNil(tracker.observe(health, now: start))
        health.kernelDrops += 100
        XCTAssertEqual(tracker.observe(health, now: start), .events(100))
        health.kernelDrops += 200
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(1))))
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(60))), .events(200))
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(120))))
        health.bootID = "b"; health.kernelDrops = 0
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(180))))
        health.ringDrops = 100
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(181))), .events(100))
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

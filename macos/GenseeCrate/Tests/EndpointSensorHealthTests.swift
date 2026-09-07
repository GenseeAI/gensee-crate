import XCTest

final class EndpointSensorHealthTests: XCTestCase {
    func testUnknownModeIsSilentAndConfirmedOffDoesNotAlarm() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(mode: "off")
        XCTAssertNil(tracker.observe(health, now: start))
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(100))))
        health.configuredMode = "off"
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(200))))
        XCTAssertNil(tracker.bannerIncident)
    }

    func testNewOutageRestoresDismissedBannerWithoutRepeatingNotification() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(configuredMode: "observe")
        _ = tracker.observe(health, now: start)
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(10))), .unavailable)
        tracker.dismissBanner()
        let dismissedRevision = tracker.bannerRevision
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(11))))
        XCTAssertEqual(tracker.bannerRevision, dismissedRevision)
        health.connected = true; health.running = true
        _ = tracker.observe(health, now: start.advanced(by: .seconds(12)))
        health.connected = false
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(32))))
        XCTAssertEqual(tracker.bannerRevision, dismissedRevision, "A short re-outage must not restore a dismissed alarm")
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(42))))
        XCTAssertGreaterThan(tracker.bannerRevision, dismissedRevision)
        XCTAssertEqual(tracker.bannerIncident, .unavailable)
        health.connected = true
        _ = tracker.observe(health, now: start.advanced(by: .seconds(43)))
        _ = tracker.observe(health, now: start.advanced(by: .seconds(73)))
        XCTAssertNil(tracker.bannerIncident)
    }

    func testEventLossBannerSurvivesContinuousHealthyRecoveryWindows() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
        _ = tracker.observe(health, now: start)
        health.kernelDrops = 100
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(29))), .events(100))
        let revision = tracker.bannerRevision
        for second in [30, 60, 90, 120] {
            XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(second))))
            XCTAssertEqual(tracker.bannerIncident, .events(100))
            XCTAssertEqual(tracker.bannerRevision, revision, "Recovery must neither clear nor restore a dismissed event-loss cue")
        }
    }

    func testUndismissedLossReturnsAfterOutageRecoveryAcrossSensorRestart() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
        health.bootID = "before"
        _ = tracker.observe(health, now: start)
        health.kernelDrops = 100
        _ = tracker.observe(health, now: start.advanced(by: .seconds(1)))
        health.connected = false
        _ = tracker.observe(health, now: start.advanced(by: .seconds(2)))
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(12))), .unavailable)
        XCTAssertEqual(tracker.bannerIncident, .unavailable)
        health.connected = true; health.bootID = "after"; health.kernelDrops = 0
        _ = tracker.observe(health, now: start.advanced(by: .seconds(13)))
        _ = tracker.observe(health, now: start.advanced(by: .seconds(43)))
        XCTAssertEqual(tracker.bannerIncident, .events(100))
        tracker.dismissBanner()
        XCTAssertNil(tracker.bannerIncident)
        _ = tracker.observe(health, now: start.advanced(by: .seconds(80)))
        XCTAssertNil(tracker.bannerIncident)
        _ = tracker.observe(health, now: start.advanced(by: .seconds(140)))
        health.kernelDrops = 100
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(141))), .events(100))
    }

    func testDismissAcknowledgesQueuedLossAndContinuedEpisode() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
        health.bootID = "a"
        _ = tracker.observe(health, now: start)
        health.kernelDrops = 100
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(1))), .events(100))
        health.kernelDrops = 500
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(2))))
        tracker.dismissBanner()
        let revision = tracker.bannerRevision
        for second in [3, 30, 61, 90, 120] {
            health.kernelDrops += 200
            XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(second))))
            XCTAssertNil(tracker.bannerIncident)
            XCTAssertEqual(tracker.bannerRevision, revision)
        }
        _ = tracker.observe(health, now: start.advanced(by: .seconds(121)))
        _ = tracker.observe(health, now: start.advanced(by: .seconds(180)))
        health.ringDrops = 100
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(181))), .events(100))
    }

    func testDismissedQueuedLossDoesNotReturnAtCooldown() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
        _ = tracker.observe(health, now: start)
        health.kernelDrops = 100
        _ = tracker.observe(health, now: start.advanced(by: .seconds(1)))
        health.kernelDrops = 500
        _ = tracker.observe(health, now: start.advanced(by: .seconds(2)))
        tracker.dismissBanner()
        for second in [3, 61, 120, 180] {
            XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(second))))
            XCTAssertNil(tracker.bannerIncident)
        }
    }

    func testDismissedLossRearmsOnSensorRestartButOutageIsIndependent() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
        health.bootID = "a"
        _ = tracker.observe(health, now: start)
        health.kernelDrops = 100
        _ = tracker.observe(health, now: start.advanced(by: .seconds(1)))
        tracker.dismissBanner()
        health.connected = false
        _ = tracker.observe(health, now: start.advanced(by: .seconds(2)))
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(12))), .unavailable)
        tracker.dismissBanner()
        health.connected = true; health.bootID = "b"; health.kernelDrops = 0
        _ = tracker.observe(health, now: start.advanced(by: .seconds(60)))
        health.kernelDrops = 100
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(61))), .events(100))
    }

    func testDismissingOutageRevealsLossWithoutRestoringTheSameOutage() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
        _ = tracker.observe(health, now: start)
        health.kernelDrops = 100
        _ = tracker.observe(health, now: start.advanced(by: .seconds(1)))
        health.connected = false
        _ = tracker.observe(health, now: start.advanced(by: .seconds(2)))
        _ = tracker.observe(health, now: start.advanced(by: .seconds(12)))
        tracker.dismissBanner()
        XCTAssertEqual(tracker.bannerIncident, .events(100))
        _ = tracker.observe(health, now: start.advanced(by: .seconds(13)))
        XCTAssertEqual(tracker.bannerIncident, .events(100))
        tracker.dismissBanner()
        _ = tracker.observe(health, now: start.advanced(by: .seconds(14)))
        XCTAssertNil(tracker.bannerIncident)
        health.connected = true
        _ = tracker.observe(health, now: start.advanced(by: .seconds(15)))
        _ = tracker.observe(health, now: start.advanced(by: .seconds(45)))
        XCTAssertNil(tracker.bannerIncident, "Dismissed history must not return after recovery")
    }

    func testLossDismissedBeforeOutageDoesNotReturnOnRecovery() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
        _ = tracker.observe(health, now: start)
        health.kernelDrops = 100
        _ = tracker.observe(health, now: start.advanced(by: .seconds(1)))
        tracker.dismissBanner()
        health.connected = false
        _ = tracker.observe(health, now: start.advanced(by: .seconds(2)))
        _ = tracker.observe(health, now: start.advanced(by: .seconds(12)))
        health.connected = true
        _ = tracker.observe(health, now: start.advanced(by: .seconds(13)))
        _ = tracker.observe(health, now: start.advanced(by: .seconds(43)))
        XCTAssertNil(tracker.bannerIncident)
    }

    func testDeathDuringSleepAlarmsFortyActiveSecondsAfterWake() {
        let start = SuspendingClock.now
        var tracker = MonitoringGapAlarmTracker()
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
        health.lastSuccessfulPollAt = start
        _ = tracker.observe(health, now: start)
        tracker.resumeAfterSleep(now: start)
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(29))))
        XCTAssertNil(tracker.observe(health, now: start.advanced(by: .seconds(30))))
        XCTAssertEqual(tracker.observe(health, now: start.advanced(by: .seconds(40))), .stalled)
    }

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
        var health = EndpointSensorHealth(configuredMode: "observe")
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
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
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
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
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
        var health = EndpointSensorHealth(configuredMode: "observe")
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
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
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
        var health = EndpointSensorHealth(connected: true, running: true, configuredMode: "observe")
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

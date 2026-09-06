import XCTest

final class EndpointSensorHealthTests: XCTestCase {
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

import XCTest

final class EndpointIngestAcknowledgementIOTests: XCTestCase {
    func testAcknowledgementTimeoutScalesForBacklogBatches() {
        XCTAssertEqual(
            EndpointIngestBatchPolicy.acknowledgementTimeout(forEventCount: 0),
            5
        )
        XCTAssertEqual(
            EndpointIngestBatchPolicy.acknowledgementTimeout(forEventCount: 500),
            55
        )
        XCTAssertEqual(
            EndpointIngestBatchPolicy.acknowledgementTimeout(forEventCount: 1_000),
            60
        )
    }

    func testRejectionWarningClearsAfterAHealthyBatch() {
        XCTAssertNotNil(EndpointIngestBatchPolicy.warning(forRejectedEvents: 1))
        XCTAssertNil(EndpointIngestBatchPolicy.warning(forRejectedEvents: 0))
    }

    func testLaunchContinuityReportsEventsOverwrittenBeforeDrainResumed() {
        let issue = EndpointEvidenceContinuityPolicy.issue(
            persistedBootID: "boot-a",
            currentBootID: "boot-a",
            persistedCursor: 100,
            oldestCursor: 125,
            nextCursor: 500,
            persistedKernelDrops: 4,
            currentKernelDrops: 7
        )

        XCTAssertEqual(issue?.unavailableEventCount, 27)
        XCTAssertEqual(issue?.sensorRestarted, false)
        XCTAssertTrue(issue?.detail.contains("27 Endpoint Security events were not retained") == true)
    }

    func testLaunchContinuityDoesNotReportHealthyResume() {
        XCTAssertNil(EndpointEvidenceContinuityPolicy.issue(
            persistedBootID: "boot-a",
            currentBootID: "boot-a",
            persistedCursor: 100,
            oldestCursor: 80,
            nextCursor: 110,
            persistedKernelDrops: 4,
            currentKernelDrops: 4
        ))
    }

    func testLaunchContinuityReportsSensorRestartWithoutInventingACount() {
        let issue = EndpointEvidenceContinuityPolicy.issue(
            persistedBootID: "boot-a",
            currentBootID: "boot-b",
            persistedCursor: 100,
            oldestCursor: 1,
            nextCursor: 20,
            persistedKernelDrops: 9,
            currentKernelDrops: 0
        )

        XCTAssertEqual(issue?.unavailableEventCount, 0)
        XCTAssertEqual(issue?.sensorRestarted, true)
        XCTAssertTrue(issue?.detail.contains("restarted while Gensee Crate was closed") == true)
    }

    func testLaunchContinuityIgnoresFirstEverConnection() {
        XCTAssertNil(EndpointEvidenceContinuityPolicy.issue(
            persistedBootID: "",
            currentBootID: "boot-a",
            persistedCursor: 0,
            oldestCursor: 20,
            nextCursor: 40,
            persistedKernelDrops: nil,
            currentKernelDrops: 10
        ))
    }

    func testReadChunkReturnsAvailableAcknowledgementData() throws {
        let pipe = Pipe()
        defer {
            try? pipe.fileHandleForReading.close()
            try? pipe.fileHandleForWriting.close()
        }
        let acknowledgement = Data("{\"gensee_ingest_ack\":\"committed\"}\n".utf8)
        try pipe.fileHandleForWriting.write(contentsOf: acknowledgement)

        XCTAssertEqual(
            try EndpointIngestAcknowledgementIO.readChunk(
                from: pipe.fileHandleForReading,
                timeout: 0.25
            ),
            acknowledgement
        )
    }

    func testReadChunkFailsWithinItsDeadlineWhenTheIngesterDoesNotRespond() {
        let pipe = Pipe()
        defer {
            try? pipe.fileHandleForReading.close()
            try? pipe.fileHandleForWriting.close()
        }
        let startedAt = ProcessInfo.processInfo.systemUptime

        XCTAssertThrowsError(
            try EndpointIngestAcknowledgementIO.readChunk(
                from: pipe.fileHandleForReading,
                timeout: 0.05
            )
        ) { error in
            let error = error as NSError
            XCTAssertEqual(error.domain, "ai.gensee.crate.endpoint-security")
            XCTAssertEqual(error.code, 7)
        }
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - startedAt, 0.5)
    }

    func testWriteDeliversACompleteBatch() async throws {
        let pipe = Pipe()
        defer {
            try? pipe.fileHandleForReading.close()
            try? pipe.fileHandleForWriting.close()
        }
        let expected = Data(repeating: 0x41, count: 32 * 1024)
        let reader = Task.detached { pipe.fileHandleForReading.readData(ofLength: expected.count) }
        try EndpointIngestAcknowledgementIO.write(
            expected,
            to: pipe.fileHandleForWriting,
            timeout: 1
        )
        let received = await reader.value
        XCTAssertEqual(received, expected)
    }
}

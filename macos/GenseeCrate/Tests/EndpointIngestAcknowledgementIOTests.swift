import XCTest

final class EndpointIngestAcknowledgementIOTests: XCTestCase {
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
}

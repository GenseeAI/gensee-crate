import XCTest

@MainActor
final class EndpointSensorPollingTests: XCTestCase {
    func testHungRequestTimesOutAndLateReplyCannotCompleteItsSuccessor() async throws {
        let polling = EndpointSensorPolling()
        var staleReply: ((Result<Int, Error>) -> Void)?
        do {
            let _: Int = try await polling.request(timeout: .milliseconds(20)) { staleReply = $0 }
            XCTFail("A missing XPC reply must time out")
        } catch {
            XCTAssertEqual((error as NSError).code, 5)
        }
        let submitted = expectation(description: "Successor submitted")
        var currentReply: ((Result<Int, Error>) -> Void)?
        let successor = Task {
            try await polling.request(timeout: .seconds(2)) { (complete: @escaping (Result<Int, Error>) -> Void) in
                currentReply = complete
                submitted.fulfill()
            }
        }
        await fulfillment(of: [submitted], timeout: 1)
        staleReply?(.success(1))
        staleReply?(.failure(NSError(domain: "late-xpc-error", code: 99)))
        currentReply?(.success(2))
        let result = try await successor.value
        XCTAssertEqual(result, 2)
    }

    func testExplicitRetryCancelsHungRequestAndSkipsTheNextBackoff() async throws {
        let polling = EndpointSensorPolling()
        let submitted = expectation(description: "Hung fetch submitted")
        let recovered = expectation(description: "Replacement fetch completed")
        var staleReply: ((Result<Int, Error>) -> Void)?
        let loop = Task {
            do {
                let _: Int = try await polling.request(timeout: .seconds(2)) {
                    staleReply = $0
                    submitted.fulfill()
                }
                XCTFail("Retry should cancel the old request")
            } catch is CancellationError {
                // Explicit retry is not a transport failure.
            } catch { XCTFail("Unexpected failure: \(error)") }
            await polling.wait(for: .seconds(30))
            let result: Int = try await polling.request { $0(.success(42)) }
            XCTAssertEqual(result, 42)
            recovered.fulfill()
        }
        defer { loop.cancel() }
        await fulfillment(of: [submitted], timeout: 1)
        polling.retryNow()
        polling.retryNow()
        staleReply?(.success(-1))
        await fulfillment(of: [recovered], timeout: 1)
        try await loop.value
    }

    func testExplicitRetryWakesAnExistingThirtySecondBackoff() async {
        let polling = EndpointSensorPolling()
        let sleeping = expectation(description: "Entering backoff")
        let woke = expectation(description: "Backoff interrupted")
        let loop = Task {
            sleeping.fulfill()
            await polling.wait(for: .seconds(30))
            woke.fulfill()
        }
        defer { loop.cancel() }
        await fulfillment(of: [sleeping], timeout: 1)
        polling.retryNow()
        await fulfillment(of: [woke], timeout: 1)
        await loop.value
    }

    func testLoopCancellationAlsoCancelsItsBackoff() async {
        let polling = EndpointSensorPolling()
        let sleeping = expectation(description: "Entering backoff")
        let cancelled = expectation(description: "Wait cancelled")
        let loop = Task {
            sleeping.fulfill()
            await polling.wait(for: .seconds(30))
            cancelled.fulfill()
        }
        await fulfillment(of: [sleeping], timeout: 1)
        loop.cancel()
        await fulfillment(of: [cancelled], timeout: 1)
        await loop.value
    }

    func testCompletedRequestDeadlineDoesNotCancelALaterRequest() async throws {
        let polling = EndpointSensorPolling()
        let first: Int = try await polling.request(timeout: .milliseconds(10)) { $0(.success(1)) }
        XCTAssertEqual(first, 1)
        let second: Int = try await polling.request(timeout: .seconds(1)) { complete in
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(30))
                complete(.success(2))
                complete(.failure(NSError(domain: "duplicate-error", code: 99)))
            }
        }
        XCTAssertEqual(second, 2)
    }
}

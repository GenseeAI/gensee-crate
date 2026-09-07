import Foundation

/// Bounds each XPC wait and keeps explicit retries responsive without starting
/// overlapping fetch/ingestion loops. All completion arbitration is on MainActor.
@MainActor
final class EndpointSensorPolling {
    private var pendingRequestID: UUID?
    private var cancelRequest: (() -> Void)?
    private var sleepTask: Task<Void, Never>?
    private var retryRequested = false

    func request<Value>(
        timeout: Duration = .seconds(5),
        submit: (@escaping (Result<Value, Error>) -> Void) -> Void
    ) async throws -> Value {
        guard pendingRequestID == nil else {
            throw NSError(domain: "ai.gensee.crate.endpoint-security", code: 6,
                          userInfo: [NSLocalizedDescriptionKey: "A sensor request is already in progress."])
        }
        return try await withCheckedThrowingContinuation { continuation in
            let id = UUID()
            pendingRequestID = id
            var deadline: Task<Void, Never>?
            let finish: (Result<Value, Error>) -> Void = { [weak self] result in
                guard let self, self.pendingRequestID == id else { return }
                self.pendingRequestID = nil
                self.cancelRequest = nil
                deadline?.cancel()
                continuation.resume(with: result)
            }
            cancelRequest = { finish(.failure(CancellationError())) }
            deadline = Task { @MainActor in
                do { try await Task.sleep(for: timeout) } catch { return }
                finish(.failure(NSError(
                    domain: "ai.gensee.crate.endpoint-security", code: 5,
                    userInfo: [NSLocalizedDescriptionKey: "The Endpoint Security sensor did not respond in time. Reconnecting automatically."]
                )))
            }
            submit { result in
                Task { @MainActor in finish(result) }
            }
        }
    }

    func retryNow() {
        // Preserve the wakeup if it arrives during a fetch or durable ingestion,
        // before the loop has entered its next sleep.
        retryRequested = true
        cancelRequest?()
        sleepTask?.cancel()
    }

    func wait(for delay: Duration) async {
        if retryRequested {
            retryRequested = false
            return
        }
        let task = Task<Void, Never> { try? await Task.sleep(for: delay) }
        sleepTask = task
        await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }
        sleepTask = nil
        retryRequested = false
    }
}

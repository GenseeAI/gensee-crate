import Darwin
import Foundation

enum EndpointIngestBatchPolicy {
    private static let minimumAcknowledgementTimeout: TimeInterval = 5
    private static let acknowledgementTimeoutPerEvent: TimeInterval = 0.1
    private static let maximumAcknowledgementTimeout: TimeInterval = 60

    static func acknowledgementTimeout(forEventCount eventCount: UInt64) -> TimeInterval {
        min(
            maximumAcknowledgementTimeout,
            minimumAcknowledgementTimeout + Double(eventCount) * acknowledgementTimeoutPerEvent
        )
    }

    static func warning(forRejectedEvents rejectedEvents: UInt64) -> String? {
        guard rejectedEvents > 0 else { return nil }
        return "Endpoint Security skipped \(rejectedEvents.formatted()) invalid event(s) in the latest batch. Update Gensee Crate if this continues."
    }
}

struct EndpointEvidenceContinuityIssue: Equatable {
    let unavailableEventCount: UInt64
    let sensorRestarted: Bool

    var title: String { "Incomplete Endpoint Security evidence" }

    var summary: String {
        if unavailableEventCount > 0 {
            return "\(unavailableEventCount.formatted()) event\(unavailableEventCount == 1 ? "" : "s") were not retained"
        }
        return "The Endpoint Security sensor restarted"
    }

    var detail: String {
        if unavailableEventCount > 0 {
            let restartSuffix = sensorRestarted ? " The sensor also restarted during that interval." : ""
            return "\(unavailableEventCount.formatted()) Endpoint Security event\(unavailableEventCount == 1 ? " was" : "s were") not retained while Gensee Crate was closed or unable to drain the sensor. Evidence for that interval is incomplete.\(restartSuffix)"
        }
        return "The Endpoint Security sensor restarted while Gensee Crate was closed. Evidence for that interval may be incomplete."
    }
}

enum EndpointEvidenceContinuityPolicy {
    static func issue(
        persistedBootID: String,
        currentBootID: String,
        persistedCursor: UInt64,
        oldestCursor: UInt64,
        nextCursor: UInt64,
        persistedKernelDrops: UInt64?,
        currentKernelDrops: UInt64
    ) -> EndpointEvidenceContinuityIssue? {
        guard !persistedBootID.isEmpty, !currentBootID.isEmpty, persistedCursor > 0 else {
            return nil
        }

        let bootChanged = persistedBootID != currentBootID
        let sensorRewound = !bootChanged && nextCursor <= persistedCursor
        let sensorRestarted = bootChanged || sensorRewound

        let overwrittenEvents: UInt64
        if sensorRestarted || oldestCursor <= persistedCursor {
            overwrittenEvents = 0
        } else {
            overwrittenEvents = oldestCursor - persistedCursor - 1
        }

        let newKernelDrops: UInt64
        if !bootChanged,
           let persistedKernelDrops,
           currentKernelDrops >= persistedKernelDrops
        {
            newKernelDrops = currentKernelDrops - persistedKernelDrops
        } else {
            newKernelDrops = 0
        }

        let unavailableEventCount = overwrittenEvents + newKernelDrops
        guard unavailableEventCount > 0 || sensorRestarted else { return nil }
        return EndpointEvidenceContinuityIssue(
            unavailableEventCount: unavailableEventCount,
            sensorRestarted: sensorRestarted
        )
    }
}

enum EndpointIngestAcknowledgementIO {
    static func write(_ data: Data, to handle: FileHandle, timeout: TimeInterval) throws {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var offset = 0
        while offset < data.count {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw timeoutError() }
            var descriptor = pollfd(
                fd: handle.fileDescriptor,
                events: Int16(POLLOUT | POLLHUP | POLLERR),
                revents: 0
            )
            let timeoutMilliseconds = Int32(min(max(remaining * 1_000, 1), Double(Int32.max)))
            var pollResult: Int32
            repeat {
                pollResult = Darwin.poll(&descriptor, 1, timeoutMilliseconds)
            } while pollResult < 0 && errno == EINTR
            guard pollResult > 0 else {
                if pollResult == 0 { throw timeoutError() }
                throw posixError("Could not wait for Endpoint Security ingestion capacity.")
            }
            let written = data.withUnsafeBytes { bytes -> Int in
                guard let base = bytes.baseAddress else { return 0 }
                return Darwin.write(
                    handle.fileDescriptor,
                    base.advanced(by: offset),
                    min(16 * 1024, data.count - offset)
                )
            }
            if written < 0 {
                if errno == EINTR || errno == EAGAIN { continue }
                throw posixError("Could not write Endpoint Security telemetry to the ingester.")
            }
            guard written > 0 else { throw timeoutError() }
            offset += written
        }
    }

    static func readChunk(from handle: FileHandle, timeout: TimeInterval) throws -> Data {
        var descriptor = pollfd(
            fd: handle.fileDescriptor,
            events: Int16(POLLIN | POLLHUP | POLLERR),
            revents: 0
        )
        let timeoutMilliseconds = Int32(min(max(timeout * 1_000, 1), Double(Int32.max)))
        var result: Int32
        repeat {
            result = Darwin.poll(&descriptor, 1, timeoutMilliseconds)
        } while result < 0 && errno == EINTR
        if result == 0 {
            throw timeoutError()
        }
        if result < 0 {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "Could not wait for Endpoint Security ingestion acknowledgement."]
            )
        }
        var buffer = [UInt8](repeating: 0, count: 4_096)
        var bytesRead: Int
        repeat {
            bytesRead = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(handle.fileDescriptor, bytes.baseAddress, bytes.count)
            }
        } while bytesRead < 0 && errno == EINTR
        if bytesRead < 0 {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "Could not read Endpoint Security ingestion acknowledgement."]
            )
        }
        return Data(buffer.prefix(bytesRead))
    }

    static func timeoutError() -> Error {
        NSError(
            domain: "ai.gensee.crate.endpoint-security",
            code: 7,
            userInfo: [NSLocalizedDescriptionKey: "Endpoint Security ingestion did not confirm durable storage before the batch deadline. The ingester will restart automatically."]
        )
    }

    private static func posixError(_ message: String) -> Error {
        NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(errno),
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}

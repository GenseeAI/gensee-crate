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

enum EndpointIngestAcknowledgementIO {
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
}

import Darwin
import Foundation

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
            userInfo: [NSLocalizedDescriptionKey: "Endpoint Security ingestion did not confirm durable storage within five seconds. The ingester will restart automatically."]
        )
    }
}

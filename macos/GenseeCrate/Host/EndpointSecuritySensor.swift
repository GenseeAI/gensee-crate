import Foundation

struct EndpointSensorHealth: Equatable {
    var connected = false
    var running = false
    var mode = "observe"
    var totalEvents: UInt64 = 0
    var bufferedEvents: UInt64 = 0
    var kernelDrops: UInt64 = 0
    var ringDrops: UInt64 = 0
    var lastGlobalSequence: UInt64 = 0
    var ingestedEvents: UInt64 = 0
    var authorizationCount: UInt64 = 0
    var deniedCount: UInt64 = 0
    var maxAuthorizationLatencyUS: UInt64 = 0
    var managedProcesses: UInt64 = 0
    var lastEventAt: Date?
    var error: String?

    var hasDataLoss: Bool { kernelDrops > 0 || ringDrops > 0 }
}

/// Pulls bounded event batches from the root system extension and streams them
/// to one long-lived `gensee ingest endpoint-security` process. The Rust side
/// owns durable storage, process graph attribution, findings, and correlation.
@MainActor
final class EndpointSecuritySensor: ObservableObject {
    @Published private(set) var health = EndpointSensorHealth()

    private let homeURL: URL
    private let executableURL: URL?
    private var connection: GenseeEndpointSecurityBridge?
    private var ingestProcess: Process?
    private var ingestInput: FileHandle?
    private var pollingTask: Task<Void, Never>?
    private var cursor: UInt64 = 0
    private var bootID = ""
    private var started = false
    private var pendingConfiguration: [String: Any] = ["mode": "observe"]
    private var configurationNeedsPush = true

    init(homeURL: URL, executableURL: URL?) {
        self.homeURL = homeURL
        self.executableURL = executableURL
    }

    deinit {
        pollingTask?.cancel()
        connection?.invalidate()
        try? ingestInput?.close()
        ingestProcess?.terminate()
    }

    func start() {
        guard !started else { return }
        started = true
        do {
            try startIngester()
            try connect()
            pollingTask = Task { [weak self] in
                while !Task.isCancelled {
                    await self?.pollOnce()
                    try? await Task.sleep(for: .milliseconds(500))
                }
            }
        } catch {
            health.error = error.localizedDescription
        }
    }

    func reconnect() {
        connection?.invalidate()
        connection = nil
        do {
            try connect()
            health.error = nil
        } catch {
            health.connected = false
            health.error = error.localizedDescription
            // Extension upgrades and service restarts invalidate the Mach
            // connection permanently. Recreate it so polling recovers without
            // requiring the user to relaunch the console.
            connection?.invalidate()
            connection = nil
            try? connect()
        }
    }

    func updateConfiguration(
        mode: String,
        protectedPaths: [String],
        blockedExecutables: [String],
        managedRoots: [[String: Any]]
    ) {
        pendingConfiguration = [
            "schema_version": 1,
            "mode": mode,
            "protected_paths": protectedPaths,
            "blocked_executables": blockedExecutables,
            "managed_roots": managedRoots,
        ]
        configurationNeedsPush = true
    }

    private func machServiceName() throws -> String {
        let extensionURL = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/SystemExtensions")
            .appendingPathComponent("ai.gensee.crate.endpoint-security.systemextension")
            .appendingPathComponent("Contents/Info.plist")
        if let dictionary = NSDictionary(contentsOf: extensionURL),
           let name = dictionary["NSEndpointSecurityMachServiceName"] as? String,
           !name.isEmpty
        {
            return name
        }
        return "3KWVB4M63F.ai.gensee.crate.endpoint-security.xpc"
    }

    private func connect() throws {
        let next = GenseeEndpointSecurityBridge(
            machServiceName: try machServiceName(),
            codeSigningRequirement: "anchor apple generic and certificate leaf[subject.OU] = \"3KWVB4M63F\" and identifier \"ai.gensee.crate.endpoint-security\""
        )
        next.interruptionHandler = { [weak self] in
            Task { @MainActor in
                self?.health.connected = false
                self?.health.error = "The Endpoint Security sensor connection was interrupted."
            }
        }
        next.invalidationHandler = { [weak self] in
            Task { @MainActor in self?.health.connected = false }
        }
        next.activate()
        connection = next
    }

    private func startIngester() throws {
        guard ingestProcess == nil else { return }
        guard let executableURL else { throw GenseeCLIError.executableNotFound }
        let process = Process()
        let input = Pipe()
        let errors = Pipe()
        process.executableURL = executableURL
        process.arguments = ["ingest", "endpoint-security"]
        process.standardInput = input
        process.standardError = errors
        var environment = ProcessInfo.processInfo.environment
        environment["GENSEE_HOME"] = homeURL.path
        process.environment = environment
        process.terminationHandler = { [weak self] process in
            let errorData = errors.fileHandleForReading.readDataToEndOfFile()
            let detail = String(decoding: errorData, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            Task { @MainActor in
                self?.ingestProcess = nil
                self?.ingestInput = nil
                if process.terminationStatus != 0 {
                    self?.health.error = detail.isEmpty
                        ? "Endpoint Security ingestion stopped unexpectedly."
                        : detail
                }
            }
        }
        try process.run()
        ingestProcess = process
        ingestInput = input.fileHandleForWriting
    }

    private func pollOnce() async {
        do {
            if ingestProcess == nil { try startIngester() }
            guard let connection else {
                throw NSError(
                    domain: "ai.gensee.crate.endpoint-security",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Endpoint Security sensor is not connected."]
                )
            }
            let response = try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<([[String: Any]], UInt64, [String: Any]), Error>) in
                connection.fetchEvents(
                    afterCursor: cursor,
                    limit: 500,
                    reply: { events, nextCursor, health in
                        guard let events = events as? [[String: Any]],
                              let health = health as? [String: Any]
                        else {
                            continuation.resume(throwing: NSError(
                                domain: "ai.gensee.crate.endpoint-security",
                                code: 2,
                                userInfo: [NSLocalizedDescriptionKey: "Endpoint Security returned malformed XPC data."]
                            ))
                            return
                        }
                        continuation.resume(returning: (events, nextCursor, health))
                    },
                    failure: { error in continuation.resume(throwing: error) }
                )
            }
            applyHealth(response.2)
            if configurationNeedsPush {
                try await pushConfiguration(using: connection)
            }
            try write(events: response.0)
            cursor = response.1
            health.connected = true
            health.error = nil
        } catch {
            health.connected = false
            health.error = error.localizedDescription
        }
    }

    private func pushConfiguration(using connection: GenseeEndpointSecurityBridge) async throws {
        let configuration = pendingConfiguration
        let accepted = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Bool, Error>) in
            connection.updateConfiguration(
                configuration,
                reply: { accepted, message in
                    if accepted {
                        continuation.resume(returning: true)
                    } else {
                        continuation.resume(throwing: NSError(
                            domain: "ai.gensee.crate.endpoint-security",
                            code: 4,
                            userInfo: [NSLocalizedDescriptionKey: message ?? "Sensor rejected its configuration."]
                        ))
                    }
                },
                failure: { error in continuation.resume(throwing: error) }
            )
        }
        if accepted { configurationNeedsPush = false }
    }

    private func applyHealth(_ dictionary: [String: Any]) {
        let nextBootID = dictionary["boot_id"] as? String ?? ""
        let nextCursor = number(dictionary["next_cursor"])
        let oldestCursor = number(dictionary["oldest_cursor"])
        if bootID != nextBootID || cursor >= nextCursor {
            bootID = nextBootID
            cursor = oldestCursor > 0 ? oldestCursor - 1 : 0
        }
        health.running = (dictionary["running"] as? Bool) ?? false
        health.mode = (dictionary["mode"] as? String) ?? "observe"
        health.totalEvents = number(dictionary["total_events"])
        health.bufferedEvents = number(dictionary["buffered_events"])
        health.kernelDrops = number(dictionary["kernel_drops"])
        health.ringDrops = number(dictionary["ring_drops"])
        health.lastGlobalSequence = number(dictionary["last_global_seq_num"])
        health.authorizationCount = number(dictionary["authorization_count"])
        health.deniedCount = number(dictionary["denied_count"])
        health.maxAuthorizationLatencyUS = number(dictionary["max_authorization_latency_us"])
        health.managedProcesses = number(dictionary["managed_processes"])
    }

    private func write(events: [[String: Any]]) throws {
        guard !events.isEmpty else { return }
        guard let ingestInput else {
            throw NSError(
                domain: "ai.gensee.crate.endpoint-security",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Endpoint Security ingestion is not running."]
            )
        }
        var batch = Data()
        for event in events {
            let data = try JSONSerialization.data(withJSONObject: event, options: [.sortedKeys])
            batch.append(data)
            batch.append(0x0A)
        }
        try ingestInput.write(contentsOf: batch)
        health.ingestedEvents += UInt64(events.count)
        health.lastEventAt = Date()
    }

    private func number(_ value: Any?) -> UInt64 {
        (value as? NSNumber)?.uint64Value ?? 0
    }
}

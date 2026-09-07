import Foundation

/// Pulls bounded event batches from the root system extension and streams them
/// to one long-lived `gensee ingest endpoint-security` process. The Rust side
/// owns durable storage, process graph attribution, findings, and correlation.
@MainActor
final class EndpointSecuritySensor: ObservableObject {
    @Published private(set) var health = EndpointSensorHealth()

    private let homeURL: URL
    private let executableURL: URL?
    private let cursorDefaultsKey: String
    private let bootIDDefaultsKey: String
    private let kernelDropsDefaultsKey: String
    private let acknowledgedContinuityDefaultsKey: String
    private var connection: GenseeEndpointSecurityBridge?
    private var connectionRecovery = EndpointConnectionRecovery()
    private var ingestProcess: Process?
    private var ingestInput: FileHandle?
    private var ingestAcknowledgements: FileHandle?
    private var pollingTask: Task<Void, Never>?
    private let polling = EndpointSensorPolling()
    private var cursor: UInt64 = 0
    private var bootID = ""
    private var persistedKernelDrops: UInt64?
    private var checkedLaunchContinuity = false
    private var started = false
    private var consecutiveFailures = 0
    private var lastPollFailed = false
    private var pendingConfiguration: [String: Any] = ["mode": "observe"]
    private var pendingConfigurationData: Data?
    // Do not replace the extension's last known managed roots with an empty
    // startup configuration. The console supplies a complete configuration
    // only after it has loaded a valid dashboard snapshot.
    private var configurationNeedsPush = false
    private var ingestErrorBuffer = Data()
    private var ingestAcknowledgementBuffer = Data()

    init(homeURL: URL, executableURL: URL?) {
        self.homeURL = homeURL
        self.executableURL = executableURL
        let defaultsSuffix = homeURL.standardizedFileURL.path
        cursorDefaultsKey = "gensee.endpointSecurity.cursor.\(defaultsSuffix)"
        bootIDDefaultsKey = "gensee.endpointSecurity.bootID.\(defaultsSuffix)"
        kernelDropsDefaultsKey = "gensee.endpointSecurity.kernelDrops.\(defaultsSuffix)"
        acknowledgedContinuityDefaultsKey = "gensee.endpointSecurity.acknowledgedContinuity.\(defaultsSuffix)"
        let defaults = UserDefaults.standard
        cursor = (defaults.object(forKey: cursorDefaultsKey) as? NSNumber)?.uint64Value ?? 0
        bootID = defaults.string(forKey: bootIDDefaultsKey) ?? ""
        persistedKernelDrops = (defaults.object(forKey: kernelDropsDefaultsKey) as? NSNumber)?.uint64Value
    }

    deinit {
        pollingTask?.cancel()
        connection?.invalidate()
        try? ingestInput?.close()
        try? ingestAcknowledgements?.close()
        ingestProcess?.terminate()
    }

    func start() {
        guard !started else { return }
        started = true
        // The loop owns startup and reconnection retries, even if the first
        // ingester launch fails or the extension goes away in the background.
        pollingTask = Task { [weak self] in
            while !Task.isCancelled {
                let delay = await self?.pollAndChooseDelay() ?? .milliseconds(500)
                await self?.polling.wait(for: delay)
            }
        }
    }

    private func pollAndChooseDelay() async -> Duration {
        let previousCursor = cursor
        await pollOnce()
        // A missing extension or ingester must not be retried at full rate:
        // each attempt builds a privileged XPC connection or spawns a process.
        if lastPollFailed {
            return EndpointIngestBatchPolicy.retryDelay(afterConsecutiveFailures: consecutiveFailures)
        }
        let draining = EndpointIngestBatchPolicy.shouldDrainImmediately(
            connected: health.connected,
            backlog: health.backlogEvents,
            previousCursor: previousCursor,
            currentCursor: cursor
        )
        return .milliseconds(draining ? 10 : 500)
    }

    func reconnect() {
        // Cancel a pending XPC wait or backoff sleep now. The one polling loop
        // still owns replacement and durable ingestion, so retries cannot race
        // another batch or advance its cursor twice.
        connectionRecovery.failed(generation: connectionRecovery.generation)
        consecutiveFailures = 0
        polling.retryNow()
        start()
    }

    func acknowledgeLaunchContinuityIssue() {
        guard let issue = health.launchContinuityIssue else { return }
        UserDefaults.standard.set(issue.fingerprint, forKey: acknowledgedContinuityDefaultsKey)
        health.launchContinuityIssue = nil
    }

    func setConfiguredMode(_ mode: String) { health.configuredMode = mode }

    func updateConfiguration(
        mode: String,
        protectedPaths: [String],
        blockedExecutables: [String],
        managedRoots: [[String: Any]],
        failClosedManagedOnly: Bool,
        maxAuthorizationLatencyMS: UInt64
    ) {
        health.configuredMode = mode
        let configuration: [String: Any] = [
            "schema_version": 1,
            "mode": mode,
            "protected_paths": protectedPaths,
            "blocked_executables": blockedExecutables,
            "managed_roots": managedRoots,
            "fail_closed_managed_only": failClosedManagedOnly,
            "max_auth_latency_ms": maxAuthorizationLatencyMS,
        ]
        let encoded = try? JSONSerialization.data(withJSONObject: configuration, options: [.sortedKeys])
        guard encoded != pendingConfigurationData else { return }
        pendingConfiguration = configuration
        pendingConfigurationData = encoded
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
        let generation = connectionRecovery.installed()
        next.interruptionHandler = { [weak self] in
            Task { @MainActor in
                self?.connectionFailed(generation: generation, message: "The Endpoint Security sensor connection was interrupted.")
            }
        }
        next.invalidationHandler = { [weak self] in
            Task { @MainActor in
                self?.connectionFailed(generation: generation, message: "The Endpoint Security sensor connection was invalidated.")
            }
        }
        let previousConnection = connection
        connection = next
        checkedLaunchContinuity = false
        configurationNeedsPush = pendingConfigurationData != nil
        // `health.connected` is left to the next fetch result: a failed
        // predecessor already cleared it, and a voluntary replacement of a
        // healthy transport is not an interruption.
        next.activate()
        previousConnection?.invalidate()
    }

    private func connectionFailed(generation: UInt64, message: String) {
        guard connectionRecovery.failed(generation: generation) else { return }
        health.connected = false
        health.error = message
    }

    private func startIngester() throws {
        guard ingestProcess == nil else { return }
        guard let executableURL else { throw GenseeCLIError.executableNotFound }
        let process = Process()
        let input = Pipe()
        let acknowledgements = Pipe()
        let errors = Pipe()
        process.executableURL = executableURL
        process.arguments = ["ingest", "endpoint-security"]
        process.standardInput = input
        process.standardOutput = acknowledgements
        process.standardError = errors
        var environment = ProcessInfo.processInfo.environment
        environment["GENSEE_HOME"] = homeURL.path
        process.environment = environment
        ingestErrorBuffer.removeAll(keepingCapacity: true)
        ingestAcknowledgementBuffer.removeAll(keepingCapacity: true)
        errors.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            Task { @MainActor in
                guard self?.ingestProcess === process else { return }
                self?.appendIngesterError(data)
            }
        }
        process.terminationHandler = { [weak self] process in
            errors.fileHandleForReading.readabilityHandler = nil
            let trailing = errors.fileHandleForReading.readDataToEndOfFile()
            Task { @MainActor in
                guard self?.ingestProcess === process else { return }
                self?.appendIngesterError(trailing)
                let detail = String(decoding: self?.ingestErrorBuffer ?? Data(), as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                self?.ingestProcess = nil
                self?.ingestInput = nil
                self?.ingestAcknowledgements = nil
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
        ingestAcknowledgements = acknowledgements.fileHandleForReading
    }

    private func pollOnce() async {
        lastPollFailed = false
        do {
            if connectionRecovery.needsConnection || connection == nil { try connect() }
            let generation = connectionRecovery.generation
            if ingestProcess == nil { try startIngester() }
            guard let connection else {
                throw NSError(
                    domain: "ai.gensee.crate.endpoint-security",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Endpoint Security sensor is not connected."]
                )
            }
            // Apply harness/root changes before fetching. Otherwise one batch
            // from a just-disabled harness can be delivered after the user has
            // turned protection off.
            if configurationNeedsPush {
                try await pushConfiguration(using: connection, generation: generation)
            }
            guard !configurationNeedsPush, !connectionRecovery.needsConnection else { return }
            let response: ([[String: Any]], UInt64, [String: Any]) = try await sensorRequest(generation: generation) { complete in
                connection.fetchEvents(
                    afterCursor: cursor,
                    limit: 500,
                    reply: { events, nextCursor, health in
                        guard let events = events as? [[String: Any]],
                              let health = health as? [String: Any]
                        else {
                            complete(.failure(NSError(
                                domain: "ai.gensee.crate.endpoint-security",
                                code: 2,
                                userInfo: [NSLocalizedDescriptionKey: "Endpoint Security returned malformed XPC data."]
                            )))
                            return
                        }
                        complete(.success((events, nextCursor, health)))
                    },
                    failure: { complete(.failure($0)) }
                )
            }
            guard generation == connectionRecovery.generation, !connectionRecovery.needsConnection else { return }
            health.lastSuccessfulPollAt = SuspendingClock.now
            health.connected = true
            let pendingCursor = response.1
            let didRewind = applyHealth(
                response.2,
                fetchedThroughCursor: pendingCursor
            )
            // A boot/ring rewind means this batch was fetched from a stale
            // cursor. Refetch from the recovered cursor before ingesting it so
            // the first post-launch batch is never delivered twice.
            if !didRewind {
                let rejectedEvents = try await write(
                    events: response.0,
                    pendingCursor: pendingCursor,
                    bootID: bootID
                )
                cursor = pendingCursor
                persistCursor()
                health.ingestionWarning = EndpointIngestBatchPolicy.warning(
                    forRejectedEvents: rejectedEvents
                )
            }
            if generation == connectionRecovery.generation, !connectionRecovery.needsConnection {
                health.connected = true
                health.error = nil
                consecutiveFailures = 0
            }
        } catch is CancellationError {
            // An explicit retry is not evidence of a transport outage.
            return
        } catch {
            lastPollFailed = true
            consecutiveFailures += 1
            health.connected = false
            health.error = error.localizedDescription
        }
    }

    private func pushConfiguration(using connection: GenseeEndpointSecurityBridge, generation: UInt64) async throws {
        let configuration = pendingConfiguration
        let configurationData = pendingConfigurationData
        let response: (Bool, String?) = try await sensorRequest(generation: generation) { complete in
            connection.updateConfiguration(
                configuration,
                reply: { complete(.success(($0, $1))) },
                failure: { complete(.failure($0)) }
            )
        }
        guard response.0 else {
            // A semantic configuration rejection is not a transport failure.
            throw NSError(domain: "ai.gensee.crate.endpoint-security", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: response.1 ?? "Sensor rejected its configuration."])
        }
        guard generation == connectionRecovery.generation, !connectionRecovery.needsConnection else { return }
        health.configurationWarning = response.1
        configurationNeedsPush = pendingConfigurationData != configurationData
    }

    private func sensorRequest<Value>(
        generation: UInt64,
        submit: (@escaping (Result<Value, Error>) -> Void) -> Void
    ) async throws -> Value {
        do {
            return try await polling.request(submit: submit)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            connectionFailed(generation: generation, message: error.localizedDescription)
            throw error
        }
    }

    @discardableResult
    private func applyHealth(
        _ dictionary: [String: Any],
        fetchedThroughCursor: UInt64
    ) -> Bool {
        if let warning = dictionary["configuration_warning"] as? String {
            health.configurationWarning = warning.isEmpty ? nil : warning
        }
        let nextBootID = dictionary["boot_id"] as? String ?? ""
        let nextCursor = number(dictionary["next_cursor"])
        let oldestCursor = number(dictionary["oldest_cursor"])
        let nextKernelDrops = number(dictionary["kernel_drops"])
        if !checkedLaunchContinuity {
            let issue = EndpointEvidenceContinuityPolicy.issue(
                persistedBootID: bootID,
                currentBootID: nextBootID,
                persistedCursor: cursor,
                oldestCursor: oldestCursor,
                nextCursor: nextCursor,
                persistedKernelDrops: persistedKernelDrops,
                currentKernelDrops: nextKernelDrops
            )
            let acknowledgedFingerprint = UserDefaults.standard.string(
                forKey: acknowledgedContinuityDefaultsKey
            )
            health.launchContinuityIssue = issue?.fingerprint == acknowledgedFingerprint ? nil : issue
            checkedLaunchContinuity = true
        }
        let firstObservation = bootID.isEmpty
        let didRewind = firstObservation || bootID != nextBootID || cursor >= nextCursor
        if didRewind {
            bootID = nextBootID
            // A pre-persistence build may already have ingested the extension
            // ring. On the first observation, resume at the live head instead
            // of replaying that ring and duplicating durable system events.
            // For an actual extension restart/rewind, resume from its oldest
            // available event so newly buffered evidence is retained.
            cursor = firstObservation
                ? (nextCursor > 0 ? nextCursor - 1 : 0)
                : (oldestCursor > 0 ? oldestCursor - 1 : 0)
        }
        health.bootID = dictionary["boot_id"] as? String ?? ""
        health.running = (dictionary["running"] as? Bool) ?? false
        health.mode = (dictionary["mode"] as? String) ?? "observe"
        health.receivedMessages = number(dictionary["received_messages"])
        health.maxCallbackLatencyUS = number(dictionary["max_callback_latency_us"])
        health.pendingEvidence = number(dictionary["pending_evidence"])
        health.maxPendingEvidence = number(dictionary["max_pending_evidence"])
        health.maxQueueDelayUS = number(dictionary["max_queue_delay_us"])
        health.totalEvents = number(dictionary["total_events"])
        health.bufferedEvents = number(dictionary["buffered_events"])
        let effectiveCursor = didRewind ? cursor : fetchedThroughCursor
        health.backlogEvents = nextCursor > effectiveCursor
            ? nextCursor - effectiveCursor - 1
            : 0
        health.kernelDrops = nextKernelDrops
        health.ringDrops = number(dictionary["ring_drops"])
        health.lastGlobalSequence = number(dictionary["last_global_seq_num"])
        health.authorizationCount = number(dictionary["authorization_count"])
        health.deniedCount = number(dictionary["denied_count"])
        health.maxAuthorizationLatencyUS = number(dictionary["max_authorization_latency_us"])
        health.configuredMaxAuthorizationLatencyUS = max(
            1,
            number(dictionary["configured_max_authorization_latency_us"])
        )
        health.managedProcesses = number(dictionary["managed_processes"])
        return didRewind
    }

    private func persistCursor() {
        let defaults = UserDefaults.standard
        defaults.set(NSNumber(value: cursor), forKey: cursorDefaultsKey)
        defaults.set(bootID, forKey: bootIDDefaultsKey)
        if persistedKernelDrops != health.kernelDrops {
            defaults.set(NSNumber(value: health.kernelDrops), forKey: kernelDropsDefaultsKey)
            persistedKernelDrops = health.kernelDrops
        }
    }

    private func write(
        events: [[String: Any]],
        pendingCursor: UInt64,
        bootID: String
    ) async throws -> UInt64 {
        guard let ingestInput, let ingestAcknowledgements else {
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
        let commit: [String: Any] = [
            "gensee_ingest_control": "commit",
            "protocol_version": 1,
            "sensor_cursor": NSNumber(value: pendingCursor),
            "boot_id": bootID,
            "event_count": NSNumber(value: events.count),
        ]
        batch.append(try JSONSerialization.data(withJSONObject: commit, options: [.sortedKeys]))
        batch.append(0x0A)
        let rejectedEvents: UInt64
        do {
            try await Task.detached(priority: .utility) {
                try EndpointIngestAcknowledgementIO.write(
                    batch,
                    to: ingestInput,
                    timeout: EndpointIngestBatchPolicy.acknowledgementTimeout(
                        forEventCount: UInt64(events.count)
                    )
                )
            }.value
            rejectedEvents = try await awaitDurableAcknowledgement(
                from: ingestAcknowledgements,
                cursor: pendingCursor,
                bootID: bootID,
                eventCount: UInt64(events.count)
            )
        } catch {
            health.ingestionWarning = error.localizedDescription
            stopIngester()
            throw error
        }
        health.ingestedEvents += UInt64(events.count) - rejectedEvents
        health.rejectedEvents += rejectedEvents
        if !events.isEmpty {
            health.lastEventAt = Date()
        }
        return rejectedEvents
    }

    private func awaitDurableAcknowledgement(
        from handle: FileHandle,
        cursor: UInt64,
        bootID: String,
        eventCount: UInt64
    ) async throws -> UInt64 {
        let acknowledgementTimeout = EndpointIngestBatchPolicy.acknowledgementTimeout(
            forEventCount: eventCount
        )
        let deadline = ProcessInfo.processInfo.systemUptime + acknowledgementTimeout
        while true {
            if let line = nextAcknowledgementLine() {
                let value = try JSONSerialization.jsonObject(with: line)
                guard let acknowledgement = value as? [String: Any],
                      acknowledgement["gensee_ingest_ack"] as? String == "committed",
                      number(acknowledgement["protocol_version"]) == 1,
                      number(acknowledgement["sensor_cursor"]) == cursor,
                      acknowledgement["boot_id"] as? String == bootID,
                      number(acknowledgement["event_count"]) == eventCount,
                      number(acknowledgement["rejected_events"]) <= eventCount
                else {
                    throw NSError(
                        domain: "ai.gensee.crate.endpoint-security",
                        code: 5,
                        userInfo: [NSLocalizedDescriptionKey: "Endpoint Security ingester returned a mismatched durability acknowledgement."]
                    )
                }
                health.persistedEvents += number(acknowledgement["persisted_events"])
                health.suppressedEvents += number(acknowledgement["suppressed_events"])
                health.prunedSystemEvents += number(acknowledgement["pruned_system_events"])
                health.prunedLowSeverityAlerts += number(acknowledgement["pruned_low_severity_alerts"])
                health.lastBatchDurationMS = number(acknowledgement["ingest_duration_ms"])
                return number(acknowledgement["rejected_events"])
            }
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw EndpointIngestAcknowledgementIO.timeoutError() }
            let data = try await Task.detached(priority: .utility) {
                try EndpointIngestAcknowledgementIO.readChunk(from: handle, timeout: remaining)
            }.value
            guard !data.isEmpty else {
                throw NSError(
                    domain: "ai.gensee.crate.endpoint-security",
                    code: 6,
                    userInfo: [NSLocalizedDescriptionKey: "Endpoint Security ingester stopped before confirming durable storage."]
                )
            }
            ingestAcknowledgementBuffer.append(data)
        }
    }

    private func stopIngester() {
        let process = ingestProcess
        let input = ingestInput
        let acknowledgements = ingestAcknowledgements
        ingestProcess = nil
        ingestInput = nil
        ingestAcknowledgements = nil
        try? input?.close()
        try? acknowledgements?.close()
        guard let process, process.isRunning else { return }
        let processIdentifier = process.processIdentifier
        process.terminate()
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.2) {
            if process.isRunning {
                Darwin.kill(processIdentifier, SIGKILL)
            }
        }
    }

    private func nextAcknowledgementLine() -> Data? {
        guard let newline = ingestAcknowledgementBuffer.firstIndex(of: 0x0A) else { return nil }
        let line = ingestAcknowledgementBuffer[..<newline]
        ingestAcknowledgementBuffer.removeSubrange(...newline)
        return Data(line)
    }

    private func appendIngesterError(_ data: Data) {
        guard !data.isEmpty else { return }
        ingestErrorBuffer.append(data)
        let maximumBytes = 64 * 1024
        if ingestErrorBuffer.count > maximumBytes {
            ingestErrorBuffer.removeFirst(ingestErrorBuffer.count - maximumBytes)
        }
    }

    private func number(_ value: Any?) -> UInt64 {
        (value as? NSNumber)?.uint64Value ?? 0
    }
}

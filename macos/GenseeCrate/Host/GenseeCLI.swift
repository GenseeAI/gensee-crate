import Foundation

struct GenseeCommandOutput: Sendable {
    let stdout: String
    let stderr: String
    let exitCode: Int32
}

enum GenseeCLIError: LocalizedError {
    case executableNotFound
    case commandFailed(arguments: [String], output: String, exitCode: Int32)
    case commandTerminated(arguments: [String], signal: Int32)
    case invalidOutput(String)

    var errorDescription: String? {
        switch self {
        case .executableNotFound:
            return "The Gensee backend could not be found. Rebuild the app or choose an installed gensee binary."
        case let .commandFailed(arguments, output, exitCode):
            let command = (["gensee"] + arguments).joined(separator: " ")
            let detail = output.trimmingCharacters(in: .whitespacesAndNewlines)
            return detail.isEmpty
                ? "\(command) failed (exit \(exitCode)) without diagnostic output."
                : "\(command) failed (exit \(exitCode)): \(detail)"
        case let .commandTerminated(arguments, signal):
            let command = (["gensee"] + arguments).joined(separator: " ")
            return "\(command) was terminated by signal \(signal)."
        case let .invalidOutput(message):
            return message
        }
    }
}

struct GenseeCLI: Sendable {
    let executableURL: URL?
    let homeURL: URL

    init(homeURL: URL) {
        self.homeURL = homeURL
        self.executableURL = Self.resolveExecutable()
    }

    static func resolveExecutable() -> URL? {
        let manager = FileManager.default
        var candidates: [URL] = []

        if let bundled = Bundle.main.url(forResource: "gensee", withExtension: nil, subdirectory: "bin") {
            candidates.append(bundled)
        }
        if let configured = UserDefaults.standard.string(forKey: "gensee.backend.path"), !configured.isEmpty {
            candidates.append(URL(fileURLWithPath: configured))
        }
        if let environmentPath = ProcessInfo.processInfo.environment["GENSEE_BIN"], !environmentPath.isEmpty {
            candidates.append(URL(fileURLWithPath: environmentPath))
        }

        let home = manager.homeDirectoryForCurrentUser
        candidates.append(contentsOf: [
            URL(fileURLWithPath: "/opt/homebrew/bin/gensee"),
            URL(fileURLWithPath: "/usr/local/bin/gensee"),
            home.appendingPathComponent(".cargo/bin/gensee"),
        ])

        return candidates.first { manager.isExecutableFile(atPath: $0.path) }
    }

    func preferredHookExecutableURL() -> URL? {
        guard let executableURL else { return nil }
        guard executableURL.path.contains(".app/Contents/") else { return executableURL }
        let stableURL = homeURL.appendingPathComponent("bin/gensee")
        let manager = FileManager.default
        let stableIsCurrent = Self.installedCopyMatches(
            source: executableURL,
            destination: stableURL,
            manager: manager
        )
        return stableIsCurrent ? stableURL : executableURL
    }

    /// Hook files outlive individual app builds, so never point them into an
    /// application bundle that may be replaced during an update.
    func stableHookExecutableURL() async throws -> URL {
        guard let executableURL else { throw GenseeCLIError.executableNotFound }
        guard executableURL.path.contains(".app/Contents/") else { return executableURL }
        let homeURL = homeURL
        return try await Task.detached(priority: .utility) {
            let manager = FileManager.default
            let binDirectory = homeURL.appendingPathComponent("bin", isDirectory: true)
            let destination = binDirectory.appendingPathComponent("gensee")
            try manager.createDirectory(at: binDirectory, withIntermediateDirectories: true)

            if Self.installedCopyMatches(
                source: executableURL,
                destination: destination,
                manager: manager
            ) {
                return destination
            }

            let staging = binDirectory.appendingPathComponent(".gensee-\(UUID().uuidString).tmp")
            try manager.copyItem(at: executableURL, to: staging)
            do {
                try manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: staging.path)
                if manager.fileExists(atPath: destination.path) {
                    _ = try manager.replaceItemAt(destination, withItemAt: staging)
                } else {
                    try manager.moveItem(at: staging, to: destination)
                }
            } catch {
                try? manager.removeItem(at: staging)
                throw error
            }
            return destination
        }.value
    }

    private static func installedCopyMatches(
        source: URL,
        destination: URL,
        manager: FileManager
    ) -> Bool {
        guard manager.isExecutableFile(atPath: destination.path) else { return false }
        let keys: Set<URLResourceKey> = [.fileSizeKey, .contentModificationDateKey]
        guard let sourceValues = try? source.resourceValues(forKeys: keys),
              let destinationValues = try? destination.resourceValues(forKeys: keys)
        else {
            return manager.contentsEqual(atPath: source.path, andPath: destination.path)
        }
        guard sourceValues.fileSize == destinationValues.fileSize else { return false }
        if sourceValues.contentModificationDate == destinationValues.contentModificationDate {
            return true
        }
        return manager.contentsEqual(atPath: source.path, andPath: destination.path)
    }

    func run(_ arguments: [String]) async throws -> GenseeCommandOutput {
        try await run(arguments, acceptingExitCodes: [0])
    }

    func run(
        _ arguments: [String],
        acceptingExitCodes: Set<Int32>
    ) async throws -> GenseeCommandOutput {
        guard let executableURL else { throw GenseeCLIError.executableNotFound }
        let homeURL = homeURL

        return try await Task.detached(priority: .userInitiated) {
            let process = Process()
            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            process.executableURL = executableURL
            process.arguments = arguments
            process.standardOutput = stdoutPipe
            process.standardError = stderrPipe

            var environment = ProcessInfo.processInfo.environment
            environment["GENSEE_HOME"] = homeURL.path
            environment["PATH"] = [
                "/opt/homebrew/bin",
                "/usr/local/bin",
                FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".cargo/bin").path,
                environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin",
            ].joined(separator: ":")
            process.environment = environment

            try process.run()
            let stdoutTask = Task.detached {
                stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            }
            let stderrTask = Task.detached {
                stderrPipe.fileHandleForReading.readDataToEndOfFile()
            }
            let stdout = await stdoutTask.value
            let stderr = await stderrTask.value
            process.waitUntilExit()

            let result = GenseeCommandOutput(
                stdout: String(decoding: stdout, as: UTF8.self),
                stderr: String(decoding: stderr, as: UTF8.self),
                exitCode: process.terminationStatus
            )
            guard acceptingExitCodes.contains(result.exitCode) else {
                if process.terminationReason == .uncaughtSignal {
                    throw GenseeCLIError.commandTerminated(
                        arguments: arguments,
                        signal: process.terminationStatus
                    )
                }
                let output = result.stderr.isEmpty ? result.stdout : result.stderr
                throw GenseeCLIError.commandFailed(
                    arguments: arguments,
                    output: output,
                    exitCode: result.exitCode
                )
            }
            return result
        }.value
    }

    func decode<T: Decodable>(_ type: T.Type, arguments: [String]) async throws -> T {
        try await decode(type, arguments: arguments, acceptingExitCodes: [0])
    }

    func decode<T: Decodable>(
        _ type: T.Type,
        arguments: [String],
        acceptingExitCodes: Set<Int32>
    ) async throws -> T {
        let output = try await run(arguments, acceptingExitCodes: acceptingExitCodes)
        guard let data = output.stdout.data(using: .utf8) else {
            throw GenseeCLIError.invalidOutput("The Gensee backend returned non-UTF-8 output.")
        }
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw GenseeCLIError.invalidOutput("The Gensee backend returned unexpected data: \(error.localizedDescription)")
        }
    }
}

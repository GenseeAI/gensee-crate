import AppKit
import Foundation

@MainActor
final class ConsoleModel: ObservableObject {
    @Published private(set) var snapshot = SecuritySnapshot()
    @Published private(set) var runs = RunListResponse()
    @Published private(set) var policy = PolicySummary()
    @Published private(set) var policyDocument = ""
    @Published private(set) var integrations: [IntegrationDescriptor] = []
    @Published private(set) var isRefreshing = false
    @Published private(set) var runningCommand: String?
    @Published private(set) var lastUpdated: Date?
    @Published var errorMessage: String?
    @Published var noticeMessage: String?

    let homeURL: URL
    let endpointSensor: EndpointSecuritySensor
    private var cli: GenseeCLI

    init() {
        let environmentHome = ProcessInfo.processInfo.environment["GENSEE_HOME"]
        let resolvedHome = environmentHome.map(URL.init(fileURLWithPath:))
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gensee")
        homeURL = resolvedHome
        cli = GenseeCLI(homeURL: resolvedHome)
        endpointSensor = EndpointSecuritySensor(homeURL: resolvedHome, executableURL: cli.executableURL)
        refreshIntegrations()
    }

    var backendPath: String? { cli.executableURL?.path }
    var backendAvailable: Bool { cli.executableURL != nil }
    var databaseURL: URL { homeURL.appendingPathComponent("gensee.db") }
    var databaseExists: Bool { FileManager.default.fileExists(atPath: databaseURL.path) }
    var databaseEncrypted: Bool {
        guard let handle = try? FileHandle(forReadingFrom: databaseURL) else { return false }
        defer { try? handle.close() }
        let header = try? handle.read(upToCount: 16)
        return header != Data("SQLite format 3\0".utf8)
    }

    var activeRunCount: Int {
        runs.sessions.filter(\.isActive).count
            + runs.tcloneRuns.filter { $0.status == "running" || $0.status == "active" }.count
    }

    var highRiskAlertCount: Int {
        snapshot.alerts.filter { ["high", "critical"].contains($0.severity.lowercased()) }.count
    }

    var riskyArtifactCount: Int {
        snapshot.artifacts.filter { $0.riskLevel != nil || $0.isControlPlane != 0 }.count
    }

    var recentActivity: [ActivityItem] {
        let agent = snapshot.agentEvents.map {
            ActivityItem(
                id: $0.id,
                kind: .agent,
                timestamp: $0.timestamp,
                title: $0.toolName ?? $0.type.replacingOccurrences(of: "_", with: " ").capitalized,
                detail: $0.cwd,
                source: $0.source
            )
        }
        let system = snapshot.systemEvents.map {
            ActivityItem(
                id: $0.id,
                kind: .system,
                timestamp: $0.timestamp,
                title: $0.type.replacingOccurrences(of: "_", with: " ").capitalized,
                detail: Self.eventDetail(args: $0.args, fallback: $0.cwd),
                source: "PID \($0.pid)"
            )
        }
        return (agent + system).sorted { $0.timestamp > $1.timestamp }
    }

    func refreshAll() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        cli = GenseeCLI(homeURL: homeURL)
        refreshIntegrations()

        guard backendAvailable else {
            errorMessage = GenseeCLIError.executableNotFound.localizedDescription
            return
        }

        await refreshDashboard()

        do {
            runs = try await cli.decode(RunListResponse.self, arguments: ["run", "list", "--json"])
        } catch {
            errorMessage = error.localizedDescription
        }

        await refreshPolicy()
        lastUpdated = Date()
    }

    func refreshPolicy() async {
        guard backendAvailable else { return }
        var next = policy
        do {
            next.source = try await cli.run(["policy", "path"]).stdout
                .trimmingCharacters(in: .whitespacesAndNewlines)
            next.systemEvents = try await policyString("watch.system_events") ?? next.systemEvents
            next.endpointSecurityMode = try await policyString("endpoint_security.mode") ?? next.endpointSecurityMode
            next.noninteractive = try await policyBool("enforcement.noninteractive") ?? next.noninteractive
            next.requireProxy = try await policyBool("egress.require_proxy") ?? next.requireProxy
            next.maxRuntimeSeconds = try await policyInt("runtime.max_runtime_seconds")
            policy = next
            policyDocument = try await loadPolicyDocument()
            configureEndpointSensor()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func refreshDashboard() async {
        guard backendAvailable else { return }
        do {
            snapshot = try await cli.decode(SecuritySnapshot.self, arguments: ["dashboard-state"])
            configureEndpointSensor()
            lastUpdated = Date()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func savePolicyDocument(_ text: String) async -> Bool {
        runningCommand = "Validating policy"
        defer { runningCommand = nil }
        do {
            let parsed = try JSONSerialization.jsonObject(with: Data(text.utf8))
            let canonical = try JSONSerialization.data(withJSONObject: parsed, options: [.prettyPrinted, .sortedKeys])
            let temporary = FileManager.default.temporaryDirectory
                .appendingPathComponent("gensee-policy-\(UUID().uuidString).json")
            try canonical.write(to: temporary, options: .atomic)
            defer { try? FileManager.default.removeItem(at: temporary) }
            _ = try await cli.run(["policy", "validate", temporary.path])
            try FileManager.default.createDirectory(at: homeURL, withIntermediateDirectories: true)
            let destination = homeURL.appendingPathComponent("policy.json")
            try canonical.write(to: destination, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
            policyDocument = String(decoding: canonical, as: UTF8.self)
            noticeMessage = "Policy saved and validated."
            await refreshPolicy()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func recordFeedback(verdict: String, action: String, ruleID: String, path: String, note: String) async -> Bool {
        runningCommand = "Recording verdict"
        defer { runningCommand = nil }
        var arguments = ["feedback", "record", "--verdict", verdict]
        if !action.isEmpty { arguments += ["--gensee", action] }
        if !ruleID.isEmpty { arguments += ["--rule", ruleID] }
        if !path.isEmpty { arguments += ["--path", path] }
        if !note.isEmpty { arguments += ["--note", note] }
        do {
            let output = try await cli.run(arguments)
            noticeMessage = output.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            await refreshDashboard()
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func setPolicy(key: String, value: String) async {
        runningCommand = "Updating policy"
        defer { runningCommand = nil }
        do {
            let output = try await cli.run(["policy", "set", key, value])
            noticeMessage = output.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            await refreshPolicy()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func configureIntegration(_ provider: String) async {
        runningCommand = "Configuring \(provider)"
        defer { runningCommand = nil }
        do {
            let output = try await cli.run(["setup", provider, "--gensee-home", homeURL.path])
            noticeMessage = output.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            refreshIntegrations()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func openFullDiskAccess() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") else { return }
        NSWorkspace.shared.open(url)
    }

    func revealDataStore() {
        NSWorkspace.shared.activateFileViewerSelecting([homeURL])
    }

    private func policyJSON(_ key: String) async throws -> Any? {
        let output = try await cli.run(["policy", "get", key])
        guard let data = output.stdout.data(using: .utf8) else { return nil }
        return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }

    private func policyBool(_ key: String) async throws -> Bool? {
        try await policyJSON(key) as? Bool
    }

    private func policyString(_ key: String) async throws -> String? {
        try await policyJSON(key) as? String
    }

    private func policyInt(_ key: String) async throws -> Int? {
        if let number = try await policyJSON(key) as? NSNumber { return number.intValue }
        return nil
    }

    private func loadPolicyDocument() async throws -> String {
        let userPolicy = homeURL.appendingPathComponent("policy.json")
        if FileManager.default.fileExists(atPath: userPolicy.path) {
            return try String(contentsOf: userPolicy, encoding: .utf8)
        }
        return try await cli.run(["policy", "print-default"]).stdout
    }

    private func refreshIntegrations() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let definitions = [
            ("codex", "Codex", "Policy decisions before tools run", ".codex/hooks.json"),
            ("claude-code", "Claude Code", "Prompt, tool, and permission hooks", ".claude/settings.json"),
            ("cursor", "Cursor", "Native agent hook coverage", ".cursor/hooks.json"),
            ("vscode", "VS Code / Copilot", "Workspace and tool activity", ".copilot/hooks/gensee.json"),
            ("antigravity", "Antigravity", "Global agent hook coverage", ".gemini/config/hooks.json"),
        ]
        integrations = definitions.map { provider, name, detail, relativePath in
            let path = home.appendingPathComponent(relativePath)
            let contents = (try? String(contentsOf: path, encoding: .utf8)) ?? ""
            return IntegrationDescriptor(
                id: provider,
                name: name,
                detail: detail,
                configPath: path.path,
                configured: contents.localizedCaseInsensitiveContains("gensee")
            )
        }
    }

    private func configureEndpointSensor() {
        let userHome = FileManager.default.homeDirectoryForCurrentUser
        var protectedPaths = [homeURL.path]
        protectedPaths += [".ssh", ".aws", ".kube", ".config/gcloud"]
            .map { userHome.appendingPathComponent($0).path }
        var blockedExecutables: [String] = []
        if let data = policyDocument.data(using: .utf8),
           let document = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let endpoint = document["endpoint_security"] as? [String: Any]
        {
            protectedPaths += endpoint["protected_paths"] as? [String] ?? []
            blockedExecutables = endpoint["blocked_executables"] as? [String] ?? []
        }
        let roots = snapshot.jsonSessions
            .filter { $0.isActive && $0.rootPID != 0 }
            .map { ["pid": $0.rootPID, "session_id": $0.sessionID] as [String: Any] }
        endpointSensor.updateConfiguration(
            mode: policy.endpointSecurityMode,
            protectedPaths: Array(Set(protectedPaths)).sorted(),
            blockedExecutables: blockedExecutables,
            managedRoots: roots
        )
    }

    private static func eventDetail(args: String?, fallback: String) -> String {
        guard let args, !args.isEmpty else { return fallback }
        guard let data = args.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return fallback }
        if let file = object["file"] as? [String: Any], let path = file["path"] as? String, !path.isEmpty {
            return path
        }
        if let target = object["target"] as? [String: Any],
           let path = target["executable_path"] as? String,
           !path.isEmpty
        {
            return path
        }
        for key in ["path", "target_path", "process", "executable"] {
            if let value = object[key] as? String, !value.isEmpty { return value }
        }
        return fallback
    }
}

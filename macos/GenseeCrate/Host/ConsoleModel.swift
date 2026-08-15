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

    func setIntegrationEnabled(_ provider: String, enabled: Bool) async {
        guard let index = integrations.firstIndex(where: { $0.id == provider }) else { return }
        let integration = integrations[index]
        guard integration.canToggle else { return }
        guard backendAvailable else {
            errorMessage = GenseeCLIError.executableNotFound.localizedDescription
            return
        }

        let previousValue = integration.configured
        integrations[index].configured = enabled
        runningCommand = "\(enabled ? "Enabling" : "Disabling") \(integration.name) protection"
        defer { runningCommand = nil }
        do {
            var arguments = ["setup", provider]
            if enabled {
                arguments += ["--gensee-home", homeURL.path]
            } else {
                arguments.append("--disable")
            }
            let output = try await cli.run(arguments)
            noticeMessage = output.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            refreshIntegrations()
        } catch {
            if let currentIndex = integrations.firstIndex(where: { $0.id == provider }) {
                integrations[currentIndex].configured = previousValue
            }
            errorMessage = error.localizedDescription
        }
    }

    func refreshHarnesses() {
        refreshIntegrations()
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
        let codexInstalled = Self.applicationInstalled(
            names: ["Codex"],
            bundleIdentifiers: ["com.openai.codex"]
        ) || Self.executableInstalled(names: ["codex"])
        let claudeInstalled = Self.executableInstalled(
            names: ["claude"],
            additionalPaths: [home.appendingPathComponent(".claude/local/claude").path]
        )
        let cursorInstalled = Self.applicationInstalled(
            names: ["Cursor"],
            bundleIdentifiers: ["com.todesktop.230313mzl4w4u92"]
        ) || Self.executableInstalled(names: ["cursor"])
        let antigravityInstalled = Self.applicationInstalled(
            names: ["Antigravity"],
            bundleIdentifiers: []
        ) || Self.executableInstalled(names: ["antigravity"])
        let copilotInstalled = Self.githubCopilotInstalled(home: home)
        let omnigentInstalled = Self.executableInstalled(names: ["omnigent"])

        let definitions: [(String, String, String, String, String, Bool, Bool, String)] = [
            (
                "codex", "Codex", "Prompt, tool, permission, and lifecycle policy hooks",
                ".codex/hooks.json", "chevron.left.forwardslash.chevron.right", codexInstalled, true,
                codexInstalled ? "Codex is available on this Mac." : "Codex app or command was not found."
            ),
            (
                "claude-code", "Claude Code", "Prompt, tool, permission, and lifecycle policy hooks",
                ".claude/settings.json", "terminal", claudeInstalled, true,
                claudeInstalled ? "Claude Code is available on this Mac." : "The claude command was not found."
            ),
            (
                "antigravity", "Antigravity", "Global pre-invocation and tool policy hooks",
                ".gemini/config/hooks.json", "sparkles", antigravityInstalled, true,
                antigravityInstalled ? "Antigravity is available on this Mac." : "Antigravity app or command was not found."
            ),
            (
                "cursor", "Cursor", "Prompt, shell, tool, and lifecycle policy hooks",
                ".cursor/hooks.json", "cursorarrow.rays", cursorInstalled, true,
                cursorInstalled ? "Cursor is available on this Mac." : "Cursor app or command was not found."
            ),
            (
                "vscode", "GitHub Copilot", "VS Code prompt, tool, and lifecycle policy hooks",
                ".copilot/hooks/gensee.json", "shippingbox", copilotInstalled, true,
                copilotInstalled ? "GitHub Copilot for VS Code is available on this Mac." : "The GitHub Copilot VS Code extension was not found."
            ),
            (
                "omnigent", "Omnigent", "Endpoint visibility through a Gensee-managed launch",
                ".omnigent", "point.3.connected.trianglepath.dotted", omnigentInstalled, false,
                omnigentInstalled ? "Run Omnigent with gensee run for managed-tree monitoring and enforcement." : "The omnigent command was not found."
            ),
        ]
        integrations = definitions.map { provider, name, detail, relativePath, symbol, installed, supportsDirectHooks, installationDetail in
            let path = home.appendingPathComponent(relativePath)
            let contents = (try? String(contentsOf: path, encoding: .utf8)) ?? ""
            let configured = contents.localizedCaseInsensitiveContains("hook \(provider)")
                && contents.localizedCaseInsensitiveContains("gensee")
            let configurationIssue: String?
            if provider == "claude-code", configured, Self.claudeHooksDisabled(contents) {
                configurationIssue = "Claude Code has disableAllHooks enabled. Turn it off in settings before relying on protection."
            } else {
                configurationIssue = nil
            }
            return IntegrationDescriptor(
                id: provider,
                name: name,
                detail: detail,
                configPath: path.path,
                symbolName: symbol,
                installed: installed,
                supportsDirectHooks: supportsDirectHooks,
                installationDetail: installationDetail,
                configurationIssue: configurationIssue,
                configured: configured
            )
        }
    }

    private static func applicationInstalled(names: [String], bundleIdentifiers: [String]) -> Bool {
        if bundleIdentifiers.contains(where: { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }) {
            return true
        }
        let homeApplications = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications")
        return names.contains { name in
            FileManager.default.fileExists(atPath: "/Applications/\(name).app")
                || FileManager.default.fileExists(atPath: homeApplications.appendingPathComponent("\(name).app").path)
        }
    }

    private static func executableInstalled(names: [String], additionalPaths: [String] = []) -> Bool {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let standardDirectories = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            home.appendingPathComponent(".local/bin").path,
            home.appendingPathComponent(".cargo/bin").path,
            home.appendingPathComponent("bin").path,
        ]
        let pathDirectories = (ProcessInfo.processInfo.environment["PATH"] ?? "")
            .split(separator: ":")
            .map(String.init)
        let candidates = additionalPaths + (standardDirectories + pathDirectories).flatMap { directory in
            names.map { URL(fileURLWithPath: directory).appendingPathComponent($0).path }
        }
        return candidates.contains { FileManager.default.isExecutableFile(atPath: $0) }
    }

    private static func githubCopilotInstalled(home: URL) -> Bool {
        let vscodeInstalled = applicationInstalled(
            names: ["Visual Studio Code", "Visual Studio Code - Insiders"],
            bundleIdentifiers: ["com.microsoft.VSCode", "com.microsoft.VSCodeInsiders"]
        ) || executableInstalled(names: ["code", "code-insiders"])
        guard vscodeInstalled else { return false }
        let extensionRoots = [
            home.appendingPathComponent(".vscode/extensions"),
            home.appendingPathComponent(".vscode-insiders/extensions"),
        ]
        return extensionRoots.contains { root in
            let entries = (try? FileManager.default.contentsOfDirectory(atPath: root.path)) ?? []
            return entries.contains { $0.lowercased().hasPrefix("github.copilot-") }
        }
    }

    private static func claudeHooksDisabled(_ contents: String) -> Bool {
        guard let data = contents.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return false }
        return root["disableAllHooks"] as? Bool == true
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

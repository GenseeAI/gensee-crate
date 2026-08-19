import AppKit
import Foundation

@MainActor
final class ConsoleModel: ObservableObject {
    @Published private(set) var snapshot = SecuritySnapshot()
    @Published private(set) var runs = RunListResponse()
    @Published private(set) var policy = PolicySummary()
    @Published private(set) var policyDocument = ""
    @Published private(set) var integrations: [IntegrationDescriptor] = []
    @Published private(set) var dailyDetail: DailyDetail?
    @Published private(set) var dailyDetailLoadState = DailyDetailLoadState.idle
    @Published private(set) var configAudit: ConfigAuditBundle?
    @Published private(set) var auditedIntegrationIDs: Set<String> = []
    @Published private(set) var verifiedIntegrationIDs: Set<String> = []
    @Published private(set) var checkpoints: [WorkspaceCheckpointRecord] = []
    @Published private(set) var checkpointWorkspace: String?
    @Published private(set) var isRefreshing = false
    @Published private(set) var runningCommand: String?
    @Published private(set) var feedbackAlertID: Int64?
    @Published private(set) var readAlertIDs: Set<Int64> = []
    @Published private(set) var lastUpdated: Date?
    @Published private(set) var dashboardRefreshIssue: String?
    @Published private(set) var isDemoMode = false
    @Published var errorMessage: String?
    @Published var noticeMessage: String?

    let homeURL: URL
    let endpointSensor: EndpointSecuritySensor
    private var cli: GenseeCLI
    private var dashboardRefreshInProgress = false
    private var readAlertBaselineCount = 0
    private var readThroughAlertID: Int64 = 0
    private var harnessVerificationBaselines: [String: Int64] = [:]
    private var hasLoadedDashboardSnapshot = false
    private var snapshotBeforeDemo = SecuritySnapshot()

    init() {
        let environmentHome = ProcessInfo.processInfo.environment["GENSEE_HOME"]
        let resolvedHome = environmentHome.map(URL.init(fileURLWithPath:))
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gensee")
        homeURL = resolvedHome
        cli = GenseeCLI(homeURL: resolvedHome)
        endpointSensor = EndpointSecuritySensor(homeURL: resolvedHome, executableURL: cli.executableURL)
        auditedIntegrationIDs = Self.loadAuditedIntegrationIDs(homeURL: resolvedHome)
        verifiedIntegrationIDs = Self.loadVerifiedIntegrationIDs(homeURL: resolvedHome)
        harnessVerificationBaselines = Self.loadHarnessVerificationBaselines(homeURL: resolvedHome)
        readAlertIDs = Self.loadReadAlertIDs(homeURL: resolvedHome)
        readAlertBaselineCount = UserDefaults.standard.integer(
            forKey: Self.readAlertsBaselineKey(homeURL: resolvedHome)
        )
        readThroughAlertID = Int64(UserDefaults.standard.integer(
            forKey: Self.readAlertsWatermarkKey(homeURL: resolvedHome)
        ))
        refreshIntegrations()
        Task { [weak self] in await self?.refreshIntegrationsWithCurrentBackend() }
    }

    var backendPath: String? { cli.executableURL?.path }
    var backendAvailable: Bool { cli.executableURL != nil }
    var databaseURL: URL { homeURL.appendingPathComponent("gensee.db") }
    var policyURL: URL { homeURL.appendingPathComponent("policy.json") }
    var databaseExists: Bool { FileManager.default.fileExists(atPath: databaseURL.path) }
    var policyExists: Bool { FileManager.default.fileExists(atPath: policyURL.path) }
    var stableBackendInstalled: Bool {
        FileManager.default.isExecutableFile(
            atPath: homeURL.appendingPathComponent("bin/gensee").path
        )
    }
    var localRuntimePrepared: Bool { stableBackendInstalled && databaseExists && policyExists }
    var protectionLevel: ProtectionLevel {
        ProtectionLevel.current(
            endpointMode: policy.endpointSecurityMode,
            noninteractive: policy.noninteractive
        )
    }
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

    var unreadAlertCount: Int {
        let baseline = min(readAlertBaselineCount, snapshot.summary.alertsCount)
        let individuallyRead = readAlertIDs.lazy.filter { $0 > self.readThroughAlertID }.count
        return max(0, snapshot.summary.alertsCount - baseline - individuallyRead)
    }

    func isAlertRead(_ alertID: Int64) -> Bool {
        alertID <= readThroughAlertID || readAlertIDs.contains(alertID)
    }

    func markAlertRead(_ alertID: Int64) {
        guard !isDemoMode else { return }
        guard !isAlertRead(alertID) else { return }
        var updated = readAlertIDs
        guard updated.insert(alertID).inserted else { return }
        readAlertIDs = updated
        persistReadAlertState()
    }

    func markAllAlertsRead() {
        guard !isDemoMode else { return }
        guard unreadAlertCount > 0 else { return }
        readAlertBaselineCount = snapshot.summary.alertsCount
        readThroughAlertID = max(readThroughAlertID, snapshot.alerts.map(\.alertID).max() ?? 0)
        readAlertIDs.removeAll()
        persistReadAlertState()
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
        guard !isDemoMode else {
            snapshot = DemoSnapshotFactory.make()
            lastUpdated = Date()
            return
        }
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        cli = GenseeCLI(homeURL: homeURL)
        await refreshIntegrationsWithCurrentBackend()

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
    }

    func refreshPolicy() async {
        guard !isDemoMode else { return }
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

    func refreshDashboard(reportErrors: Bool = true) async {
        guard !isDemoMode else { return }
        guard backendAvailable else { return }
        guard !dashboardRefreshInProgress else { return }
        dashboardRefreshInProgress = true
        defer { dashboardRefreshInProgress = false }
        do {
            let refreshedSnapshot = try await cli.decode(
                SecuritySnapshot.self,
                arguments: ["dashboard-state"],
                // Large experimental stores can legitimately take more than
                // twelve seconds to summarize. Keep a finite deadline so a
                // wedged backend is terminated and retried, while leaving
                // enough headroom above the observed healthy query time.
                timeout: 20
            )
            hasLoadedDashboardSnapshot = true
            reconcileReadAlertState(alertCount: refreshedSnapshot.summary.alertsCount)
            snapshot = refreshedSnapshot
            reconcileHarnessVerification()
            configureEndpointSensor()
            lastUpdated = Date()
            dashboardRefreshIssue = nil
        } catch {
            dashboardRefreshIssue = error.localizedDescription
            // Keep the last good snapshot visible, but always release the
            // in-progress guard so the next scheduled refresh can recover.
            if reportErrors, errorMessage == nil {
                errorMessage = error.localizedDescription
            }
        }
    }

    func refreshDailyDetail(day: String) async {
        if isDemoMode {
            dailyDetail = DemoSnapshotFactory.dailyDetail(for: day, snapshot: snapshot)
            dailyDetailLoadState = dailyDetail == nil
                ? .unavailable(day: day, message: "No synthetic activity is available for this day.")
                : .loaded(day)
            return
        }
        guard backendAvailable else {
            dailyDetailLoadState = .unavailable(
                day: day,
                message: "The Gensee backend is unavailable. Repair the app backend, then try again."
            )
            return
        }
        dailyDetailLoadState = .loading(day)
        do {
            let detail = try await cli.decode(DailyDetail.self, arguments: ["dashboard-day", day])
            guard !Task.isCancelled else { return }
            guard detail.date == day else {
                dailyDetailLoadState = .unavailable(
                    day: day,
                    message: "The backend returned daily details for \(detail.date) instead of \(day)."
                )
                return
            }
            dailyDetail = detail
            dailyDetailLoadState = .loaded(day)
        } catch {
            guard !Task.isCancelled else { return }
            dashboardRefreshIssue = error.localizedDescription
            dailyDetailLoadState = .unavailable(day: day, message: error.localizedDescription)
        }
    }

    func runConfigAudit(target: String, workspace: String) async {
        guard !isDemoMode else {
            noticeMessage = "Config Audit is read-only in the synthetic demo. Exit demo mode to audit this Mac."
            return
        }
        guard backendAvailable else {
            errorMessage = GenseeCLIError.executableNotFound.localizedDescription
            return
        }
        let expandedWorkspace = (workspace as NSString).expandingTildeInPath
        let workspaceURL = URL(fileURLWithPath: expandedWorkspace)
            .standardizedFileURL
            .resolvingSymlinksInPath()
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: workspaceURL.path, isDirectory: &isDirectory),
              isDirectory.boolValue
        else {
            errorMessage = "Choose an existing workspace directory before running Config Audit."
            return
        }

        configAudit = nil
        runningCommand = "Auditing \(target == "vscode" ? "VS Code" : "Codex") configuration"
        defer { runningCommand = nil }
        do {
            let audit = try await cli.decode(
                ConfigAuditBundle.self,
                arguments: ["audit", target, "--workspace", workspaceURL.path, "--json"],
                acceptingExitCodes: [0, 2]
            )
            configAudit = audit
            if let harnessID = audit.auditedHarnessID {
                auditedIntegrationIDs.insert(harnessID)
                persistAuditedIntegrationIDs()
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func loadCheckpoints(workspace: String, reportErrors: Bool = true) async {
        guard backendAvailable else {
            if reportErrors { errorMessage = GenseeCLIError.executableNotFound.localizedDescription }
            return
        }
        guard let workspaceURL = existingWorkspaceURL(workspace) else {
            checkpoints = []
            checkpointWorkspace = nil
            if reportErrors { errorMessage = "Choose an existing Git workspace to view recovery checkpoints." }
            return
        }
        do {
            let response = try await cli.decode(
                CheckpointListResponse.self,
                arguments: ["checkpoint", "list", "--workspace", workspaceURL.path, "--json"]
            )
            checkpoints = response.checkpoints
            checkpointWorkspace = response.workspace
        } catch {
            checkpoints = []
            checkpointWorkspace = nil
            if reportErrors { errorMessage = error.localizedDescription }
        }
    }

    func createCheckpoint(workspace: String, label: String) async {
        guard let workspaceURL = existingWorkspaceURL(workspace) else {
            errorMessage = "Choose an existing Git workspace before creating a checkpoint."
            return
        }
        runningCommand = "Creating a local recovery checkpoint"
        defer { runningCommand = nil }
        var arguments = ["checkpoint", "create", "--workspace", workspaceURL.path, "--json"]
        let trimmedLabel = label.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedLabel.isEmpty {
            arguments += ["--label", trimmedLabel]
        }
        do {
            let checkpoint = try await cli.decode(
                WorkspaceCheckpointRecord.self,
                arguments: arguments,
                timeout: 60
            )
            noticeMessage = "Checkpoint \(checkpoint.id) is ready."
            await loadCheckpoints(workspace: workspaceURL.path, reportErrors: false)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func restoreCheckpoint(_ checkpoint: WorkspaceCheckpointRecord, workspace: String) async {
        guard let workspaceURL = existingWorkspaceURL(workspace) else {
            errorMessage = "Choose the checkpoint's Git workspace before restoring it."
            return
        }
        runningCommand = "Restoring checkpoint and creating a rescue point"
        defer { runningCommand = nil }
        do {
            let response = try await cli.decode(
                CheckpointRestoreResponse.self,
                arguments: [
                    "checkpoint", "restore", checkpoint.id,
                    "--workspace", workspaceURL.path,
                    "--yes", "--json",
                ],
                timeout: 60
            )
            noticeMessage = "Restored \(response.restored.label ?? response.restored.id). Rescue checkpoint: \(response.rescue.id)."
            await loadCheckpoints(workspace: workspaceURL.path, reportErrors: false)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func existingWorkspaceURL(_ workspace: String) -> URL? {
        let expanded = (workspace as NSString).expandingTildeInPath
        let url = URL(fileURLWithPath: expanded)
            .standardizedFileURL
            .resolvingSymlinksInPath()
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
              isDirectory.boolValue
        else { return nil }
        return url
    }

    func savePolicyDocument(_ text: String) async -> Bool {
        guard !isDemoMode else {
            noticeMessage = "Synthetic demo mode never changes your policy."
            return false
        }
        runningCommand = "Validating policy"
        defer { runningCommand = nil }
        do {
            guard var parsed = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
                throw CocoaError(.propertyListReadCorrupt)
            }
            parsed["schema_version"] = 2
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

    func recordFeedback(for alert: SecurityAlert, agrees: Bool) async -> Bool {
        guard !isDemoMode else {
            noticeMessage = "Feedback is not stored for synthetic demo findings."
            return false
        }
        guard feedbackAlertID == nil else { return false }
        feedbackAlertID = alert.alertID
        defer { feedbackAlertID = nil }

        let action = alert.action.lowercased()
        let verdict = agrees
            ? "agree"
            : (["allow", "watch"].contains(action) ? "deny" : "allow")
        var arguments = [
            "feedback", "record",
            "--verdict", verdict,
            "--event-key", "alert:\(alert.alertID)",
            "--gensee", alert.action,
            "--rule", alert.ruleID,
        ]
        if let sessionID = alert.sessionID, !sessionID.isEmpty {
            arguments += ["--session", sessionID]
        }
        if let toolUseID = alert.toolUseID, !toolUseID.isEmpty {
            arguments += ["--tool-use-id", toolUseID]
        }
        if let path = alert.path, !path.isEmpty {
            arguments += ["--path", path]
        }
        do {
            _ = try await cli.run(arguments)
            await refreshDashboard(reportErrors: false)
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func setPolicy(key: String, value: String) async {
        guard !isDemoMode else {
            noticeMessage = "Synthetic demo mode never changes your policy."
            return
        }
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
        guard !isDemoMode else {
            noticeMessage = "Synthetic demo mode never installs or removes harness hooks."
            return
        }
        guard let index = integrations.firstIndex(where: { $0.id == provider }) else { return }
        let integration = integrations[index]
        guard integration.canToggle else { return }
        guard backendAvailable else {
            errorMessage = GenseeCLIError.executableNotFound.localizedDescription
            return
        }

        let previousValue = integration.configured
        let previousVerified = verifiedIntegrationIDs.contains(provider)
        let previousBaseline = harnessVerificationBaselines[provider]
        integrations[index].configured = enabled
        if enabled {
            beginHarnessVerification(provider)
        }
        runningCommand = "\(enabled ? "Enabling" : "Disabling") \(integration.name) protection"
        defer { runningCommand = nil }
        do {
            var arguments = ["setup", provider]
            if enabled {
                arguments += ["--gensee-home", homeURL.path]
                let hookExecutable = try await cli.stableHookExecutableURL()
                arguments += ["--bin", hookExecutable.path]
                if provider == "claude-code" {
                    arguments.append("--repair")
                }
            } else {
                arguments.append("--disable")
            }
            let output = try await cli.run(arguments)
            if !enabled {
                clearHarnessVerification(provider)
            }
            noticeMessage = output.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            await refreshIntegrationsWithCurrentBackend()
            configureEndpointSensor()
        } catch {
            if let currentIndex = integrations.firstIndex(where: { $0.id == provider }) {
                integrations[currentIndex].configured = previousValue
            }
            restoreHarnessVerification(
                provider,
                verified: previousVerified,
                baseline: previousBaseline
            )
            errorMessage = error.localizedDescription
        }
    }

    func repairIntegration(_ provider: String) async {
        guard !isDemoMode else {
            noticeMessage = "Synthetic demo mode never changes harness configuration."
            return
        }
        guard let integration = integrations.first(where: { $0.id == provider }),
              integration.canToggle,
              integration.requiresRepair
        else { return }
        guard backendAvailable else {
            errorMessage = GenseeCLIError.executableNotFound.localizedDescription
            return
        }

        runningCommand = "Repairing \(integration.name) protection"
        defer { runningCommand = nil }
        let previousVerified = verifiedIntegrationIDs.contains(provider)
        let previousBaseline = harnessVerificationBaselines[provider]
        do {
            beginHarnessVerification(provider)
            var arguments = ["setup", provider, "--gensee-home", homeURL.path]
            let configuredBackend = integration.configuredBackendPath.map(URL.init(fileURLWithPath:))
            let hookExecutable: URL
            if let configuredBackend,
               FileManager.default.isExecutableFile(atPath: configuredBackend.path)
            {
                hookExecutable = configuredBackend
            } else {
                hookExecutable = try await cli.stableHookExecutableURL()
            }
            arguments += ["--bin", hookExecutable.path]
            if provider == "claude-code" {
                arguments.append("--repair")
            }
            let output = try await cli.run(arguments)
            await refreshIntegrationsWithCurrentBackend()
            if let updated = integrations.first(where: { $0.id == provider }),
               let issue = updated.configurationIssue
            {
                errorMessage = "\(updated.name) still needs repair: \(issue)"
            } else {
                let detail = output.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
                noticeMessage = detail.isEmpty
                    ? "\(integration.name) protection was repaired."
                    : detail
            }
        } catch {
            restoreHarnessVerification(
                provider,
                verified: previousVerified,
                baseline: previousBaseline
            )
            await refreshIntegrationsWithCurrentBackend()
            errorMessage = error.localizedDescription
        }
    }

    func prepareLocalRuntime() async -> Bool {
        guard !isDemoMode else { return true }
        guard backendAvailable else {
            errorMessage = GenseeCLIError.executableNotFound.localizedDescription
            return false
        }

        runningCommand = "Preparing the local Gensee runtime"
        defer { runningCommand = nil }
        do {
            try FileManager.default.createDirectory(
                at: homeURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: homeURL.path
            )
            _ = try await cli.stableHookExecutableURL()
            if !policyExists {
                _ = try await cli.run(["policy", "init"])
            }
            if FileManager.default.fileExists(atPath: policyURL.path) {
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: policyURL.path
                )
            }
            let preparedSnapshot = try await cli.decode(
                SecuritySnapshot.self,
                arguments: ["dashboard-state"]
            )
            hasLoadedDashboardSnapshot = true
            snapshot = preparedSnapshot
            reconcileReadAlertState(alertCount: preparedSnapshot.summary.alertsCount)
            reconcileHarnessVerification()
            await refreshPolicy()
            await refreshIntegrationsWithCurrentBackend()
            noticeMessage = nil
            return localRuntimePrepared
        } catch {
            errorMessage = "Could not prepare the local Gensee runtime: \(error.localizedDescription)"
            return false
        }
    }

    func enableAllInstalledIntegrations() async {
        guard !isDemoMode else { return }
        let providers = integrations
            .filter { $0.installed && $0.supportsDirectHooks && !$0.isHealthy }
            .map(\.id)
        for provider in providers {
            guard let integration = integrations.first(where: { $0.id == provider }) else { continue }
            if integration.requiresRepair {
                await repairIntegration(provider)
            } else if !integration.configured {
                await setIntegrationEnabled(provider, enabled: true)
            }
        }
    }

    func refreshHarnesses() async {
        guard !isDemoMode else { return }
        await refreshIntegrationsWithCurrentBackend()
    }

    func enterDemoMode() {
        guard !isDemoMode else { return }
        snapshotBeforeDemo = snapshot
        snapshot = DemoSnapshotFactory.make()
        isDemoMode = true
        dashboardRefreshIssue = nil
        errorMessage = nil
        lastUpdated = Date()
    }

    func exitDemoMode() async {
        guard isDemoMode else { return }
        isDemoMode = false
        snapshot = snapshotBeforeDemo
        dailyDetail = nil
        dailyDetailLoadState = .idle
        await refreshAll()
    }

    func applyProtectionLevel(_ level: ProtectionLevel) async -> Bool {
        guard !isDemoMode else {
            noticeMessage = "Exit synthetic demo mode before changing protection."
            return false
        }
        if policyDocument.isEmpty {
            await refreshPolicy()
        }
        do {
            guard var root = try JSONSerialization.jsonObject(with: Data(policyDocument.utf8)) as? [String: Any] else {
                throw CocoaError(.propertyListReadCorrupt)
            }
            var endpoint = root["endpoint_security"] as? [String: Any] ?? [:]
            endpoint["mode"] = level.endpointMode
            root["endpoint_security"] = endpoint
            var enforcement = root["enforcement"] as? [String: Any] ?? [:]
            enforcement["noninteractive"] = level.noninteractive
            root["enforcement"] = enforcement
            let data = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
            guard let text = String(data: data, encoding: .utf8) else {
                throw CocoaError(.fileReadInapplicableStringEncoding)
            }
            let saved = await savePolicyDocument(text)
            if saved {
                noticeMessage = "Protection level set to \(level.title)."
            }
            return saved
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func openFullDiskAccess() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") else { return }
        NSWorkspace.shared.open(url)
    }

    func openPrivacyAndSecurity() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security") else { return }
        NSWorkspace.shared.open(url)
    }

    func openAutomationPrivacy() {
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Automation"
        ) else { return }
        NSWorkspace.shared.open(url)
    }

    func openCodexHookReview() {
        guard runningCommand == nil else { return }
        runningCommand = "Finding the installed Codex CLI"
        let candidates = Self.codexExecutableCandidates()
        Task { [weak self] in
            guard let self else { return }
            let codexURL = await Task.detached(priority: .userInitiated) {
                let manager = FileManager.default
                return CodexExecutableResolver.firstRunnable(candidates: candidates) { candidate in
                    manager.isExecutableFile(atPath: candidate.path)
                        && CodexExecutableResolver.respondsToVersionProbe(candidate)
                }
            }.value
            runningCommand = nil
            guard let codexURL else {
                errorMessage = "Gensee could not find a working Codex CLI. Install or update Codex, then run it and enter /hooks to review the Gensee hook."
                return
            }

            let shellCommand = CodexHookReviewScript.shellCommand(codexURL: codexURL)
            let appleScriptSource = CodexHookReviewLauncher.appleScriptSource(
                shellCommand: shellCommand
            )
            var executionError: NSDictionary?
            guard let appleScript = NSAppleScript(source: appleScriptSource),
                  appleScript.executeAndReturnError(&executionError) != nil
            else {
                if CodexHookReviewLauncher.isAutomationPermissionError(executionError) {
                    openAutomationPrivacy()
                    errorMessage = "Gensee Crate needs permission to control Terminal. In System Settings → Privacy & Security → Automation, allow Gensee Crate to use Terminal, then try again."
                    return
                }
                let detail = executionError?[NSAppleScript.errorMessage] as? String
                    ?? "Terminal could not start the review command."
                errorMessage = "Could not open Codex hook review: \(detail)"
                return
            }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("/hooks", forType: .string)
            noticeMessage = "Opened Codex CLI and copied /hooks. The review window closes automatically after Gensee hooks are trusted."
        }
    }

    func copyOmnigentManagedLaunch() {
        let command = "\(homeURL.appendingPathComponent("bin/gensee").path) run -- omnigent"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
        noticeMessage = "Copied the Omnigent managed-launch command. Add the arguments for the agent you want to run."
    }

    func revealDataStore() {
        NSWorkspace.shared.activateFileViewerSelecting([homeURL])
    }

    private func policyJSON(_ key: String) async throws -> Any? {
        let output = try await cli.run(["policy", "get", key])
        guard let data = output.stdout.data(using: .utf8) else { return nil }
        return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }

    private static func readAlertsKey(homeURL: URL) -> String {
        "gensee.alerts.read.\(homeURL.path)"
    }

    private static func auditedIntegrationsKey(homeURL: URL) -> String {
        "gensee.harnesses.audited.\(homeURL.path)"
    }

    private static func verifiedIntegrationsKey(homeURL: URL) -> String {
        "gensee.harnesses.verified.\(homeURL.path)"
    }

    private static func verificationBaselinesKey(homeURL: URL) -> String {
        "gensee.harnesses.verification-baselines.\(homeURL.path)"
    }

    private static func loadAuditedIntegrationIDs(homeURL: URL) -> Set<String> {
        let values = UserDefaults.standard.stringArray(
            forKey: auditedIntegrationsKey(homeURL: homeURL)
        ) ?? []
        return Set(values)
    }

    private static func loadVerifiedIntegrationIDs(homeURL: URL) -> Set<String> {
        let values = UserDefaults.standard.stringArray(
            forKey: verifiedIntegrationsKey(homeURL: homeURL)
        ) ?? []
        return Set(values)
    }

    private static func loadHarnessVerificationBaselines(homeURL: URL) -> [String: Int64] {
        let values = UserDefaults.standard.dictionary(
            forKey: verificationBaselinesKey(homeURL: homeURL)
        ) ?? [:]
        return values.reduce(into: [:]) { result, item in
            if let number = item.value as? NSNumber {
                result[item.key] = number.int64Value
            }
        }
    }

    private func persistAuditedIntegrationIDs() {
        UserDefaults.standard.set(
            auditedIntegrationIDs.sorted(),
            forKey: Self.auditedIntegrationsKey(homeURL: homeURL)
        )
    }

    private func persistHarnessVerification() {
        UserDefaults.standard.set(
            verifiedIntegrationIDs.sorted(),
            forKey: Self.verifiedIntegrationsKey(homeURL: homeURL)
        )
        UserDefaults.standard.set(
            harnessVerificationBaselines.mapValues(NSNumber.init(value:)),
            forKey: Self.verificationBaselinesKey(homeURL: homeURL)
        )
    }

    private func beginHarnessVerification(_ provider: String) {
        verifiedIntegrationIDs.remove(provider)
        harnessVerificationBaselines[provider] = Int64(Date().timeIntervalSince1970 * 1_000)
        persistHarnessVerification()
        refreshIntegrations()
    }

    private func clearHarnessVerification(_ provider: String) {
        verifiedIntegrationIDs.remove(provider)
        harnessVerificationBaselines.removeValue(forKey: provider)
        persistHarnessVerification()
        refreshIntegrations()
    }

    private func restoreHarnessVerification(
        _ provider: String,
        verified: Bool,
        baseline: Int64?
    ) {
        if verified {
            verifiedIntegrationIDs.insert(provider)
        } else {
            verifiedIntegrationIDs.remove(provider)
        }
        harnessVerificationBaselines[provider] = baseline
        persistHarnessVerification()
        refreshIntegrations()
    }

    private func reconcileHarnessVerification() {
        var changed = false
        let configuredProviders = Set(
            integrations
                .filter { $0.configurationHealthy && $0.supportsDirectHooks }
                .map(\.id)
        )

        for provider in Array(verifiedIntegrationIDs) where !configuredProviders.contains(provider) {
            verifiedIntegrationIDs.remove(provider)
            changed = true
        }

        for integration in integrations where configuredProviders.contains(integration.id) {
            let baseline: Int64
            if let existing = harnessVerificationBaselines[integration.id] {
                baseline = existing
            } else {
                baseline = HarnessActivationGuidance.configurationTimestampMS(path: integration.configPath)
                harnessVerificationBaselines[integration.id] = baseline
                changed = true
            }
            if !verifiedIntegrationIDs.contains(integration.id),
               snapshot.agentEvents.contains(where: {
                   $0.timestamp >= baseline
                       && HarnessActivationGuidance.eventMatches(
                           provider: integration.id,
                           source: $0.source
                       )
               })
            {
                verifiedIntegrationIDs.insert(integration.id)
                changed = true
            }
        }

        guard changed else { return }
        persistHarnessVerification()
        refreshIntegrations()
    }

    private static func readAlertsBaselineKey(homeURL: URL) -> String {
        "gensee.alerts.read-baseline.\(homeURL.path)"
    }

    private static func readAlertsWatermarkKey(homeURL: URL) -> String {
        "gensee.alerts.read-through.\(homeURL.path)"
    }

    private static func loadReadAlertIDs(homeURL: URL) -> Set<Int64> {
        let values = UserDefaults.standard.array(forKey: readAlertsKey(homeURL: homeURL)) as? [NSNumber] ?? []
        return Set(values.map(\.int64Value))
    }

    private func reconcileReadAlertState(alertCount: Int) {
        guard AlertReadState.storeWasReset(
            alertCount: alertCount,
            readAlertBaselineCount: readAlertBaselineCount
        ) else { return }
        readAlertBaselineCount = 0
        readThroughAlertID = 0
        readAlertIDs.removeAll()
        persistReadAlertState()
    }

    private func persistReadAlertState() {
        let retained = Array(readAlertIDs.sorted(by: >).prefix(5_000))
        readAlertIDs = Set(retained)
        UserDefaults.standard.set(
            retained.map(NSNumber.init(value:)),
            forKey: Self.readAlertsKey(homeURL: homeURL)
        )
        UserDefaults.standard.set(
            readAlertBaselineCount,
            forKey: Self.readAlertsBaselineKey(homeURL: homeURL)
        )
        UserDefaults.standard.set(
            readThroughAlertID,
            forKey: Self.readAlertsWatermarkKey(homeURL: homeURL)
        )
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

    private func refreshIntegrationsWithCurrentBackend() async {
        if cli.executableURL?.path.contains(".app/Contents/") == true {
            do {
                _ = try await cli.stableHookExecutableURL()
            } catch {
                errorMessage = "Could not refresh the stable Gensee hook backend: \(error.localizedDescription)"
            }
        }
        refreshIntegrations()
    }

    private func refreshIntegrations() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let preferredHookExecutable = cli.preferredHookExecutableURL()
        let codexInstalled = Self.applicationInstalled(
            names: ["Codex"],
            bundleIdentifiers: ["com.openai.codex"]
        ) || Self.executableInstalled(names: ["codex"])
        let claudeInstalled = Self.claudeCodeInstalled(home: home)
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
            let expectedCommand = preferredHookExecutable.map {
                HarnessConfigurationHealth.expectedCommand(
                    provider: provider,
                    homeURL: homeURL,
                    backendURL: $0
                )
            }
            let inspection = supportsDirectHooks
                ? HarnessConfigurationHealth.inspect(
                    provider: provider,
                    contents: contents,
                    expectedCommand: expectedCommand,
                    eventStorePath: homeURL.path
                )
                : HarnessConfigurationInspection(configured: false, issue: nil)
            return IntegrationDescriptor(
                id: provider,
                name: name,
                detail: detail,
                configPath: path.path,
                symbolName: symbol,
                installed: installed,
                supportsDirectHooks: supportsDirectHooks,
                installationDetail: installationDetail,
                configurationIssue: inspection.issue,
                configurationNote: inspection.note,
                canRepair: inspection.canRepair,
                configuredBackendPath: inspection.backendPath,
                configured: inspection.configured,
                verified: verifiedIntegrationIDs.contains(provider)
            )
        }
    }

    private static func codexExecutableCandidates() -> [URL] {
        let manager = FileManager.default
        let home = manager.homeDirectoryForCurrentUser
        let applicationURLs = ["com.openai.codex"].compactMap {
            NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0)
        }
        return CodexExecutableResolver.orderedCandidates(
            home: home,
            applicationURLs: applicationURLs
        )
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
        let manager = FileManager.default
        let applicationNames = ["Visual Studio Code", "Visual Studio Code - Insiders"]
        let bundleIdentifiers = ["com.microsoft.VSCode", "com.microsoft.VSCodeInsiders"]
        let applicationDirectories = [URL(fileURLWithPath: "/Applications"), home.appendingPathComponent("Applications")]
        var applicationURLs = bundleIdentifiers.compactMap {
            NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0)
        }
        applicationURLs += applicationDirectories.flatMap { directory in
            applicationNames.map { directory.appendingPathComponent("\($0).app") }
        }
        applicationURLs = applicationURLs.reduce(into: []) { result, candidate in
            guard manager.fileExists(atPath: candidate.path), !result.contains(candidate) else { return }
            result.append(candidate)
        }

        let vscodeInstalled = !applicationURLs.isEmpty || executableInstalled(names: ["code", "code-insiders"])
        guard vscodeInstalled else { return false }

        let extensionRoots = [
            home.appendingPathComponent(".vscode/extensions"),
            home.appendingPathComponent(".vscode-insiders/extensions"),
        ] + applicationURLs.map {
            $0.appendingPathComponent("Contents/Resources/app/extensions")
        }
        return extensionRoots.contains(where: copilotExtensionInstalled)
    }

    private static func claudeCodeInstalled(home: URL) -> Bool {
        if executableInstalled(
            names: ["claude"],
            additionalPaths: [home.appendingPathComponent(".claude/local/claude").path]
        ) {
            return true
        }
        if applicationInstalled(
            names: ["Claude Code"],
            bundleIdentifiers: ["com.anthropic.claude-code"]
        ) {
            return true
        }

        let managedRoot = home.appendingPathComponent("Library/Application Support/Claude/claude-code")
        let versions = (try? FileManager.default.contentsOfDirectory(
            at: managedRoot,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )) ?? []
        return versions.contains { versionURL in
            let bundleURL = versionURL.appendingPathComponent("claude.app")
            let infoURL = bundleURL.appendingPathComponent("Contents/Info.plist")
            let executableURL = bundleURL.appendingPathComponent("Contents/MacOS/claude")
            guard FileManager.default.isExecutableFile(atPath: executableURL.path),
                  let data = try? Data(contentsOf: infoURL),
                  let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let bundleIdentifier = info["CFBundleIdentifier"] as? String
            else { return false }
            return bundleIdentifier == "com.anthropic.claude-code"
        }
    }

    private static func copilotExtensionInstalled(in root: URL) -> Bool {
        let entries = (try? FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []
        return entries.contains { extensionURL in
            let manifestURL = extensionURL.appendingPathComponent("package.json")
            guard let data = try? Data(contentsOf: manifestURL),
                  let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let publisher = manifest["publisher"] as? String,
                  let name = manifest["name"] as? String
            else { return false }
            let normalizedName = name.lowercased()
            return publisher.caseInsensitiveCompare("github") == .orderedSame
                && (normalizedName == "copilot" || normalizedName == "copilot-chat")
        }
    }

    private func configureEndpointSensor() {
        // A failed dashboard query must not clear the system extension's
        // existing process roots. Without a validated snapshot, an empty
        // in-memory model means "unknown", not "no active sessions".
        guard hasLoadedDashboardSnapshot else { return }
        let userHome = FileManager.default.homeDirectoryForCurrentUser
        var protectedPaths = [".ssh", ".aws", ".kube", ".config/gcloud"]
            .map { userHome.appendingPathComponent($0).path }
        protectedPaths += [
            homeURL.appendingPathComponent("policy.json").standardizedFileURL.path,
            homeURL.appendingPathComponent("bin", isDirectory: true).standardizedFileURL.path,
        ]
        var blockedExecutables: [String] = []
        var maxAuthorizationLatencyMS: UInt64 = 10
        if let data = policyDocument.data(using: .utf8),
           let document = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let endpoint = document["endpoint_security"] as? [String: Any]
        {
            protectedPaths += endpoint["protected_paths"] as? [String] ?? []
            blockedExecutables = endpoint["blocked_executables"] as? [String] ?? []
            maxAuthorizationLatencyMS = (endpoint["max_auth_latency_ms"] as? NSNumber)?.uint64Value ?? 10
        }
        let enabledHarnesses = Set(integrations.lazy.filter(\.configured).map(\.id))
        let roots = snapshot.jsonSessions
            .filter {
                $0.isActive
                    && $0.rootPID != 0
                    && EndpointSessionScope.isEnabled($0, enabledHarnesses: enabledHarnesses)
            }
            .map { ["pid": $0.rootPID, "session_id": $0.sessionID] as [String: Any] }
        endpointSensor.updateConfiguration(
            mode: policy.endpointSecurityMode,
            protectedPaths: Array(Set(protectedPaths)).sorted(),
            blockedExecutables: blockedExecutables,
            managedRoots: roots,
            failClosedManagedOnly: true,
            maxAuthorizationLatencyMS: min(100, max(1, maxAuthorizationLatencyMS))
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

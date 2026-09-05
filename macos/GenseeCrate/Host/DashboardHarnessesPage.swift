import SwiftUI

struct DashboardHarnessesPage: View {
    @ObservedObject var model: ConsoleModel
    @State private var selectedAuditTarget: String?

    private let auditPanelID = "harness-config-audit"

    private var installedCount: Int {
        model.integrations.filter(\.installed).count
    }

    private var protectedCount: Int {
        model.integrations.filter { $0.installed && $0.isHealthy && $0.supportsDirectHooks }.count
    }

    private var hookCapableInstalledCount: Int {
        model.integrations.filter { $0.installed && $0.supportsDirectHooks }.count
    }

    private var auditCapableInstalledCount: Int {
        model.integrations.filter { $0.installed && configAuditTarget($0) != nil }.count
    }

    private var auditedCount: Int {
        model.integrations.filter {
            $0.installed
                && configAuditTarget($0) != nil
                && model.auditedIntegrationIDs.contains($0.id)
        }.count
    }

    var body: some View {
        ScrollViewReader { scrollProxy in
            DashboardPage {
                VStack(alignment: .leading, spacing: 16) {
                    DashboardPageHeader(
                        "Harnesses",
                        description: "Audit local agent configuration and manage Gensee protection from one place."
                    ) {
                        Button { Task { await model.refreshHarnesses() } } label: {
                            Label("Scan again", systemImage: "arrow.clockwise")
                        }
                        .controlSize(.small)
                    }

                    coverageSummary

                    DashboardCard("Harness protection") {
                        VStack(spacing: 0) {
                            ForEach(Array(model.integrations.enumerated()), id: \.element.id) { index, integration in
                                if integration.isCowork {
                                    CoworkHarnessRow(model: model, sensor: model.endpointSensor, integration: integration)
                                } else {
                                    harnessRow(integration)
                                }
                                if index < model.integrations.count - 1 {
                                    Divider().padding(.leading, 54)
                                }
                            }
                        }
                    }

                    HStack(alignment: .top, spacing: 9) {
                        Image(systemName: "info.circle")
                            .foregroundStyle(.secondary)
                        Text("Gensee verifies hook coverage, the active event-store path, the backend executable, and harness-specific blockers. Repair rewrites only Gensee-owned entries; unrelated settings and hooks are preserved. Omnigent currently requires a managed `gensee run` launch because it does not yet expose a first-class policy bridge.")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.horizontal, 4)

                    if let selectedAuditTarget {
                        HarnessConfigAuditPanel(
                            model: model,
                            target: selectedAuditTarget,
                            onClose: { self.selectedAuditTarget = nil }
                        )
                        .id(auditPanelID)
                        .transition(.opacity.combined(with: .move(edge: .bottom)))
                    }
                }
            }
            .onChange(of: selectedAuditTarget) { target in
                guard target != nil else { return }
                DispatchQueue.main.async {
                    withAnimation(.easeOut(duration: 0.22)) {
                        scrollProxy.scrollTo(auditPanelID, anchor: .top)
                    }
                }
            }
        }
    }

    private var coverageSummary: some View {
        HStack(spacing: 0) {
            summaryMetric(
                value: "\(protectedCount)",
                label: "Protected",
                detail: "of \(hookCapableInstalledCount) hook-capable",
                color: protectedCount == hookCapableInstalledCount && hookCapableInstalledCount > 0 ? .dashboardGreen : .dashboardGold
            )
            Rectangle().fill(Color.dashboardLine).frame(width: 1, height: 48)
            summaryMetric(
                value: "\(installedCount)",
                label: "Installed",
                detail: "of \(model.integrations.count) supported",
                color: .dashboardBlue
            )
            Rectangle().fill(Color.dashboardLine).frame(width: 1, height: 48)
            summaryMetric(
                value: "\(auditedCount)",
                label: "Audited",
                detail: "of \(auditCapableInstalledCount) audit-capable",
                color: auditedCount == auditCapableInstalledCount && auditCapableInstalledCount > 0
                    ? .dashboardGreen
                    : .secondary
            )
            Rectangle().fill(Color.dashboardLine).frame(width: 1, height: 48)
            HStack(spacing: 10) {
                Image(systemName: "checkmark.shield")
                    .font(.system(size: 19, weight: .medium))
                    .foregroundStyle(Color.dashboardRed)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Policy-backed protection")
                        .font(.system(size: 12, weight: .semibold))
                    Text("Monitoring and pre-tool decisions use the same local Gensee policy.")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 12)
        .background(Color.dashboardPanel)
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.dashboardLine, lineWidth: 1))
    }

    private func summaryMetric(
        value: String,
        label: String,
        detail: String,
        color: Color
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 9) {
            Text(value)
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 1) {
                Text(label).font(.system(size: 11, weight: .semibold))
                Text(detail).font(.system(size: 9)).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 18)
        .frame(width: 180, alignment: .leading)
    }

    private func harnessRow(_ integration: IntegrationDescriptor) -> some View {
        HStack(alignment: .center, spacing: 14) {
            DashboardSymbol(
                integration.symbolName,
                color: integration.installed ? .secondary : Color.secondary.opacity(0.45),
                size: 15,
                weight: .regular
            )
            .frame(width: 40, height: 40)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(integration.name)
                        .font(.system(size: 13, weight: .semibold))
                    DashboardTag(text: integration.statusLabel, color: statusColor(integration))
                }
                Text(integration.detail)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Text(
                    integration.configurationIssue
                        ?? integration.configurationNote
                        ?? (integration.awaitingVerification
                            ? HarnessActivationGuidance.instruction(for: integration.id).detail
                            : integration.installationDetail)
                )
                    .font(.system(size: 10))
                    .foregroundStyle(integration.configurationIssue == nil ? Color.secondary : Color.dashboardGold)
                    .lineLimit(2)
                if integration.installed && integration.supportsDirectHooks {
                    Text(abbreviatedPath(integration.configPath))
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if integration.awaitingVerification,
                       let actionTitle = HarnessActivationGuidance.instruction(for: integration.id).actionTitle {
                        Button(actionTitle) {
                            if integration.id == "codex" {
                                model.openCodexHookReview()
                            } else if integration.id == "omnigent" {
                                model.copyOmnigentManagedLaunch()
                            }
                        }
                        .buttonStyle(.link)
                        .font(.system(size: 10, weight: .medium))
                        .accessibilityIdentifier("harness.\(integration.id).activationAction")
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            auditButton(integration)
            protectionButton(integration)
            recoveryPointControl(integration)
        }
        .padding(.vertical, 13)
        .contentShape(Rectangle())
        .opacity(integration.installed ? 1 : 0.42)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private func recoveryPointControl(_ integration: IntegrationDescriptor) -> some View {
        if integration.supportsDirectHooks {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.counterclockwise.circle")
                    Text("Smart recovery points")
                }
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)
                Picker(
                    "Smart recovery points",
                    selection: Binding(
                        get: { model.recoveryPointSettings.mode(for: integration.id) },
                        set: { mode in
                            Task { await model.updateRecoveryPointMode(mode, for: integration.id) }
                        }
                    )
                ) {
                    ForEach(RecoveryPointMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 178)
                Text(recoveryModeHelp(integration))
                    .font(.system(size: 8))
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .frame(width: 178, alignment: .leading)
            }
            .disabled(!integration.installed || !model.backendAvailable || model.runningCommand != nil)
            .help(recoveryModeHelp(integration))
        }
    }

    private func recoveryModeHelp(_ integration: IntegrationDescriptor) -> String {
        switch model.recoveryPointSettings.mode(for: integration.id) {
        case .auto:
            return "Creates once before the first risky change."
        case .ask where integration.id == "codex":
            return "Codex may require approval, then a retry."
        case .ask:
            return "Pauses briefly for approval in Gensee."
        case .off:
            return "No automatic Git recovery point."
        }
    }

    private func auditButton(_ integration: IntegrationDescriptor) -> some View {
        let target = configAuditTarget(integration)
        return Button {
            guard let target else { return }
            withAnimation(.easeOut(duration: 0.18)) {
                selectedAuditTarget = target
            }
        } label: {
            VStack(spacing: 1) {
                Label("Audit Config", systemImage: "checkmark.shield")
                if target == nil {
                    Text("Coming soon")
                        .font(.system(size: 8, weight: .medium))
                }
            }
            .frame(width: 104)
            .frame(minHeight: 26)
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .disabled(target == nil || !integration.installed || model.runningCommand != nil)
        .help(auditHelp(integration, target: target))
        .accessibilityLabel(target == nil ? "Audit Config coming soon for \(integration.name)" : "Audit \(integration.name) configuration")
    }

    private func protectionButton(_ integration: IntegrationDescriptor) -> some View {
        Button {
            Task {
                if integration.requiresRepair {
                    await model.repairIntegration(integration.id)
                } else {
                    await model.setIntegrationEnabled(integration.id, enabled: !integration.configured)
                }
            }
        } label: {
            Label(protectionActionLabel(integration), systemImage: protectionActionSymbol(integration))
                .frame(width: 126)
                .frame(minHeight: 26)
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .tint(protectionActionColor(integration))
        .disabled(protectionActionDisabled(integration))
        .help(protectionHelp(integration))
        .accessibilityLabel("\(protectionActionLabel(integration)) for \(integration.name)")
    }

    private func configAuditTarget(_ integration: IntegrationDescriptor) -> String? {
        switch integration.id {
        case "codex": "codex"
        case "vscode": "vscode"
        default: nil
        }
    }

    private func auditHelp(_ integration: IntegrationDescriptor, target: String?) -> String {
        guard target != nil else { return "Configuration Audit support for \(integration.name) is coming soon." }
        guard integration.installed else { return "Install \(integration.name) before auditing its configuration." }
        return "Run a read-only security audit of \(integration.name) configuration for a selected workspace."
    }

    private func protectionActionLabel(_ integration: IntegrationDescriptor) -> String {
        if integration.requiresRepair { return "Repair Protection" }
        return integration.configured ? "Disable Protection" : "Enable Protection"
    }

    private func protectionActionSymbol(_ integration: IntegrationDescriptor) -> String {
        if integration.requiresRepair { return "wrench.and.screwdriver" }
        return integration.configured ? "shield.slash" : "shield.checkered"
    }

    private func protectionActionColor(_ integration: IntegrationDescriptor) -> Color {
        if integration.requiresRepair { return .dashboardGold }
        return integration.configured ? .secondary : .dashboardRed
    }

    private func protectionActionDisabled(_ integration: IntegrationDescriptor) -> Bool {
        !integration.canToggle
            || !model.backendAvailable
            || model.runningCommand != nil
            || (integration.configurationIssue != nil && !integration.canRepair)
    }

    private func protectionHelp(_ integration: IntegrationDescriptor) -> String {
        if !integration.installed { return "Install \(integration.name) before enabling Gensee protection." }
        if !integration.supportsDirectHooks {
            return "Omnigent protection currently requires launching it with gensee run."
        }
        if !model.backendAvailable { return "The bundled Gensee backend is unavailable." }
        if integration.requiresRepair {
            return "Reconnect \(integration.name) hooks to this app's event store and backend."
        }
        if integration.configurationIssue != nil {
            return "This configuration must be fixed manually before Gensee can safely manage it."
        }
        return integration.configured
            ? "Remove Gensee hooks while preserving unrelated harness settings."
            : "Install Gensee monitoring and policy hooks."
    }

    private func statusColor(_ integration: IntegrationDescriptor) -> Color {
        if !integration.installed { return .secondary }
        if integration.configurationIssue != nil { return .dashboardGold }
        if !integration.supportsDirectHooks { return .dashboardBlue }
        if integration.isHealthy { return .dashboardGreen }
        if integration.awaitingVerification { return .dashboardGold }
        return .secondary
    }
}

/// Cowork has endpoint evidence, not Claude Code's synchronous policy hooks.
/// Observe the sensor directly so connectivity cannot get stuck at a stale
/// value while the expensive dashboard projection is idle.
private struct CoworkHarnessRow: View {
    @ObservedObject var model: ConsoleModel
    @ObservedObject var sensor: EndpointSecuritySensor
    let integration: IntegrationDescriptor
    @State private var expanded = false
    @State private var pendingProtectionLevel: ProtectionLevel?

    private var sensorReady: Bool {
        sensor.health.connected && sensor.health.running && sensor.health.error == nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 14) {
                DashboardSymbol("desktopcomputer", color: .secondary, size: 15, weight: .regular)
                    .frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text("Claude Cowork").font(.system(size: 13, weight: .semibold))
                        DashboardTag(text: integration.statusLabel, color: integration.configured ? .dashboardBlue : .secondary)
                    }
                    Text(integration.detail).font(.system(size: 11)).foregroundStyle(.secondary)
                    if !integration.installed {
                        Text(integration.installationDetail).font(.system(size: 10)).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Button("Verify") {
                    expanded = true
                    Task { await model.verifyCowork() }
                }
                .disabled(!integration.configured || !model.backendAvailable || model.isDemoMode || model.runningCommand != nil)
                .accessibilityIdentifier("harness.claude-cowork.verify")
                Button(integration.configured ? "Disable visibility" : "Enable visibility") {
                    expanded = true
                    Task { await model.setIntegrationEnabled(integration.id, enabled: !integration.configured) }
                }
                .disabled(!integration.canToggle || !model.backendAvailable || model.isDemoMode || model.runningCommand != nil)
                .accessibilityIdentifier("harness.claude-cowork.toggle")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    Text("Protection (Mac-wide)").fontWeight(.medium)
                    Picker("Mac-wide protection", selection: Binding<ProtectionLevel?>(
                        get: { model.protectionLevel },
                        set: { level in
                            guard let level else { return }
                            if model.wouldLowerProtection(level) {
                                pendingProtectionLevel = level
                            } else {
                                Task { _ = await model.applyProtectionLevel(level) }
                            }
                        }
                    )) {
                        if model.protectionLevel == nil { Text("Custom").tag(Optional<ProtectionLevel>.none) }
                        ForEach(ProtectionLevel.allCases) { level in
                            Text(level.endpointMode.capitalized).tag(Optional(level))
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)
                    .frame(width: 270)
                    .disabled(model.isDemoMode || !model.backendAvailable || model.policyDocument.isEmpty || model.runningCommand != nil)
                    .accessibilityIdentifier("harness.claude-cowork.protectionLevel")
                    .help("Uses the same presets as Settings: Observe = Fast, Protect = Review, Strict = Sensitive. Changes sensor mode and hook interactivity for all enabled harnesses.")
                }
                Text(protectionDetail + " Shared by all enabled harnesses.")
                    .foregroundStyle(.secondary)
                HStack(spacing: 16) {
                    Label(sensorReady ? "Sensor connected" : "Sensor unavailable", systemImage: sensorReady ? "checkmark.circle" : "exclamationmark.circle")
                    Link("Set up audit collection ↗", destination: URL(string: "https://github.com/GenseeAI/gensee-crate/blob/main/integrations/claude-cowork/README.md#local-audit-ingestion")!)
                        .help("Audit collection runs separately in your terminal. Stop it there when finished.")
                    if !sensorReady || sensor.health.hasDataLoss || sensor.health.hasBackpressure {
                        Button("Review sensor health") { model.requestedDashboardDestination = .settings }
                            .buttonStyle(.link)
                            .foregroundStyle(Color.dashboardGold)
                    }
                }
                .foregroundStyle(.secondary)
                Text("Covers host activity and VM boundaries; guest commands and cloud execution are outside coverage.")
                    .foregroundStyle(.secondary)

                DisclosureGroup("Session & evidence", isExpanded: $expanded) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 10) {
                            Text("Session mode")
                            Picker("Cowork session mode", selection: Binding(
                                get: { model.coworkSessionMode },
                                set: { mode in Task { await model.setCoworkSessionMode(mode) } }
                            )) {
                                Text("Unknown / mixed").tag("unknown")
                                Text("Local").tag("local")
                                Text("Cloud").tag("cloud")
                            }
                            .labelsHidden()
                            .frame(width: 155)
                            .disabled(model.isDemoMode || !model.backendAvailable || model.runningCommand != nil)
                            .accessibilityIdentifier("harness.claude-cowork.sessionMode")
                            .help("Choose Local only for confirmed local sessions. Restart manual audit ingestion after changing mode.")
                        }
                        if let issue = model.coworkCheckIssue {
                            Text(issue).foregroundStyle(Color.dashboardGold)
                        } else if let evidence = model.coworkEvidence, let checkedAt = model.coworkCheckedAt {
                            if evidence.evidence.isEmpty {
                                Text("No Cowork evidence in the latest \(evidence.sampleLimit) events.")
                            } else {
                                ForEach(Array(evidence.evidence.enumerated()), id: \.offset) { _, item in
                                    HStack {
                                        Text(evidenceLabel(item))
                                        Text(Date(timeIntervalSince1970: Double(item.lastEventAt) / 1_000).formatted(date: .abbreviated, time: .standard))
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                            Text("Checked \(checkedAt.formatted(date: .omitted, time: .shortened)) · Recent history, not live verification")
                                .foregroundStyle(.secondary)
                                .help("Samples the latest \(evidence.sampleLimit) system events. Older evidence may be outside the sample. Run native and VM test tasks, then Verify again to check for new event times.")
                        } else {
                            Text("Run a Cowork task, then Verify to check recent evidence.")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.top, 8)
                }
            }
            .font(.system(size: 11))
            .fixedSize(horizontal: false, vertical: true)
            .padding(.leading, 54)
        }
        .padding(.vertical, 13)
        .accessibilityElement(children: .contain)
        .alert("Lower protection for all harnesses?", isPresented: Binding(
            get: { pendingProtectionLevel != nil },
            set: { if !$0 { pendingProtectionLevel = nil } }
        ), presenting: pendingProtectionLevel) { level in
            Button("Cancel", role: .cancel) { pendingProtectionLevel = nil }
            Button("Use \(level.endpointMode.capitalized)", role: .destructive) {
                pendingProtectionLevel = nil
                Task { _ = await model.applyProtectionLevel(level) }
            }
        } message: { _ in
            Text("This changes this Mac’s sensor mode and hook interactivity for all enabled harnesses.")
        }
    }

    private var protectionDetail: String {
        switch model.protectionLevel {
        case .observe: "Records host activity; existing hook rules still apply."
        case .guarded: "Blocks protected host paths and executables."
        case .unattended: "Same host blocks as Protect; risky hook approvals become denials."
        case nil: "Custom policy. Select a preset to change protection."
        }
    }

    private func evidenceLabel(_ item: CoworkEvidenceStatus.Evidence) -> String {
        guard item.source == "claude-cowork-local-audit" else { return "Host events (\(item.origin))" }
        switch item.origin {
        case "host-native": return "Native audit"
        case "vm-mediated": return "VM audit"
        case "cloud-mediated": return "Cloud audit"
        default: return "Unknown audit"
        }
    }
}

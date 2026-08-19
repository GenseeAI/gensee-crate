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
                                harnessRow(integration)
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

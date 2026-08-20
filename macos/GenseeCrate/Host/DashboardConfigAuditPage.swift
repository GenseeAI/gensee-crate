import AppKit
import SwiftUI

struct HarnessConfigAuditPanel: View {
    @ObservedObject var model: ConsoleModel
    let target: String
    let onClose: () -> Void
    @State private var workspacePath = Self.defaultWorkspace
    @State private var section = AuditSection.findings

    private static var defaultWorkspace: String {
        ProcessInfo.processInfo.environment["GENSEE_WORKSPACE"] ?? ""
    }

    private var bundle: ConfigAuditBundle? {
        guard !workspacePath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let bundle = model.configAudit,
              bundle.requestedTarget == target,
              let auditedWorkspace = bundle.includedReports.first?.report.target.workspace,
              auditedWorkspace == normalizedWorkspacePath
        else { return nil }
        return bundle
    }

    private var normalizedWorkspacePath: String {
        let expanded = (workspacePath as NSString).expandingTildeInPath
        return URL(fileURLWithPath: expanded)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 12) {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(Color.dashboardBlue.opacity(0.11))
                    .frame(width: 38, height: 38)
                    .overlay(
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 16, weight: .medium))
                            .foregroundStyle(Color.dashboardBlue)
                    )
                VStack(alignment: .leading, spacing: 3) {
                    Text("\(targetName) Config Audit")
                        .font(.system(size: 17, weight: .semibold))
                    Text("Static, read-only review of permissions, privacy, extensions, and trust boundaries.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if let bundle {
                    StatusPill(
                        label: bundle.summary.assessment.capitalized,
                        color: bundle.summary.assessment == "complete" ? .dashboardGreen : .dashboardGold,
                        symbol: bundle.summary.assessment == "complete" ? "checkmark.circle.fill" : "exclamationmark.circle.fill"
                    )
                }
                Button(action: onClose) {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
                .help("Close Config Audit")
                .accessibilityLabel("Close \(targetName) Config Audit")
            }

            auditControls

            if let bundle {
                summary(bundle)
                Picker("Audit detail", selection: $section) {
                    ForEach(AuditSection.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 720)

                switch section {
                case .findings: findingsView(bundle)
                case .inventory: inventoryView(bundle)
                case .sources: sourcesView(bundle)
                case .manualChecks: manualChecksView(bundle)
                }
            } else {
                DashboardCard {
                    DashboardEmpty(
                        text: "Select a workspace and run a local configuration audit for \(targetName).",
                        symbol: "checkmark.shield"
                    )
                }
            }
        }
        .padding(.top, 6)
    }

    private var auditControls: some View {
        DashboardCard("Audit scope") {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .bottom, spacing: 12) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Workspace").font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                        HStack(spacing: 6) {
                            TextField("/path/to/workspace", text: $workspacePath)
                                .textFieldStyle(.roundedBorder)
                            Button { chooseWorkspace() } label: {
                                Image(systemName: "folder")
                            }
                            .help("Choose workspace")
                        }
                    }

                    Button {
                        Task { await model.runConfigAudit(target: target, workspace: workspacePath) }
                    } label: {
                        Label(bundle == nil ? "Run Audit" : "Run Again", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.dashboardRed)
                    .disabled(model.runningCommand != nil || workspacePath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                Text("The shared OSS Rust auditor reads bounded local configuration files. It does not launch agents, extensions, hooks, skills, MCP servers, or package runners.")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var targetName: String {
        target == "vscode" ? "GitHub Copilot" : "Codex"
    }

    private func summary(_ bundle: ConfigAuditBundle) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if let drift = model.configAuditDrift {
                HStack(spacing: 10) {
                    DashboardSymbol(
                        drift.hasChanges ? "arrow.triangle.2.circlepath" : "checkmark.circle",
                        color: drift.hasChanges ? .dashboardGold : .dashboardGreen,
                        size: 13
                    )
                    VStack(alignment: .leading, spacing: 2) {
                        Text(drift.hasChanges ? "Configuration drift detected" : "No changes since the previous audit")
                            .font(.system(size: 11, weight: .semibold))
                        Text("\(drift.addedFindingCount) new findings · \(drift.resolvedFindingCount) resolved · \(drift.changedSourceCount) configuration sources changed")
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text("Compared with the last \(targetName) audit")
                        .font(.system(size: 9))
                        .foregroundStyle(.tertiary)
                }
                .padding(11)
                .background((drift.hasChanges ? Color.dashboardGold : Color.dashboardGreen).opacity(0.07), in: RoundedRectangle(cornerRadius: 6))
            } else {
                Label("Baseline saved. The next audit will highlight new findings, resolved findings, and changed configuration sources.", systemImage: "bookmark")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }

            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
                DashboardStatCard(
                    title: "Findings",
                    value: bundle.summary.findingCount,
                    symbol: "magnifyingglass",
                    color: .dashboardBlue
                )
                DashboardStatCard(
                    title: "Critical + high",
                    value: bundle.summary.count("critical") + bundle.summary.count("high"),
                    symbol: "exclamationmark.triangle.fill",
                    color: .dashboardRed
                )
                DashboardStatCard(
                    title: "Medium",
                    value: bundle.summary.count("medium"),
                    symbol: "exclamationmark.circle",
                    color: .dashboardGold
                )
                DashboardStatCard(
                    title: "Manual checks",
                    value: bundle.summary.manualChecks,
                    symbol: "person.crop.circle.badge.questionmark",
                    color: .purple
                )
            }

            HStack(spacing: 8) {
                ForEach(bundle.reports) { item in
                    AuditPill(
                        text: pretty(item.target),
                        color: item.applicability == "not_detected" ? .secondary : .dashboardBlue
                    )
                    if let reason = item.applicabilityReason {
                        Image(systemName: "info.circle")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .help(reason)
                    }
                }
                Spacer()
                Text(abbreviatedPath(bundle.includedReports.first?.report.target.workspace ?? workspacePath))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }

    private func findingsView(_ bundle: ConfigAuditBundle) -> some View {
        let findings = bundle.includedReports.flatMap { targetReport in
            targetReport.report.findings.map { AuditFindingDisplay(target: targetReport.target, finding: $0) }
        }
        return VStack(alignment: .leading, spacing: 8) {
            if findings.isEmpty {
                DashboardCard { DashboardEmpty(text: "No static configuration findings were reported.", symbol: "checkmark.shield.fill") }
            } else {
                ForEach(findings) { item in
                    ConfigAuditFindingCard(item: item)
                }
            }
        }
    }

    private func inventoryView(_ bundle: ConfigAuditBundle) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(bundle.includedReports) { item in
                let inventory = item.report.inventory
                DashboardCard(pretty(item.target)) {
                    VStack(alignment: .leading, spacing: 12) {
                        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 8), count: 4), spacing: 8) {
                            AuditMetric(label: "MCP servers", value: inventory.mcpServers.count)
                            AuditMetric(label: "Skills", value: inventory.skills.count)
                            AuditMetric(label: "Extensions", value: inventory.extensions.count)
                            AuditMetric(label: "Hook commands", value: inventory.hookCommands)
                            AuditMetric(label: "Rules", value: inventory.ruleFiles)
                            AuditMetric(label: "Instructions", value: inventory.instructionFiles)
                            AuditMetric(label: "Plugins", value: inventory.pluginManifests)
                            AuditMetric(label: "Custom agents", value: inventory.customAgents)
                        }

                        if item.report.target.provider != "codex" {
                            Label(
                                "VS Code enabled state, MCP tool allowlists, and skill review state are not statically modeled.",
                                systemImage: "info.circle"
                            )
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                        }

                        if !item.report.effectiveSecurityConfig.isEmpty {
                            Divider()
                            Text("Effective security configuration").font(.system(size: 12, weight: .semibold))
                            ForEach(item.report.effectiveSecurityConfig.sorted { $0.key < $1.key }, id: \.key) { key, value in
                                HStack(alignment: .firstTextBaseline) {
                                    Text(pretty(key)).foregroundStyle(.secondary).frame(width: 210, alignment: .leading)
                                    Text(value.displayValue).font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                                }
                                .font(.system(size: 11))
                            }
                        }

                        inventoryResources(item)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func inventoryResources(_ item: ConfigAuditTargetReport) -> some View {
        let inventory = item.report.inventory
        if !inventory.mcpServers.isEmpty {
            Divider()
            Text("MCP servers").font(.system(size: 12, weight: .semibold))
            ForEach(inventory.mcpServers) { server in
                HStack {
                    Text(server.id).font(.system(size: 11, weight: .medium))
                    AuditPill(text: server.transport, color: .dashboardBlue)
                    Spacer()
                    Text(server.endpoint ?? "Local process").font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                }
            }
        }
        if !inventory.skills.isEmpty {
            Divider()
            Text("Skills").font(.system(size: 12, weight: .semibold))
            ForEach(inventory.skills) { skill in
                HStack {
                    Text(skill.name).font(.system(size: 11, weight: .medium)).frame(width: 180, alignment: .leading)
                    AuditPill(text: pretty(skill.scope), color: .purple)
                    if skill.hasScripts { AuditPill(text: "Scripts", color: .dashboardGold) }
                    Spacer()
                    Text(abbreviatedPath(skill.path)).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
        if !inventory.extensions.isEmpty {
            Divider()
            Text("Extensions").font(.system(size: 12, weight: .semibold))
            ForEach(inventory.extensions) { item in
                HStack {
                    Text(item.id).font(.system(size: 11, weight: .medium))
                    Text(item.version).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                    Spacer()
                    AuditPill(text: pretty(item.enabledState), color: .dashboardBlue)
                }
            }
        }
    }

    private func sourcesView(_ bundle: ConfigAuditBundle) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(bundle.includedReports) { item in
                DashboardCard(pretty(item.target)) {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(item.report.sources.enumerated()), id: \.offset) { index, source in
                            HStack(alignment: .top, spacing: 10) {
                                Image(systemName: source.errors.isEmpty ? "doc.text" : "exclamationmark.triangle.fill")
                                    .foregroundStyle(source.errors.isEmpty ? Color.secondary : Color.dashboardGold)
                                    .frame(width: 18)
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack(spacing: 6) {
                                        Text(pretty(source.kind)).font(.system(size: 11, weight: .semibold))
                                        if source.applied { AuditPill(text: "Applied", color: .dashboardGreen) }
                                        if !source.errors.isEmpty { AuditPill(text: "Partial", color: .dashboardGold) }
                                    }
                                    Text(abbreviatedPath(source.path))
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                    ForEach(source.errors, id: \.self) { Text($0).font(.system(size: 10)).foregroundStyle(Color.dashboardGold) }
                                }
                                Spacer()
                            }
                            .padding(.vertical, 8)
                            if index < item.report.sources.count - 1 { Divider() }
                        }
                    }
                }
            }
        }
    }

    private func manualChecksView(_ bundle: ConfigAuditBundle) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(bundle.includedReports) { item in
                ForEach(item.report.manualChecks) { check in
                    DashboardCard {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: "person.crop.circle.badge.questionmark")
                                .font(.system(size: 18))
                                .foregroundStyle(Color.dashboardGold)
                            VStack(alignment: .leading, spacing: 7) {
                                HStack(spacing: 7) {
                                    Text(check.title).font(.system(size: 12, weight: .semibold))
                                    AuditPill(text: check.priority, color: .dashboardGold)
                                    AuditPill(text: pretty(item.target), color: .dashboardBlue)
                                }
                                Text(check.reason).font(.system(size: 11)).foregroundStyle(.secondary)
                                Label(check.action, systemImage: "arrow.right.circle")
                                    .font(.system(size: 11, weight: .medium))
                            }
                        }
                    }
                }
                if !item.report.limitations.isEmpty {
                    DashboardCard("Audit limitations") {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(item.report.limitations, id: \.self) { limitation in
                                Label(limitation, systemImage: "info.circle")
                                    .font(.system(size: 10))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
    }

    private func chooseWorkspace() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: workspacePath)
        panel.prompt = "Choose Workspace"
        if panel.runModal() == .OK, let url = panel.url { workspacePath = url.path }
    }
}

private enum AuditSection: String, CaseIterable, Identifiable {
    case findings = "Findings"
    case inventory = "Inventory"
    case sources = "Sources"
    case manualChecks = "Manual Checks"
    var id: String { rawValue }
}

private struct AuditFindingDisplay: Identifiable {
    let target: String
    let finding: ConfigAuditFinding
    var id: String { "\(target):\(finding.fingerprint)" }
}

private struct ConfigAuditFindingCard: View {
    let item: AuditFindingDisplay
    @State private var expanded = false

    var body: some View {
        DashboardCard {
            DisclosureGroup(isExpanded: $expanded) {
                VStack(alignment: .leading, spacing: 12) {
                    Text(item.finding.description).font(.system(size: 11)).foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        Label("Recommended action", systemImage: "arrow.right.circle.fill")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(Color.dashboardBlue)
                        Text(item.finding.remediation.summary).font(.system(size: 11))
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.dashboardBlue.opacity(0.07), in: RoundedRectangle(cornerRadius: 5))

                    if !item.finding.evidence.isEmpty {
                        Text("Evidence").font(.system(size: 11, weight: .semibold))
                        ForEach(item.finding.evidence) { evidence in
                            VStack(alignment: .leading, spacing: 3) {
                                Text(abbreviatedPath(evidence.source))
                                    .font(.system(size: 10, design: .monospaced))
                                    .textSelection(.enabled)
                                if let key = evidence.key {
                                    Text(evidence.value.map { "\(key) = \($0)" } ?? key)
                                        .font(.system(size: 10))
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 4))
                        }
                    }
                }
                .padding(.top, 12)
            } label: {
                HStack(alignment: .top, spacing: 10) {
                    Circle().fill(severityColor(item.finding.severity)).frame(width: 8, height: 8).padding(.top, 5)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(item.finding.title).font(.system(size: 12, weight: .semibold))
                        HStack(spacing: 6) {
                            AuditPill(text: item.finding.severity, color: severityColor(item.finding.severity))
                            AuditPill(text: pretty(item.finding.assessment), color: item.finding.assessment == "confirmed" ? .dashboardRed : .dashboardGold)
                            AuditPill(text: item.finding.ruleID, color: .secondary)
                            AuditPill(text: pretty(item.target), color: .dashboardBlue)
                        }
                    }
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .tint(.secondary)
        }
    }
}

private struct AuditMetric: View {
    let label: String
    let value: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.system(size: 10)).foregroundStyle(.secondary)
            Text(value.formatted()).font(.system(size: 18, weight: .semibold))
        }
        .padding(9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))
    }
}

private struct AuditPill: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 8, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 4))
    }
}

private func pretty(_ value: String) -> String {
    value.replacingOccurrences(of: "_", with: " ")
        .replacingOccurrences(of: "-", with: " ")
        .split(separator: " ")
        .map { $0.prefix(1).uppercased() + $0.dropFirst() }
        .joined(separator: " ")
}

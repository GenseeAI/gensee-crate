import AppKit
import SwiftUI

struct DashboardAlertsPage: View {
    @ObservedObject var model: ConsoleModel
    let searchText: String
    @State private var severity = "All"
    @State private var action = "All"
    @StateObject private var columns = AlertColumnLayout()

    private var alerts: [SecurityAlert] {
        model.snapshot.alerts.filter {
            (severity == "All" || $0.severity.caseInsensitiveCompare(severity) == .orderedSame)
            && (action == "All" || $0.action.caseInsensitiveCompare(action) == .orderedSame)
            && containsSearch(
                searchText,
                fields: $0.message, $0.ruleID, $0.path, $0.sessionID,
                $0.originalUserPrompt, $0.toolName, $0.toolInput
            )
        }
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Alerts", description: "Policy decisions and risk findings across all sessions.") {
                    HStack(spacing: 8) {
                        Picker("Severity", selection: $severity) { ForEach(["All", "Info", "Low", "Medium", "High", "Critical"], id: \.self, content: Text.init) }.frame(width: 120)
                        Picker("Action", selection: $action) { ForEach(["All", "Allow", "Warn", "Ask", "Block"], id: \.self, content: Text.init) }.frame(width: 110)
                        Button { model.markAllAlertsRead() } label: {
                            Label("Mark All as Read", systemImage: "checkmark.circle")
                                .frame(minWidth: 116)
                        }
                        .buttonStyle(.bordered)
                        .fixedSize(horizontal: true, vertical: false)
                        .disabled(model.unreadAlertCount == 0)
                        .help("Clear the unread alert badge without deleting alert history")
                        DashboardRefreshButton(refreshing: model.isRefreshing) { Task { await model.refreshAll() } }
                    }.controlSize(.small)
                }
                DashboardCard {
                    if alerts.isEmpty { DashboardEmpty(text: "No alerts found.", symbol: "checkmark.shield") }
                    else {
                        VStack(spacing: 0) {
                            AlertListHeader(layout: columns)
                            ForEach(alerts) { alert in
                                Divider()
                                ExpandableAlertRow(alert: alert, model: model, layout: columns)
                            }
                        }
                    }
                }
            }
        }
    }
}

@MainActor
final class AlertColumnLayout: ObservableObject {
    @Published var severity: CGFloat = 74
    @Published var action: CGFloat = 68
    @Published var finding: CGFloat = 280
    @Published var path: CGFloat = 176
    @Published var time: CGFloat = 112
    @Published var review: CGFloat = 92
}

struct AlertListHeader: View {
    @ObservedObject var layout: AlertColumnLayout

    var body: some View {
        HStack(spacing: 10) {
            Color.clear.frame(width: 14)
            ResizableAlertHeaderCell(title: "Severity", width: $layout.severity, range: 62...120)
            ResizableAlertHeaderCell(title: "Action", width: $layout.action, range: 58...110)
            ResizableAlertHeaderCell(title: "Finding", width: $layout.finding, range: 180...520)
            ResizableAlertHeaderCell(title: "Path", width: $layout.path, range: 110...420)
            ResizableAlertHeaderCell(title: "Time", width: $layout.time, range: 92...190)
            ResizableAlertHeaderCell(title: "Review", width: $layout.review, range: 82...140)
            Spacer(minLength: 0)
        }
        .font(.system(size: 11, weight: .semibold))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(Color.dashboardMutedFill)
    }
}

private struct ResizableAlertHeaderCell: View {
    let title: String
    @Binding var width: CGFloat
    let range: ClosedRange<CGFloat>
    @State private var dragStart: CGFloat?

    var body: some View {
        Text(title)
            .frame(width: width, alignment: .leading)
            .help("Drag the divider to resize the \(title.lowercased()) column")
            .overlay(alignment: .trailing) {
                Rectangle()
                    .fill(Color.clear)
                    .frame(width: 9)
                    .contentShape(Rectangle())
                    .overlay {
                        Rectangle()
                            .fill(Color.dashboardLine)
                            .frame(width: 1, height: 15)
                    }
                    .onHover { hovering in
                        if hovering { NSCursor.resizeLeftRight.push() } else { NSCursor.pop() }
                    }
                    .gesture(
                        DragGesture(minimumDistance: 1)
                            .onChanged { value in
                                let start = dragStart ?? width
                                dragStart = start
                                width = min(range.upperBound, max(range.lowerBound, start + value.translation.width))
                            }
                            .onEnded { _ in dragStart = nil }
                    )
            }
    }
}

struct ExpandableAlertRow: View {
    let alert: SecurityAlert
    @ObservedObject var model: ConsoleModel
    @ObservedObject var layout: AlertColumnLayout
    @State private var expanded = false

    private var unread: Bool { !model.isAlertRead(alert.alertID) }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Button {
                    toggleDetails()
                } label: {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                        .frame(width: 14)
                        .overlay(alignment: .topTrailing) {
                            if unread {
                                Circle()
                                    .fill(Color.dashboardRed)
                                    .frame(width: 5, height: 5)
                                    .offset(x: 4, y: -3)
                                    .accessibilityHidden(true)
                            }
                        }
                }
                .buttonStyle(.plain)
                .help(expanded ? "Hide finding evidence" : "Show finding evidence")

                    DashboardTag(text: alert.severity, color: severityColor(alert.severity))
                        .frame(width: layout.severity, alignment: .leading)
                        .help("Severity: \(alert.severity.uppercased())")
                    DashboardTag(text: alert.action, color: actionColor(alert.action))
                        .frame(width: layout.action, alignment: .leading)
                        .help("Action: \(alert.action.uppercased())")
                    Text(alert.message)
                        .font(.system(size: 12, weight: unread ? .semibold : .medium))
                        .lineLimit(expanded ? 2 : 1)
                    .frame(width: layout.finding, alignment: .leading)
                    .contentShape(Rectangle())
                    .onTapGesture(perform: toggleDetails)
                    .help("\(alert.message)\nRule: \(alert.ruleID)")
                    Text(alert.path.map(abbreviatedPath) ?? "—")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(alert.path == nil ? .tertiary : .secondary)
                        .frame(width: layout.path, alignment: .leading)
                        .lineLimit(1)
                        .help(alert.path ?? "No path was associated with this finding")
                    Text(dashboardDate(alert.createdAt))
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .frame(width: layout.time, alignment: .leading)
                        .help(Date(timeIntervalSince1970: TimeInterval(alert.createdAt) / 1_000).formatted(date: .complete, time: .complete))
                    FindingReviewControl(alert: alert, model: model)
                        .frame(width: layout.review, alignment: .leading)
                    Spacer(minLength: 0)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 9)
            .contentShape(Rectangle())
            .background(unread ? Color.dashboardRed.opacity(0.035) : .clear)
            .accessibilityLabel("\(unread ? "Unread, " : "")\(alert.severity) severity, \(alert.action), \(alert.message)")
            .accessibilityHint(expanded ? "Collapse alert details" : "Expand alert details")

            if expanded {
                alertDetails
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .animation(.easeOut(duration: 0.16), value: expanded)
    }

    private var alertDetails: some View {
        VStack(alignment: .leading, spacing: 16) {
            Divider()
            HStack(alignment: .top, spacing: 24) {
                AlertEvidenceBlock(
                    title: "User request",
                    symbol: "text.bubble",
                    content: alert.originalUserPrompt,
                    unavailable: "The originating harness did not provide a captured user request."
                )
                .frame(maxWidth: .infinity, alignment: .topLeading)

                VStack(alignment: .leading, spacing: 8) {
                    Label("Tool call", systemImage: "wrench.and.screwdriver")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.secondary)
                    if let toolName = alert.toolName {
                        HStack(spacing: 6) {
                            Text(toolName).font(.system(size: 12, weight: .semibold))
                            if let source = alert.eventSource { DashboardTag(text: source, color: .dashboardBlue) }
                            if let type = alert.eventType { DashboardTag(text: type, color: .secondary) }
                        }
                        if let toolInput = alert.toolInput {
                            Text(prettyAlertJSON(toolInput))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .padding(10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.dashboardCanvas.opacity(0.7), in: RoundedRectangle(cornerRadius: 5))
                        } else {
                            Text("No tool input was captured for this call.")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                    } else {
                        Text("No tool call could be correlated with this alert.")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }

            AlertMetadata(alert: alert)
        }
        .padding(.leading, 36)
        .padding(.trailing, 10)
        .padding(.bottom, 16)
        .background(Color.dashboardMutedFill.opacity(0.45))
    }

    private func toggleDetails() {
        model.markAlertRead(alert.alertID)
        expanded.toggle()
    }
}

private struct FindingReviewControl: View {
    let alert: SecurityAlert
    @ObservedObject var model: ConsoleModel
    @State private var pendingChange: PendingRuleTuning?

    private let severities = ["Info", "Low", "Medium", "High", "Critical"]
    private let actions = ["Allow", "Warn", "Ask", "Block"]

    private var currentOverride: RuleReviewOverride? {
        model.reviewOverride(for: alert.ruleID)
    }

    var body: some View {
        Menu {
            Menu("Set future severity") {
                ForEach(severities, id: \.self) { severity in
                    Button {
                        requestTune(severity: severity)
                    } label: {
                        if severity.caseInsensitiveCompare(currentOverride?.severity ?? alert.severity) == .orderedSame {
                            Label(severity, systemImage: "checkmark")
                        } else {
                            Text(severity)
                        }
                    }
                }
            }
            Menu("Set future action") {
                ForEach(actions, id: \.self) { action in
                    Button {
                        requestTune(action: action)
                    } label: {
                        if action.caseInsensitiveCompare(currentOverride?.action ?? alert.action) == .orderedSame {
                            Label(action, systemImage: "checkmark")
                        } else {
                            Text(action)
                        }
                    }
                }
            }
        } label: {
            if model.feedbackAlertID == alert.alertID {
                ProgressView().controlSize(.small)
            } else {
                Label(currentOverride == nil ? "Review" : "Tuned", systemImage: "slider.horizontal.3")
                    .font(.system(size: 12, weight: .medium))
            }
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .fixedSize()
        .disabled(model.feedbackAlertID != nil)
        .help("Changes this rule for all future paths and sessions. Strict fail-closed keeps the original enforcement floor.")
        .alert(
            "Weaken this rule globally?",
            isPresented: Binding(
                get: { pendingChange != nil },
                set: { if !$0 { pendingChange = nil } }
            ),
            presenting: pendingChange
        ) { change in
            Button("Apply to Future Matches", role: .destructive) {
                tune(severity: change.severity, action: change.action)
                pendingChange = nil
            }
            Button("Cancel", role: .cancel) { pendingChange = nil }
        } message: { _ in
            Text("This affects every future match of \(alert.ruleID), across all paths and sessions. Strict and non-interactive fail-closed modes will retain the rule's original enforcement floor.")
        }
    }

    private func requestTune(severity: String? = nil, action: String? = nil) {
        let change = PendingRuleTuning(severity: severity, action: action)
        let currentSeverity = currentOverride?.severity ?? alert.severity
        let currentAction = currentOverride?.action ?? alert.action
        let weakensSeverity = severity.map { severityRank($0) < severityRank(currentSeverity) } ?? false
        let weakensAction = action.map { actionRank($0) < actionRank(currentAction) } ?? false
        if weakensSeverity || weakensAction {
            pendingChange = change
        } else {
            tune(severity: severity, action: action)
        }
    }

    private func tune(severity: String? = nil, action: String? = nil) {
        Task { _ = await model.tuneFinding(alert, severity: severity, action: action) }
    }

    private func severityRank(_ value: String) -> Int {
        ["info", "low", "medium", "high", "critical"].firstIndex(of: value.lowercased()) ?? 0
    }

    private func actionRank(_ value: String) -> Int {
        ["allow", "warn", "ask", "block"].firstIndex(of: value.lowercased()) ?? 0
    }

    private struct PendingRuleTuning: Identifiable {
        let severity: String?
        let action: String?
        let id = UUID()
    }
}

private struct AlertEvidenceBlock: View {
    let title: String
    let symbol: String
    let content: String?
    let unavailable: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: symbol)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
            Text(content ?? unavailable)
                .font(.system(size: 12))
                .foregroundStyle(content == nil ? .secondary : .primary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Color.dashboardCanvas.opacity(0.7), in: RoundedRectangle(cornerRadius: 5))
        }
    }
}

private struct AlertMetadata: View {
    let alert: SecurityAlert

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Alert evidence", systemImage: "list.bullet.rectangle")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 6) {
                metadataRow("Session", alert.sessionID, "Request", alert.requestID.map(String.init))
                metadataRow("Tool use ID", alert.toolUseID, "Path", alert.path.map(abbreviatedPath))
                metadataRow("Rule", alert.ruleID, "Alert ID", String(alert.alertID))
            }
            if let evidence = alert.evidence {
                DisclosureGroup("Raw evidence") {
                    Text(prettyAlertJSON(evidence))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .padding(.top, 6)
                }
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(.secondary)
            }
        }
    }

    private func metadataRow(_ leftLabel: String, _ leftValue: String?, _ rightLabel: String, _ rightValue: String?) -> some View {
        GridRow {
            metadataValue(leftLabel, leftValue)
            metadataValue(rightLabel, rightValue)
        }
    }

    private func metadataValue(_ label: String, _ value: String?) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 7) {
            Text(label).foregroundStyle(.tertiary).frame(width: 72, alignment: .leading)
            Text(value ?? "—").foregroundStyle(.secondary).textSelection(.enabled).lineLimit(2)
        }
        .font(.system(size: 10, design: .monospaced))
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private func prettyAlertJSON(_ text: String) -> String {
    guard let data = text.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data),
          let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    else { return text }
    return String(decoding: pretty, as: UTF8.self)
}

struct LineagePage: View {
    @ObservedObject var model: ConsoleModel
    let searchText: String
    @State private var selectedURI: String?

    private var artifacts: [ArtifactFact] {
        model.snapshot.artifacts
            .filter { containsSearch(searchText, fields: $0.uri, $0.kind, $0.lastModifiedSource, $0.riskLevel) }
            .filter { attentionScore($0) > 0 }
            .sorted {
                let lhs = attentionScore($0)
                let rhs = attentionScore($1)
                return lhs == rhs ? $0.lastSeenAt > $1.lastSeenAt : lhs > rhs
            }
    }

    private var selectedArtifact: ArtifactFact? {
        guard let selectedURI else { return nil }
        return artifacts.first { $0.uri == selectedURI }
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Watchlist", description: "Persistent and sensitive targets that deserve attention across agent sessions.")
                HStack(alignment: .top, spacing: 16) {
                    DashboardCard("Watched targets (\(artifacts.count))") {
                        if artifacts.isEmpty { DashboardEmpty(text: "No cross-session targets need attention yet.") }
                        else {
                            ScrollView {
                                VStack(spacing: 2) {
                                    ForEach(artifacts) { artifact in
                                        Button { selectedURI = selectedURI == artifact.uri ? nil : artifact.uri } label: {
                                            HStack(spacing: 8) {
                                                Rectangle().fill(selectedURI == artifact.uri ? Color.dashboardRed : .clear).frame(width: 3)
                                                VStack(alignment: .leading, spacing: 2) {
                                                    Text(artifact.displayName)
                                                        .font(.system(size: 12, weight: selectedURI == artifact.uri ? .semibold : .regular)).lineLimit(1)
                                                    Text(abbreviatedPath(artifact.filePath))
                                                        .font(.system(size: 11, design: .monospaced))
                                                        .foregroundStyle(.secondary)
                                                        .lineLimit(1)
                                                        .truncationMode(.middle)
                                                    Text([artifact.kind, artifact.lastModifiedSource, artifact.riskLevel].compactMap { $0 }.joined(separator: " · "))
                                                        .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                                                    if attentionScore(artifact) > 0 {
                                                        Text(watchReason(artifact))
                                                            .font(.system(size: 11, weight: .medium))
                                                            .foregroundStyle(Color.dashboardGold)
                                                            .lineLimit(1)
                                                    }
                                                }
                                                Spacer()
                                                DashboardPathMenu(path: artifact.filePath)
                                            }
                                            .padding(.vertical, 6).padding(.horizontal, 4)
                                            .background(selectedURI == artifact.uri ? Color.dashboardBlue.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 4))
                                            .contentShape(Rectangle())
                                        }
                                        .buttonStyle(.plain)
                                        .help(artifact.filePath)
                                        .contextMenu {
                                            DashboardPathContextActions(path: artifact.filePath)
                                        }
                                    }
                                }
                            }.frame(maxHeight: 520)
                        }
                    }.frame(width: 370)

                    DashboardCard(selectedArtifact == nil ? "Select a target" : "Target history") {
                        VStack(alignment: .leading, spacing: 10) {
                            if let selectedArtifact {
                                VStack(alignment: .leading, spacing: 9) {
                                    Text(abbreviatedPath(selectedArtifact.filePath))
                                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                        .textSelection(.enabled)
                                    Text(watchReason(selectedArtifact))
                                        .font(.system(size: 11))
                                        .foregroundStyle(.secondary)
                                    HStack(spacing: 8) {
                                        if selectedArtifact.isControlPlane != 0 { DashboardTag(text: "Control plane", color: .dashboardRed) }
                                        if selectedArtifact.isMemoryArtifact != 0 { DashboardTag(text: "Agent memory", color: .dashboardGold) }
                                        if selectedArtifact.isPersistentTarget != 0 { DashboardTag(text: "Persistent", color: .dashboardBlue) }
                                        if let risk = selectedArtifact.riskLevel { DashboardTag(text: risk, color: severityColor(risk)) }
                                    }
                                    DashboardPathActions(path: selectedArtifact.filePath)
                                }
                                .padding(.horizontal, 4)
                                Divider()
                            }
                            Text("Relationship history")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(.secondary)
                            ArtifactGraphView(facts: artifacts, edges: model.snapshot.relations, selectedURI: $selectedURI)
                                .frame(minHeight: 420)
                        }
                    }.frame(maxWidth: .infinity)
                }
            }
        }
    }

    private func attentionScore(_ artifact: ArtifactFact) -> Int {
        (artifact.isControlPlane != 0 ? 10 : 0)
            + (artifact.isMemoryArtifact != 0 ? 7 : 0)
            + (artifact.isPersistentTarget != 0 ? 5 : 0)
            + ((artifact.recentUnmatchedEffectCount ?? 0) * 3)
            + ((artifact.recentCrossSessionWriteCount ?? 0) * 2)
            + riskAttentionScore(artifact.riskLevel)
    }

    private func riskAttentionScore(_ riskLevel: String?) -> Int {
        switch riskLevel?.lowercased() {
        case "critical": 12
        case "high": 8
        case "medium": 4
        default: 0
        }
    }

    private func watchReason(_ artifact: ArtifactFact) -> String {
        var reasons: [String] = []
        let unmatched = artifact.recentUnmatchedEffectCount ?? 0
        let crossSession = artifact.recentCrossSessionWriteCount ?? 0
        if unmatched > 0 { reasons.append("\(unmatched) undeclared effect\(unmatched == 1 ? "" : "s")") }
        if crossSession > 0 { reasons.append("written across \(crossSession) recent session\(crossSession == 1 ? "" : "s")") }
        if artifact.isControlPlane != 0 { reasons.append("changes agent or repository behavior") }
        if artifact.isMemoryArtifact != 0 { reasons.append("influences future agent context") }
        if artifact.isPersistentTarget != 0 { reasons.append("persists beyond one request") }
        return reasons.isEmpty ? "Observed recently; open the relationship history for provenance." : reasons.joined(separator: " · ")
    }
}

private struct ArtifactGraphView: View {
    private let nodeSize = CGSize(width: 184, height: 106)
    private let horizontalInset: CGFloat = 16
    private let verticalInset: CGFloat = 24
    private let minimumColumnSpacing: CGFloat = 24
    private let rowSpacing: CGFloat = 40

    let facts: [ArtifactFact]
    let edges: [ArtifactEdge]
    @Binding var selectedURI: String?

    var body: some View {
        if facts.isEmpty { DashboardEmpty(text: "No artifact facts recorded yet.") }
        else {
            GeometryReader { geometry in
                let layout = graphLayout(viewportSize: geometry.size)
                ScrollViewReader { scrollProxy in
                    ScrollView([.horizontal, .vertical]) {
                        ZStack {
                            Canvas { context, _ in
                                for edge in edges {
                                    guard let source = layout.uriPositions[edge.sourceURI],
                                          let destination = layout.uriPositions[edge.destinationURI]
                                    else { continue }
                                    var path = Path()
                                    path.move(to: source)
                                    path.addLine(to: destination)
                                    let highlighted = selectedURI == edge.sourceURI || selectedURI == edge.destinationURI
                                    context.stroke(
                                        path,
                                        with: .color(highlighted ? .dashboardRed : .secondary.opacity(0.45)),
                                        lineWidth: highlighted ? 2 : 1
                                    )
                                }
                            }
                            ForEach(facts) { fact in
                                if let position = layout.positions[fact.id] {
                                    Button { selectedURI = selectedURI == fact.uri ? nil : fact.uri } label: {
                                        VStack(alignment: .leading, spacing: 5) {
                                            Text(fact.displayName)
                                                .font(.system(size: 12, weight: .semibold)).lineLimit(1)
                                            Text(abbreviatedPath(fact.filePath))
                                                .font(.system(size: 11, design: .monospaced))
                                                .foregroundStyle(.secondary)
                                                .lineLimit(1)
                                                .truncationMode(.middle)
                                            Text(fact.lastModifiedSource ?? fact.kind).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                                            DashboardTag(text: artifactClass(fact), color: artifactClass(fact) == "sensitive" ? .orange : .dashboardBlue)
                                        }
                                        .padding(10).frame(width: nodeSize.width, height: nodeSize.height, alignment: .leading)
                                        .background(Color.dashboardPanel, in: RoundedRectangle(cornerRadius: 8))
                                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(selectedURI == fact.uri ? Color.dashboardRed : Color.dashboardLine, lineWidth: selectedURI == fact.uri ? 2.5 : 1))
                                    }
                                    .buttonStyle(.plain)
                                    .help(fact.filePath)
                                    .contextMenu {
                                        DashboardPathContextActions(path: fact.filePath)
                                    }
                                    .position(position)
                                    .id(fact.id)
                                }
                            }
                        }
                        .frame(width: layout.canvasSize.width, height: layout.canvasSize.height)
                    }
                    .onChange(of: selectedURI) { uri in
                        guard let uri, let fact = facts.first(where: { $0.uri == uri }) else { return }
                        withAnimation(.easeOut(duration: 0.2)) {
                            scrollProxy.scrollTo(fact.id, anchor: .center)
                        }
                    }
                }
            }
        }
    }

    private func graphLayout(viewportSize: CGSize) -> ArtifactGraphLayout {
        let usableWidth = max(nodeSize.width, viewportSize.width - horizontalInset * 2)
        let columns = max(
            1,
            Int((usableWidth + minimumColumnSpacing) / (nodeSize.width + minimumColumnSpacing))
        )
        let rows = Int(ceil(Double(facts.count) / Double(columns)))
        let columnSpacing = columns > 1
            ? max(minimumColumnSpacing, (usableWidth - CGFloat(columns) * nodeSize.width) / CGFloat(columns - 1))
            : 0
        let contentWidth = CGFloat(columns) * nodeSize.width
            + CGFloat(max(0, columns - 1)) * columnSpacing
        let requiredWidth = horizontalInset * 2 + contentWidth
        let canvasWidth = max(viewportSize.width, requiredWidth)
        let leadingInset = max(horizontalInset, (canvasWidth - contentWidth) / 2)
        let requiredHeight = verticalInset * 2
            + CGFloat(rows) * nodeSize.height
            + CGFloat(max(0, rows - 1)) * rowSpacing
        var positions: [String: CGPoint] = [:]
        var uriPositions: [String: CGPoint] = [:]

        for (index, fact) in facts.enumerated() {
            let column = index % columns
            let row = index / columns
            let position = CGPoint(
                x: leadingInset + nodeSize.width / 2 + CGFloat(column) * (nodeSize.width + columnSpacing),
                y: verticalInset + nodeSize.height / 2 + CGFloat(row) * (nodeSize.height + rowSpacing)
            )
            positions[fact.id] = position
            if uriPositions[fact.uri] == nil {
                uriPositions[fact.uri] = position
            }
        }

        return ArtifactGraphLayout(
            positions: positions,
            uriPositions: uriPositions,
            canvasSize: CGSize(
                width: canvasWidth,
                height: max(viewportSize.height, requiredHeight)
            )
        )
    }

    private struct ArtifactGraphLayout {
        let positions: [String: CGPoint]
        let uriPositions: [String: CGPoint]
        let canvasSize: CGSize
    }

    private func artifactClass(_ fact: ArtifactFact) -> String {
        fact.isSensitive ? "sensitive" : "benign"
    }
}

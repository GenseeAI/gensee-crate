import SwiftUI

struct DashboardAlertsPage: View {
    @ObservedObject var model: ConsoleModel
    let searchText: String
    @State private var severity = "All"
    @State private var action = "All"

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
                            AlertListHeader()
                            ForEach(alerts) { alert in
                                Divider()
                                ExpandableAlertRow(alert: alert, model: model)
                            }
                        }
                    }
                }
            }
        }
    }
}

struct AlertListHeader: View {
    var body: some View {
        HStack(spacing: 12) {
            Color.clear.frame(width: 14)
            Text("Severity").frame(width: 72, alignment: .leading)
            Text("Action").frame(width: 66, alignment: .leading)
            Text("Alert").frame(maxWidth: .infinity, alignment: .leading)
            Text("Path").frame(width: 210, alignment: .leading)
            Text("Time").frame(width: 128, alignment: .leading)
        }
        .font(.system(size: 11, weight: .semibold))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(Color.dashboardMutedFill)
    }
}

struct ExpandableAlertRow: View {
    let alert: SecurityAlert
    @ObservedObject var model: ConsoleModel
    @State private var expanded = false

    private var feedbackPending: Bool { model.feedbackAlertID == alert.alertID }
    private var unread: Bool { !model.isAlertRead(alert.alertID) }
    private var helpfulSelected: Bool { alert.humanVerdict == "agree" }
    private var inaccurateSelected: Bool {
        guard let verdict = alert.humanVerdict else { return false }
        return verdict == "allow" || verdict == "deny"
    }

    var body: some View {
        VStack(spacing: 0) {
            Button {
                model.markAlertRead(alert.alertID)
                expanded.toggle()
            } label: {
                HStack(spacing: 12) {
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
                    DashboardTag(text: alert.severity, color: severityColor(alert.severity))
                        .frame(width: 72, alignment: .leading)
                    DashboardTag(text: alert.action, color: actionColor(alert.action))
                        .frame(width: 66, alignment: .leading)
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(alert.message)
                                .font(.system(size: 12, weight: unread ? .semibold : .medium))
                                .lineLimit(expanded ? 2 : 1)
                            if alert.humanVerdict != nil {
                                Image(systemName: helpfulSelected ? "hand.thumbsup.fill" : "hand.thumbsdown.fill")
                                    .font(.system(size: 10))
                                    .foregroundStyle(helpfulSelected ? Color.dashboardGreen : Color.dashboardGold)
                                    .help(helpfulSelected ? "You marked this alert helpful" : "You marked this alert inaccurate")
                            }
                        }
                        Text(alert.ruleID)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    Text(alert.path.map(abbreviatedPath) ?? "—")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(alert.path == nil ? .tertiary : .secondary)
                        .frame(width: 210, alignment: .leading)
                        .lineLimit(1)
                    Text(dashboardDate(alert.createdAt))
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .frame(width: 128, alignment: .leading)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 9)
                .contentShape(Rectangle())
                .background(unread ? Color.dashboardRed.opacity(0.035) : .clear)
            }
            .buttonStyle(.plain)
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

            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Was this alert useful?").font(.system(size: 12, weight: .semibold))
                    Text(feedbackStatus)
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if feedbackPending { ProgressView().controlSize(.small) }
                feedbackButton(
                    title: "Helpful",
                    symbol: helpfulSelected ? "hand.thumbsup.fill" : "hand.thumbsup",
                    selected: helpfulSelected,
                    color: .dashboardGreen,
                    agrees: true
                )
                feedbackButton(
                    title: "Inaccurate",
                    symbol: inaccurateSelected ? "hand.thumbsdown.fill" : "hand.thumbsdown",
                    selected: inaccurateSelected,
                    color: .dashboardGold,
                    agrees: false
                )
            }
            .padding(.top, 2)
        }
        .padding(.leading, 36)
        .padding(.trailing, 10)
        .padding(.bottom, 16)
        .background(Color.dashboardMutedFill.opacity(0.45))
    }

    private var feedbackStatus: String {
        switch alert.feedbackLabel {
        case "confirmed": "Your feedback confirms this decision."
        case "false_positive": "You marked this alert as a false positive."
        case "false_negative": "You marked this alert as a false negative."
        case .some: "Your latest feedback is recorded."
        case nil: "Your choice is stored with this alert for policy tuning."
        }
    }

    private func feedbackButton(
        title: String,
        symbol: String,
        selected: Bool,
        color: Color,
        agrees: Bool
    ) -> some View {
        Button {
            Task { _ = await model.recordFeedback(for: alert, agrees: agrees) }
        } label: {
            Label(title, systemImage: symbol)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(selected ? color : .primary)
        }
        .buttonStyle(.bordered)
        .tint(selected ? color : .secondary)
        .disabled(feedbackPending || selected || (model.feedbackAlertID != nil && !feedbackPending))
        .accessibilityLabel("Mark alert as \(title.lowercased())")
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
        model.snapshot.artifacts.filter { containsSearch(searchText, fields: $0.uri, $0.kind, $0.lastModifiedSource, $0.riskLevel) }
    }

    private var selectedArtifact: ArtifactFact? {
        guard let selectedURI else { return nil }
        return artifacts.first { $0.uri == selectedURI }
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Lineage Graph", description: "Artifact relationships and provenance tracked by Gensee.")
                HStack(alignment: .top, spacing: 16) {
                    DashboardCard("Artifacts (\(artifacts.count))") {
                        if artifacts.isEmpty { DashboardEmpty(text: "No artifact facts recorded yet.") }
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
                                                        .font(.system(size: 9, design: .monospaced))
                                                        .foregroundStyle(.secondary)
                                                        .lineLimit(1)
                                                        .truncationMode(.middle)
                                                    Text([artifact.kind, artifact.lastModifiedSource, artifact.riskLevel].compactMap { $0 }.joined(separator: " · "))
                                                        .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                                                }
                                                Spacer()
                                            }
                                            .padding(.vertical, 6).padding(.horizontal, 4)
                                            .background(selectedURI == artifact.uri ? Color.dashboardBlue.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 4))
                                            .contentShape(Rectangle())
                                        }
                                        .buttonStyle(.plain)
                                        .help(artifact.filePath)
                                    }
                                }
                            }.frame(maxHeight: 520)
                        }
                    }.frame(width: 370)

                    DashboardCard("Lineage Graph (\(artifacts.count))") {
                        VStack(alignment: .leading, spacing: 10) {
                            if let selectedArtifact {
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Text("Selected path")
                                        .font(.system(size: 10, weight: .semibold))
                                        .foregroundStyle(.secondary)
                                    Text(abbreviatedPath(selectedArtifact.filePath))
                                        .font(.system(size: 10, design: .monospaced))
                                        .textSelection(.enabled)
                                        .lineLimit(2)
                                        .truncationMode(.middle)
                                        .help(selectedArtifact.filePath)
                                    Spacer(minLength: 0)
                                }
                                .padding(.horizontal, 4)
                                Divider()
                            }
                            ArtifactGraphView(facts: artifacts, edges: model.snapshot.relations, selectedURI: $selectedURI)
                                .frame(minHeight: 420)
                        }
                    }.frame(maxWidth: .infinity)
                }
            }
        }
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
                                                .font(.system(size: 9, design: .monospaced))
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

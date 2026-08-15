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
            && containsSearch(searchText, fields: $0.message, $0.ruleID, $0.path, $0.sessionID)
        }
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Alerts", description: "Policy decisions and risk findings across all sessions.") {
                    HStack(spacing: 8) {
                        Picker("Severity", selection: $severity) { ForEach(["All", "Info", "Low", "Medium", "High", "Critical"], id: \.self, content: Text.init) }.frame(width: 120)
                        Picker("Action", selection: $action) { ForEach(["All", "Allow", "Warn", "Ask", "Block"], id: \.self, content: Text.init) }.frame(width: 110)
                        DashboardRefreshButton(refreshing: model.isRefreshing) { Task { await model.refreshAll() } }
                    }.controlSize(.small)
                }
                DashboardCard {
                    if alerts.isEmpty { DashboardEmpty(text: "No alerts found.", symbol: "checkmark.shield") }
                    else {
                        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 0) {
                            GridRow { Text("Severity"); Text("Action"); Text("Rule"); Text("Message"); Text("Path"); Text("Time") }
                                .font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                            Divider().gridCellColumns(6)
                            ForEach(alerts) { alert in
                                DashboardAlertRow(alert: alert)
                                Divider().gridCellColumns(6)
                            }
                        }
                    }
                }
            }
        }
    }
}

struct LineagePage: View {
    @ObservedObject var model: ConsoleModel
    let searchText: String
    @State private var selectedURI: String?

    private var artifacts: [ArtifactFact] {
        model.snapshot.artifacts.filter { containsSearch(searchText, fields: $0.uri, $0.kind, $0.lastModifiedSource, $0.riskLevel) }
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
                                                    Text(URL(fileURLWithPath: artifact.uri.replacingOccurrences(of: "file://", with: "")).lastPathComponent)
                                                        .font(.system(size: 12, weight: selectedURI == artifact.uri ? .semibold : .regular)).lineLimit(1)
                                                    Text([artifact.kind, artifact.lastModifiedSource, artifact.riskLevel].compactMap { $0 }.joined(separator: " · "))
                                                        .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                                                }
                                                Spacer()
                                            }
                                            .padding(.vertical, 6).padding(.horizontal, 4)
                                            .background(selectedURI == artifact.uri ? Color.dashboardBlue.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 4))
                                            .contentShape(Rectangle())
                                        }.buttonStyle(.plain)
                                    }
                                }
                            }.frame(maxHeight: 520)
                        }
                    }.frame(width: 330)

                    DashboardCard("Lineage Graph") {
                        ArtifactGraphView(facts: Array(artifacts.prefix(6)), edges: model.snapshot.relations, selectedURI: $selectedURI)
                            .frame(minHeight: 420)
                    }.frame(maxWidth: .infinity)
                }
            }
        }
    }
}

private struct ArtifactGraphView: View {
    let facts: [ArtifactFact]
    let edges: [ArtifactEdge]
    @Binding var selectedURI: String?

    var body: some View {
        if facts.isEmpty { DashboardEmpty(text: "No artifact facts recorded yet.") }
        else {
            GeometryReader { geometry in
                let positions = Dictionary(uniqueKeysWithValues: facts.enumerated().map { index, fact in
                    let columns = min(3, max(1, facts.count))
                    let col = index % columns
                    let row = index / columns
                    let x = (geometry.size.width / CGFloat(columns)) * (CGFloat(col) + 0.5)
                    let y = 84 + CGFloat(row) * 150
                    return (fact.uri, CGPoint(x: x, y: y))
                })
                ZStack {
                    Canvas { context, _ in
                        for edge in edges {
                            guard let source = positions[edge.sourceURI], let destination = positions[edge.destinationURI] else { continue }
                            var path = Path(); path.move(to: source); path.addLine(to: destination)
                            let highlighted = selectedURI == edge.sourceURI || selectedURI == edge.destinationURI
                            context.stroke(path, with: .color(highlighted ? .dashboardRed : .secondary.opacity(0.45)), lineWidth: highlighted ? 2 : 1)
                        }
                    }
                    ForEach(facts) { fact in
                        if let position = positions[fact.uri] {
                            Button { selectedURI = selectedURI == fact.uri ? nil : fact.uri } label: {
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(URL(fileURLWithPath: fact.uri.replacingOccurrences(of: "file://", with: "")).lastPathComponent)
                                        .font(.system(size: 12, weight: .semibold)).lineLimit(1)
                                    Text(fact.lastModifiedSource ?? fact.kind).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                                    DashboardTag(text: artifactClass(fact), color: artifactClass(fact) == "sensitive" ? .orange : .dashboardBlue)
                                }
                                .padding(10).frame(width: 150, height: 88, alignment: .leading)
                                .background(Color.dashboardPanel, in: RoundedRectangle(cornerRadius: 8))
                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(selectedURI == fact.uri ? Color.dashboardRed : Color.dashboardLine, lineWidth: selectedURI == fact.uri ? 2.5 : 1))
                            }.buttonStyle(.plain).position(position)
                        }
                    }
                }
            }
        }
    }

    private func artifactClass(_ fact: ArtifactFact) -> String {
        fact.riskLevel != nil || fact.isMemoryArtifact != 0 || fact.isControlPlane != 0 || fact.isPersistentTarget != 0 ? "sensitive" : "benign"
    }
}

struct FeedbackPage: View {
    @ObservedObject var model: ConsoleModel
    let searchText: String
    @State private var showingForm = false

    private var feedback: [HumanFeedback] {
        model.snapshot.humanFeedback.filter { containsSearch(searchText, fields: $0.humanVerdict, $0.label, $0.genseeAction, $0.ruleID, $0.path, $0.note) }
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Feedback", description: "Human review verdicts on shield decisions — used for policy tuning.") {
                    HStack(spacing: 8) {
                        Button { showingForm = true } label: { Label("Record verdict", systemImage: "plus") }.buttonStyle(.borderedProminent).tint(.dashboardRed)
                        DashboardRefreshButton(refreshing: model.isRefreshing) { Task { await model.refreshAll() } }
                    }.controlSize(.small)
                }
                DashboardCard {
                    if feedback.isEmpty { DashboardEmpty(text: "No feedback recorded yet.", symbol: "hand.thumbsup") }
                    else {
                        VStack(spacing: 0) {
                            DashboardTableHeader(columns: [("Verdict", 90), ("Label", 120), ("Gensee action", 110), ("Rule", 180), ("Path", nil), ("Time", 140)])
                            ForEach(feedback) { item in
                                HStack(spacing: 12) {
                                    DashboardTag(text: item.humanVerdict, color: item.humanVerdict == "deny" ? .red : item.humanVerdict == "allow" ? .blue : .green).frame(width: 90, alignment: .leading)
                                    DashboardTag(text: item.label ?? "—", color: item.label == "false_negative" ? .red : item.label == "false_positive" ? .orange : .green).frame(width: 120, alignment: .leading)
                                    Text(item.genseeAction ?? "—").frame(width: 110, alignment: .leading)
                                    Text(item.ruleID ?? "—").frame(width: 180, alignment: .leading).lineLimit(1)
                                    Text(item.path.map(abbreviatedPath) ?? "—").font(.system(size: 11, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading).lineLimit(1)
                                    Text(dashboardDate(item.createdAt)).foregroundStyle(.secondary).frame(width: 140, alignment: .leading)
                                }.font(.system(size: 11)).padding(.horizontal, 10).padding(.vertical, 7)
                                Divider()
                            }
                        }
                    }
                }
            }
        }
        .sheet(isPresented: $showingForm) { FeedbackForm(model: model, isPresented: $showingForm) }
    }
}

private struct FeedbackForm: View {
    @ObservedObject var model: ConsoleModel
    @Binding var isPresented: Bool
    @State private var verdict = "agree"
    @State private var action = ""
    @State private var ruleID = ""
    @State private var path = ""
    @State private var note = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Record verdict").font(.title2.weight(.semibold))
            Form {
                Picker("Verdict", selection: $verdict) {
                    Text("Agree (confirmed)").tag("agree")
                    Text("Allow (false positive)").tag("allow")
                    Text("Deny (false negative)").tag("deny")
                }
                TextField("Gensee action", text: $action, prompt: Text("block / ask / allow / warn"))
                TextField("Rule ID", text: $ruleID)
                TextField("Path", text: $path)
                TextField("Note", text: $note)
            }
            HStack { Spacer(); Button("Cancel") { isPresented = false }; Button("Save") { Task { if await model.recordFeedback(verdict: verdict, action: action, ruleID: ruleID, path: path, note: note) { isPresented = false } } }.buttonStyle(.borderedProminent).tint(.dashboardRed) }
        }.padding(24).frame(width: 520)
    }
}

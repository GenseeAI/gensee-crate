import SwiftUI

struct LiveFeedPage: View {
    @ObservedObject var model: ConsoleModel
    let searchText: String
    @State private var enabled = true
    @State private var category = "All"
    @State private var eventType = "All"

    private var agentEvents: [AgentEvent] {
        model.snapshot.agentEvents.filter {
            (category == "All" || category == "Agent activity")
            && (eventType == "All" || $0.type == eventType)
            && containsSearch(searchText, fields: $0.type, $0.toolName, $0.cwd, $0.source)
        }
    }
    private var transactionEvents: [TransactionEvent] {
        model.snapshot.transactionEvents.filter {
            (category == "All" || category == "Transactional environment")
            && containsSearch(searchText, fields: $0.operation, $0.summary, $0.workspace, $0.sourceRunID, $0.targetRunID)
        }
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Live Feed", description: "Real-time stream of agent hook events.") {
                    HStack(spacing: 12) {
                        LiveFeedConnectionBadge(connected: model.backendAvailable)
                        Picker("Category", selection: $category) {
                            ForEach(["All", "Agent activity", "Transactional environment"], id: \.self, content: Text.init)
                        }.frame(width: 190)
                        Picker("Type", selection: $eventType) {
                            ForEach(["All", "PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop"], id: \.self, content: Text.init)
                        }.frame(width: 160).disabled(category == "Transactional environment")
                        Button { enabled.toggle() } label: { Image(systemName: enabled ? "pause.circle" : "play.circle") }.help(enabled ? "Pause" : "Resume")
                    }.controlSize(.small)
                }
                DashboardCard("Events (\(agentEvents.count + transactionEvents.count) / \(model.snapshot.agentEvents.count + model.snapshot.transactionEvents.count) total)") {
                    if agentEvents.isEmpty && transactionEvents.isEmpty {
                        DashboardEmpty(text: model.backendAvailable ? "Waiting for agent events…" : "Not connected — check the Gensee backend.", symbol: "bolt")
                    } else {
                        VStack(spacing: 0) {
                            ForEach(agentEvents.prefix(150)) { event in
                                HStack(spacing: 12) {
                                    Text(dashboardTime(event.timestamp)).frame(width: 80, alignment: .leading).foregroundStyle(.secondary)
                                    DashboardTag(text: event.type, color: event.type == "PostToolUse" ? .green : event.type == "PreToolUse" ? .blue : .purple)
                                    if let tool = event.toolName { Text(tool).font(.system(size: 11, design: .monospaced)).padding(.horizontal, 5).background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 3)) }
                                    Text(abbreviatedPath(event.cwd)).lineLimit(1).foregroundStyle(.secondary)
                                    Spacer()
                                    Text("pid \(event.pid)").foregroundStyle(.tertiary)
                                }.font(.system(size: 11)).padding(.vertical, 6)
                                Divider()
                            }
                            ForEach(transactionEvents.prefix(150)) { event in
                                HStack(spacing: 12) {
                                    Text(dashboardTime(event.occurredAt)).frame(width: 80, alignment: .leading).foregroundStyle(.secondary)
                                    DashboardTag(text: "Transactional environment", color: .purple)
                                    DashboardTag(text: "\(event.operation) · \(event.phase)", color: event.phase == "failed" ? .red : event.phase == "started" ? .blue : .green)
                                    Text(event.summary).lineLimit(1)
                                    Spacer()
                                }.font(.system(size: 11)).padding(.vertical, 6)
                                Divider()
                            }
                        }
                    }
                }
            }
        }
        .task(id: enabled) {
            while enabled && !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                if enabled { await model.refreshDashboard(reportErrors: false) }
            }
        }
    }
}

private struct LiveFeedConnectionBadge: View {
    let connected: Bool

    private var color: Color { connected ? .green : .red }

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "circle.fill")
                .font(.system(size: 8, weight: .semibold))
            Text(connected ? "Connected" : "Disconnected")
                .font(.system(size: 11, weight: .semibold))
                .lineLimit(1)
        }
        .foregroundStyle(color)
        .padding(.horizontal, 9)
        .frame(height: 24)
        .background(color.opacity(0.10), in: Capsule())
        .fixedSize(horizontal: true, vertical: false)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(connected ? "Gensee backend connected" : "Gensee backend disconnected")
    }
}

struct TimelinePage: View {
    @ObservedObject var model: ConsoleModel
    let searchText: String
    @State private var source = "All"
    @State private var hideEmpty = true

    private var sessions: [RecordedSession] {
        model.snapshot.sessions.filter {
            (source == "All" || $0.agentID.localizedCaseInsensitiveContains(source))
            && (!hideEmpty || ($0.requestCount ?? 0) > 0 || ($0.eventCount ?? 0) > 0)
            && containsSearch(searchText, fields: $0.sessionID, $0.agentID)
        }
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Timeline", description: "Chronological history of agent sessions and requests.") {
                    HStack(spacing: 8) {
                        Picker("Agent", selection: $source) {
                            ForEach(["All", "claude-code", "codex", "antigravity", "sidecar-watch", "system-monitor"], id: \.self, content: Text.init)
                        }.frame(width: 160)
                        Toggle("Hide empty", isOn: $hideEmpty).toggleStyle(.switch).font(.system(size: 11))
                        DashboardRefreshButton(refreshing: model.isRefreshing) { Task { await model.refreshAll() } }
                    }.controlSize(.small)
                }
                DashboardCard {
                    if sessions.isEmpty { DashboardEmpty(text: "No sessions recorded yet.", symbol: "clock") }
                    else {
                        VStack(spacing: 8) {
                            ForEach(sessions) { session in SessionDisclosure(session: session, model: model) }
                        }
                    }
                }
            }
        }
    }
}

private struct SessionDisclosure: View {
    let session: RecordedSession
    @ObservedObject var model: ConsoleModel
    @State private var expanded = false

    private var events: [AgentEvent] { model.snapshot.agentEvents.filter { $0.sessionID == session.sessionID }.sorted { $0.timestamp > $1.timestamp } }

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            if events.isEmpty { DashboardEmpty(text: "No requests in this session yet.") }
            else {
                VStack(spacing: 0) {
                    ForEach(events) { event in
                        HStack(spacing: 10) {
                            Text(dashboardTime(event.timestamp)).foregroundStyle(.secondary).frame(width: 80, alignment: .leading)
                            DashboardTag(text: event.type, color: .dashboardBlue)
                            Text(event.toolName ?? "(no tool)").font(.system(size: 11, design: .monospaced))
                            Text(event.toolInput ?? "").lineLimit(1).foregroundStyle(.secondary)
                            Spacer()
                        }.font(.system(size: 11)).padding(.vertical, 6)
                        Divider()
                    }
                }.padding(.leading, 20)
            }
        } label: {
            HStack(spacing: 10) {
                if session.flagged != 0 { DashboardTag(text: "High", color: .red) }
                Text(session.sessionID.count > 22 ? "\(session.sessionID.prefix(18))…" : session.sessionID).font(.system(size: 11, design: .monospaced))
                DashboardTag(text: session.agentID, color: session.sessionID == "system" ? .orange : .secondary)
                Text("\(session.requestCount ?? 0) req · \(session.eventCount ?? 0) events").font(.system(size: 11)).foregroundStyle(.secondary)
                Spacer()
                Text(dashboardDate(session.firstEventAt)).font(.system(size: 11)).foregroundStyle(.secondary)
            }.padding(.vertical, 6)
        }
        .padding(.horizontal, 10)
        .background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))
    }
}

struct TransactionsPage: View {
    @ObservedObject var model: ConsoleModel
    let searchText: String
    @State private var view = "Dependencies"
    @State private var operation = "All"
    @State private var phase = "All"

    private var events: [TransactionEvent] {
        model.snapshot.transactionEvents.filter {
            (operation == "All" || $0.operation == operation.lowercased())
            && (phase == "All" || $0.phase == phase.lowercased())
            && containsSearch(searchText, fields: $0.operationID, $0.summary, $0.workspace, $0.sourceRunID, $0.targetRunID)
        }
    }
    private var groups: [(String, [TransactionEvent])] {
        Dictionary(grouping: events, by: { $0.operationID }).map { ($0.key, $0.value.sorted { $0.occurredAt < $1.occurredAt }) }.sorted { ($0.1.last?.occurredAt ?? 0) > ($1.1.last?.occurredAt ?? 0) }
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Transactions", description: "History and dependencies for transactional environments.") {
                    HStack(spacing: 8) {
                        Label(model.backendAvailable ? "Live" : "Offline", systemImage: "circle.fill").font(.system(size: 11)).foregroundStyle(model.backendAvailable ? Color.green : Color.secondary)
                        Picker("View", selection: $view) { Text("Dependencies").tag("Dependencies"); Text("History").tag("History") }.pickerStyle(.segmented).labelsHidden().frame(width: 190)
                        Picker("Operation", selection: $operation) { ForEach(["All", "Source", "Fork", "Merge", "Switch", "Keep", "Discard", "Delete"], id: \.self, content: Text.init) }.frame(width: 130)
                        Picker("Status", selection: $phase) { ForEach(["All", "Started", "Succeeded", "Failed"], id: \.self, content: Text.init) }.frame(width: 120)
                        DashboardRefreshButton(refreshing: model.isRefreshing) { Task { await model.refreshAll() } }
                    }.controlSize(.small)
                }
                DashboardCard {
                    if groups.isEmpty { DashboardEmpty(text: "No transactional environment activity recorded yet.", symbol: "arrow.triangle.branch") }
                    else {
                        VStack(spacing: 8) {
                            ForEach(groups, id: \.0) { id, events in TransactionDisclosure(operationID: id, events: events, view: view) }
                        }
                    }
                }
            }
        }
    }
}

private struct TransactionDisclosure: View {
    let operationID: String
    let events: [TransactionEvent]
    let view: String
    @State private var expanded = true

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 10) {
                if view == "Dependencies" { dependencySummary }
                ForEach(events) { event in
                    HStack(spacing: 10) {
                        DashboardTag(text: event.operation, color: operationColor(event.operation))
                        DashboardTag(text: event.phase, color: event.phase == "failed" ? .red : event.phase == "started" ? .blue : .green)
                        Text(event.summary).font(.system(size: 12)).lineLimit(2)
                        Spacer()
                        Text(dashboardDate(event.occurredAt)).font(.system(size: 11)).foregroundStyle(.secondary)
                    }.padding(.vertical, 5)
                    Divider()
                }
            }.padding(.leading, 20).padding(.top, 8)
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(operationID).font(.system(size: 12, weight: .semibold, design: .monospaced))
                    Text(events.last?.workspace.map(abbreviatedPath) ?? "Unknown workspace").font(.system(size: 10)).foregroundStyle(.secondary)
                }
                Spacer()
                let forks = events.filter { $0.operation == "fork" && $0.phase == "succeeded" }.count
                let merges = events.filter { $0.operation == "merge" && $0.phase == "succeeded" }.count
                DashboardTag(text: "\(forks) forks", color: .cyan)
                DashboardTag(text: "\(merges) merged", color: .green)
            }.padding(.vertical, 6)
        }
        .padding(.horizontal, 10)
        .background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))
    }

    private var dependencySummary: some View {
        HStack(spacing: 8) {
            if let source = events.compactMap(\.sourceRunID).first { runNode(source, color: .dashboardBlue) }
            Image(systemName: "arrow.right").foregroundStyle(.secondary)
            DashboardTag(text: events.last?.operation ?? "operation", color: operationColor(events.last?.operation ?? ""))
            Image(systemName: "arrow.right").foregroundStyle(.secondary)
            if let target = events.compactMap(\.targetRunID).last { runNode(target, color: .dashboardGreen) }
        }
    }

    private func runNode(_ id: String, color: Color) -> some View {
        Text(id.count > 28 ? "\(id.prefix(14))…\(id.suffix(8))" : id)
            .font(.system(size: 11, design: .monospaced)).padding(8)
            .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 5))
            .overlay(RoundedRectangle(cornerRadius: 5).stroke(color.opacity(0.6)))
    }

    private func operationColor(_ operation: String) -> Color {
        switch operation { case "merge": .green; case "discard": .orange; case "delete": .red; case "switch": .purple; default: .blue }
    }
}

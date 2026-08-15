import Charts
import SwiftUI

struct DashboardOverviewPage: View {
    @ObservedObject var model: ConsoleModel
    @ObservedObject var sensor: EndpointSecuritySensor

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Dashboard", description: "Overview of agent activity, security alerts, and system health.")

                HStack(spacing: 10) {
                    Image(systemName: sensor.health.connected ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                        .foregroundStyle(sensor.health.connected ? .green : .orange)
                    Text(sensor.health.connected ? "Endpoint Security sensor connected" : "Endpoint Security sensor disconnected")
                        .font(.system(size: 12, weight: .semibold))
                    DashboardTag(text: sensor.health.mode.capitalized, color: sensor.health.mode == "observe" ? .dashboardBlue : .dashboardRed)
                    Text("\(sensor.health.ingestedEvents.formatted()) events ingested")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                    Spacer()
                    if sensor.health.hasDataLoss {
                        DashboardTag(text: "Event gaps detected", color: .dashboardRed)
                    } else {
                        DashboardTag(text: "No event gaps", color: .green)
                    }
                }
                .padding(12)
                .background(Color.dashboardPanel, in: RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.dashboardLine))

                HStack(spacing: 16) {
                    DashboardStatCard(title: "Sessions", value: model.snapshot.summary.sessionsCount, symbol: "person.2", color: .dashboardBlue)
                    DashboardStatCard(title: "Requests", value: model.snapshot.summary.requestsCount, symbol: "doc.text", color: .dashboardGreen)
                    DashboardStatCard(title: "Agent Events", value: model.snapshot.summary.agentEventsCount, symbol: "bolt", color: .dashboardGold)
                    DashboardStatCard(title: "High Alerts (24 h)", value: model.snapshot.summary.recentHighAlerts, symbol: "exclamationmark.triangle", color: .dashboardRed)
                }

                HStack(alignment: .top, spacing: 16) {
                    ActivityChartCard(model: model).frame(maxWidth: .infinity)
                    SeverityBreakdownCard(alerts: model.snapshot.alerts).frame(width: 360)
                }

                DashboardCard("Recent Alerts") {
                    if model.snapshot.alerts.isEmpty {
                        DashboardEmpty(text: "No recent alerts — all clear.", symbol: "checkmark.shield")
                    } else {
                        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 0) {
                            GridRow {
                                Text("Severity"); Text("Action"); Text("Rule"); Text("Message"); Text("Path"); Text("Time")
                            }
                            .font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                            Divider().gridCellColumns(6)
                            ForEach(model.snapshot.alerts.prefix(10)) { alert in
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

private struct ActivityPoint: Identifiable {
    let hour: Date
    let count: Int
    var id: Date { hour }
}

private struct ActivityChartCard: View {
    @ObservedObject var model: ConsoleModel
    @State private var range = "24 h"
    @State private var metric = "Sessions"

    private var data: [ActivityPoint] {
        let calendar = Calendar.current
        let slots = range == "7 d" ? 7 : 24
        let component: Calendar.Component = range == "7 d" ? .day : .hour
        let interval: TimeInterval = range == "7 d" ? 86_400 : 3_600
        let now = Date()
        let timestamps: [Int64]
        switch metric {
        case "Alerts": timestamps = model.snapshot.alerts.map(\.createdAt)
        case "Agent Events": timestamps = model.snapshot.agentEvents.map(\.timestamp)
        default: timestamps = model.snapshot.sessions.map(\.firstEventAt)
        }
        return (0..<slots).map { index in
            let date = now.addingTimeInterval(-Double(slots - 1 - index) * interval)
            let start = calendar.dateInterval(of: component, for: date)?.start ?? date
            let end = start.addingTimeInterval(interval)
            let count = timestamps.filter {
                let eventDate = Date(timeIntervalSince1970: Double($0) / 1_000)
                return eventDate >= start && eventDate < end
            }.count
            return ActivityPoint(hour: start, count: count)
        }
    }

    var body: some View {
        DashboardCard("Activity over time") {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Picker("Metric", selection: $metric) {
                        Text("Sessions").tag("Sessions")
                        Text("Agent Events").tag("Agent Events")
                        Text("Alerts").tag("Alerts")
                    }
                    .pickerStyle(.segmented).labelsHidden().frame(maxWidth: 340)
                    Spacer()
                    Picker("Range", selection: $range) {
                        Text("24 h").tag("24 h")
                        Text("7 d").tag("7 d")
                    }
                    .pickerStyle(.segmented).labelsHidden().frame(width: 120)
                }
                Chart(data) { point in
                    AreaMark(x: .value("Time", point.hour), y: .value("Count", point.count))
                        .foregroundStyle(metricColor.opacity(0.18))
                    LineMark(x: .value("Time", point.hour), y: .value("Count", point.count))
                        .foregroundStyle(metricColor).lineStyle(.init(lineWidth: 2))
                }
                .chartYAxis { AxisMarks(position: .leading) }
                .frame(height: 205)
            }
        }
    }

    private var metricColor: Color {
        metric == "Alerts" ? .dashboardRed : metric == "Agent Events" ? .dashboardGold : .dashboardBlue
    }
}

private struct SeverityBreakdownCard: View {
    let alerts: [SecurityAlert]
    private let severities = ["critical", "high", "medium", "low", "info"]
    private var counts: [(String, Int)] { severities.map { value in (value, alerts.filter { $0.severity.lowercased() == value }.count) } }

    var body: some View {
        DashboardCard("Alert severity breakdown") {
            HStack(spacing: 22) {
                ZStack {
                    Circle().stroke(Color.dashboardMutedFill, lineWidth: 16)
                    Circle().trim(from: 0, to: min(1, alerts.isEmpty ? 0 : Double(alerts.filter { ["critical", "high"].contains($0.severity.lowercased()) }.count) / Double(alerts.count)))
                        .stroke(Color.dashboardRed, style: StrokeStyle(lineWidth: 16, lineCap: .butt))
                        .rotationEffect(.degrees(-90))
                    VStack(spacing: 0) {
                        Text(alerts.count.formatted()).font(.system(size: 23, weight: .semibold))
                        Text("alerts").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .frame(width: 132, height: 132)
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(counts, id: \.0) { severity, count in
                        HStack {
                            Circle().fill(severityColor(severity)).frame(width: 8, height: 8)
                            Text(severity.capitalized).font(.system(size: 11))
                            Spacer()
                            Text(count.formatted()).font(.system(size: 11, weight: .semibold))
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, minHeight: 220)
        }
    }
}

struct TodayHighlightPage: View {
    @ObservedObject var model: ConsoleModel
    @State private var date = Date()

    private var day: DateInterval { Calendar.current.dateInterval(of: .day, for: date)! }
    private var agentEvents: [AgentEvent] { model.snapshot.agentEvents.filter { day.contains(Date(timeIntervalSince1970: Double($0.timestamp) / 1_000)) } }
    private var alerts: [SecurityAlert] { model.snapshot.alerts.filter { day.contains(Date(timeIntervalSince1970: Double($0.createdAt) / 1_000)) } }
    private var sessions: [RecordedSession] { model.snapshot.sessions.filter { day.contains(Date(timeIntervalSince1970: Double($0.firstEventAt) / 1_000)) } }
    private var requests: Int { Set(agentEvents.map(\.requestID)).count }
    private var filesWritten: Int { agentEvents.filter { event in ["write", "edit", "create"].contains(where: { (event.toolName ?? "").localizedCaseInsensitiveContains($0) }) }.count }
    private var filesRead: Int { agentEvents.filter { ($0.toolName ?? "").localizedCaseInsensitiveContains("read") }.count }
    private var webSearches: Int { agentEvents.filter { ($0.toolName ?? "").localizedCaseInsensitiveContains("search") }.count }
    private var webFetches: Int { agentEvents.filter { ($0.toolName ?? "").localizedCaseInsensitiveContains("fetch") }.count }
    private var topTools: [(String, Int)] {
        Dictionary(grouping: agentEvents.compactMap(\.toolName), by: { $0 })
            .map { ($0.key, $0.value.count) }.sorted { $0.1 > $1.1 }.prefix(8).map { $0 }
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Today's Highlight", description: friendlyDate) {
                    HStack(spacing: 6) {
                        Button { date = Calendar.current.date(byAdding: .day, value: -1, to: date)! } label: { Image(systemName: "chevron.left") }
                        Button("Today") { date = Date() }.disabled(Calendar.current.isDateInToday(date))
                        Button { date = Calendar.current.date(byAdding: .day, value: 1, to: date)! } label: { Image(systemName: "chevron.right") }
                            .disabled(Calendar.current.isDateInToday(date))
                    }.controlSize(.small)
                }
                metricRow([
                    ("Sessions", sessions.count, "person.2", Color.dashboardBlue),
                    ("Agent Turns", requests, "bolt", Color.dashboardGold),
                    ("Total Tool Calls", agentEvents.filter { $0.toolName != nil }.count, "chevron.left.forwardslash.chevron.right", Color.dashboardGreen),
                    ("Alerts", alerts.count, "exclamationmark.triangle", Color.dashboardRed),
                ])
                metricRow([
                    ("Files Written / Edited", filesWritten, "square.and.pencil", Color.dashboardBlue),
                    ("Files Read", filesRead, "book", Color.dashboardGreen),
                    ("Web Searches", webSearches, "globe", Color.dashboardGold),
                    ("URLs Fetched", webFetches, "doc.text", Color.purple),
                ])
                HStack(alignment: .top, spacing: 16) {
                    DashboardCard("Alert breakdown") {
                        HStack(alignment: .top, spacing: 40) {
                            breakdown("By action", values: ["block", "ask", "warn", "allow"], field: { $0.action })
                            breakdown("By severity", values: ["critical", "high", "medium", "low", "info"], field: { $0.severity })
                        }.frame(minHeight: 150, alignment: .top)
                    }
                    DashboardCard("Tool usage") {
                        if topTools.isEmpty { DashboardEmpty(text: "No tool calls recorded today.") }
                        else {
                            VStack(spacing: 0) {
                                ForEach(Array(topTools.enumerated()), id: \.offset) { _, tool in
                                    HStack {
                                        Text(tool.0).font(.system(size: 11, design: .monospaced))
                                        Spacer()
                                        ProgressView(value: Double(tool.1), total: Double(max(1, agentEvents.count))).frame(width: 90)
                                        Text(tool.1.formatted()).font(.system(size: 11, weight: .semibold)).frame(width: 34, alignment: .trailing)
                                    }.padding(.vertical, 6)
                                    Divider()
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private var friendlyDate: String {
        if Calendar.current.isDateInToday(date) { return "Today" }
        if Calendar.current.isDateInYesterday(date) { return "Yesterday" }
        return date.formatted(date: .complete, time: .omitted)
    }

    private func metricRow(_ items: [(String, Int, String, Color)]) -> some View {
        HStack(spacing: 16) { ForEach(Array(items.enumerated()), id: \.offset) { _, item in DashboardStatCard(title: item.0, value: item.1, symbol: item.2, color: item.3) } }
    }

    private func breakdown(_ title: String, values: [String], field: @escaping (SecurityAlert) -> String) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title).font(.system(size: 12)).foregroundStyle(.secondary)
            ForEach(values, id: \.self) { value in
                let count = alerts.filter { field($0).lowercased() == value }.count
                if count > 0 { HStack { DashboardTag(text: value, color: title.contains("action") ? actionColor(value) : severityColor(value)); Text(count.formatted()).font(.system(size: 12, weight: .semibold)) } }
            }
            if alerts.isEmpty { Text("No alerts today").font(.system(size: 12)).foregroundStyle(.secondary) }
        }
    }
}

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
                        VStack(spacing: 0) {
                            AlertListHeader()
                            ForEach(model.snapshot.alerts.prefix(10)) { alert in
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
    private var severityValues: [String] { alerts.map(\.severity) }
    private var severityCounts: [String: Int] { AlertSeverityBreakdown.counts(for: severityValues) }
    private var slices: [AlertSeveritySlice] { AlertSeverityBreakdown.slices(for: severityValues) }

    var body: some View {
        DashboardCard("Alert severity breakdown") {
            HStack(spacing: 22) {
                ZStack {
                    Circle().stroke(Color.dashboardMutedFill, lineWidth: 16)
                    ForEach(slices) { slice in
                        Circle()
                            .trim(from: slice.startFraction, to: slice.endFraction)
                            .stroke(severityColor(slice.severity), style: StrokeStyle(lineWidth: 16, lineCap: .butt))
                            .rotationEffect(.degrees(-90))
                    }
                    VStack(spacing: 0) {
                        Text(alerts.count.formatted()).font(.system(size: 23, weight: .semibold))
                        Text("alerts").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .frame(width: 132, height: 132)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Alert severity chart")
                .accessibilityValue(accessibilityBreakdown)
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(AlertSeverityBreakdown.orderedSeverities, id: \.self) { severity in
                        HStack {
                            Circle().fill(severityColor(severity)).frame(width: 8, height: 8)
                            Text(severity.capitalized).font(.system(size: 11))
                            Spacer()
                            Text(severityCounts[severity, default: 0].formatted()).font(.system(size: 11, weight: .semibold))
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, minHeight: 220)
        }
    }

    private var accessibilityBreakdown: String {
        AlertSeverityBreakdown.orderedSeverities
            .map { "\($0.capitalized) \(severityCounts[$0, default: 0])" }
            .joined(separator: ", ")
    }
}

struct TodayHighlightPage: View {
    @ObservedObject var model: ConsoleModel
    @State private var date = Date()

    private var selectedActivity: DailyActivity? { model.snapshot.dailyActivity.first { $0.date == dayKey(date) } }
    private var selectedDetail: DailyDetail? { model.dailyDetail?.date == dayKey(date) ? model.dailyDetail : nil }
    private var requests: Int { selectedDetail?.requests ?? selectedActivity?.requests ?? 0 }
    private var toolCalls: Int { selectedDetail?.toolCalls ?? selectedActivity?.toolCalls ?? 0 }
    private var alertCount: Int { selectedDetail?.alerts ?? selectedActivity?.alerts ?? 0 }
    private var tokenCount: Int { selectedDetail?.tokens ?? selectedActivity?.tokens ?? 0 }
    private var detailUnavailableMessage: String? {
        guard case let .unavailable(day, message) = model.dailyDetailLoadState,
              day == dayKey(date)
        else { return nil }
        return message
    }
    private var detailIsLoading: Bool {
        guard case let .loading(day) = model.dailyDetailLoadState else { return false }
        return day == dayKey(date)
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Daily Highlight", description: "Today at a glance, with a rolling year of agent activity.") {
                    HStack(spacing: 6) {
                        Button { date = Calendar.current.date(byAdding: .day, value: -1, to: date)! } label: { Image(systemName: "chevron.left") }
                        Button("Today") { date = Date() }.disabled(Calendar.current.isDateInToday(date))
                        Button { date = Calendar.current.date(byAdding: .day, value: 1, to: date)! } label: { Image(systemName: "chevron.right") }
                            .disabled(Calendar.current.isDateInToday(date))
                    }.controlSize(.small)
                }
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(Calendar.current.isDateInToday(date) ? "TODAY'S HIGHLIGHT" : "DAILY HIGHLIGHT")
                            .font(.system(size: 10, weight: .bold))
                            .tracking(1.1)
                            .foregroundStyle(.secondary)
                        Text(friendlyDate)
                            .font(.system(size: 17, weight: .semibold))
                    }
                    Spacer()
                    if requests > 0 && tokenCount == 0 {
                        Label("No compatible token usage was captured for this date", systemImage: "info.circle")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                }
                metricRow([
                    ("Agent Turns", requests, "bolt", Color.dashboardGold),
                    ("Tool Calls", toolCalls, "chevron.left.forwardslash.chevron.right", Color.dashboardGreen),
                    ("Alerts", alertCount, "exclamationmark.triangle", Color.dashboardRed),
                    ("Tokens", tokenCount, "text.word.spacing", Color.purple),
                ])
                if let detail = selectedDetail {
                    metricRow([
                        ("Sessions", detail.sessions, "person.2", Color.dashboardBlue),
                        ("Files Written / Edited", detail.filesWritten, "square.and.pencil", Color.dashboardBlue),
                        ("Files Read", detail.filesRead, "book", Color.dashboardGreen),
                        ("Web Requests", detail.webRequests, "globe", Color.dashboardGold),
                    ])
                    HStack(alignment: .top, spacing: 16) {
                        DashboardCard("Alert breakdown") {
                            HStack(alignment: .top, spacing: 40) {
                                breakdown("By action", values: detail.alertsByAction)
                                breakdown("By severity", values: detail.alertsBySeverity)
                            }.frame(minHeight: 150, alignment: .top)
                        }
                        DashboardCard("Tool usage") {
                            if detail.topTools.isEmpty { DashboardEmpty(text: "No tool calls recorded for this date.") }
                            else {
                                VStack(spacing: 0) {
                                    ForEach(Array(detail.topTools.enumerated()), id: \.offset) { _, tool in
                                        HStack {
                                            Text(tool.name).font(.system(size: 11, design: .monospaced))
                                            Spacer()
                                            ProgressView(value: Double(tool.count), total: Double(max(1, toolCalls))).frame(width: 90)
                                            Text(tool.count.formatted()).font(.system(size: 11, weight: .semibold)).frame(width: 34, alignment: .trailing)
                                        }.padding(.vertical, 6)
                                        Divider()
                                    }
                                }
                            }
                        }
                    }
                } else {
                    DashboardCard("Daily details") {
                        HStack(spacing: 10) {
                            if detailIsLoading {
                                ProgressView().controlSize(.small)
                                Text("Loading session, file, web, alert, and tool details…")
                            } else if let detailUnavailableMessage {
                                Image(systemName: "exclamationmark.triangle")
                                    .foregroundStyle(Color.dashboardGold)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("Detailed activity is unavailable for this date.")
                                        .font(.system(size: 12, weight: .semibold))
                                    Text(detailUnavailableMessage)
                                        .font(.system(size: 11))
                                        .foregroundStyle(.secondary)
                                        .lineLimit(2)
                                }
                            } else {
                                ProgressView().controlSize(.small)
                                Text("Preparing daily details…")
                            }
                        }
                        .frame(maxWidth: .infinity, minHeight: 90, alignment: .leading)
                    }
                }
                DashboardCard("Rolling 53-week activity") {
                    VStack(alignment: .leading, spacing: 22) {
                        CalendarHeatmap(
                            title: "Agent turns",
                            detail: "One request submitted to an agent",
                            activity: model.snapshot.dailyActivity,
                            value: \.requests,
                            color: .dashboardBlue,
                            selectedDate: $date
                        )
                        Divider()
                        CalendarHeatmap(
                            title: "Tool calls",
                            detail: "Tools invoked before execution",
                            activity: model.snapshot.dailyActivity,
                            value: \.toolCalls,
                            color: .dashboardGreen,
                            selectedDate: $date
                        )
                        Divider()
                        CalendarHeatmap(
                            title: "Alerts",
                            detail: "Policy and security findings",
                            activity: model.snapshot.dailyActivity,
                            value: \.alerts,
                            color: .dashboardRed,
                            selectedDate: $date
                        )
                        Divider()
                        CalendarHeatmap(
                            title: "Tokens",
                            detail: "Captured from supported completed turns",
                            activity: model.snapshot.dailyActivity,
                            value: \.tokens,
                            color: .purple,
                            selectedDate: $date
                        )
                    }
                }
            }
        }
        .task(id: dayKey(date)) {
            await model.refreshDailyDetail(day: dayKey(date))
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

    private func breakdown(_ title: String, values: [DailyCount]) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title).font(.system(size: 12)).foregroundStyle(.secondary)
            ForEach(values) { value in
                if value.count > 0 { HStack { DashboardTag(text: value.name, color: title.contains("action") ? actionColor(value.name) : severityColor(value.name)); Text(value.count.formatted()).font(.system(size: 12, weight: .semibold)) } }
            }
            if values.isEmpty { Text("No alerts for this date").font(.system(size: 12)).foregroundStyle(.secondary) }
        }
    }
}

private struct HeatmapDay: Identifiable {
    let date: Date
    let value: Int
    let isFuture: Bool
    var id: Date { date }
}

private struct MonthMarker: Identifiable {
    let week: Int
    let label: String
    var id: Int { week }
}

private struct CalendarHeatmap: View {
    let title: String
    let detail: String
    let activity: [DailyActivity]
    let value: KeyPath<DailyActivity, Int>
    let color: Color
    @Binding var selectedDate: Date
    @State private var hoveredDay: HeatmapDay?

    private let cellSize: CGFloat = 11
    private let gap: CGFloat = 3
    private let weeks = 53
    private var calendar: Calendar {
        var result = Calendar(identifier: .gregorian)
        result.locale = Locale(identifier: "en_US_POSIX")
        result.timeZone = .current
        result.firstWeekday = 1
        return result
    }
    private var today: Date { calendar.startOfDay(for: Date()) }
    private var startDate: Date {
        let currentWeek = calendar.dateInterval(of: .weekOfYear, for: today)?.start ?? today
        return calendar.date(byAdding: .weekOfYear, value: -(weeks - 1), to: currentWeek) ?? currentWeek
    }
    private var valuesByDay: [String: Int] {
        Dictionary(activity.map { ($0.date, $0[keyPath: value]) }, uniquingKeysWith: +)
    }
    private var columns: [[HeatmapDay]] {
        (0..<weeks).map { week in
            (0..<7).compactMap { weekday in
                guard let date = calendar.date(byAdding: .day, value: week * 7 + weekday, to: startDate) else { return nil }
                return HeatmapDay(date: date, value: valuesByDay[dayKey(date)] ?? 0, isFuture: date > today)
            }
        }
    }
    private var maximum: Int { max(1, activity.map { $0[keyPath: value] }.max() ?? 0) }
    private var total: Int { activity.reduce(0) { $0 + $1[keyPath: value] } }
    private var activeDays: Int { activity.filter { $0[keyPath: value] > 0 }.count }
    private var gridWidth: CGFloat { CGFloat(weeks) * cellSize + CGFloat(weeks - 1) * gap }
    private var monthMarkers: [MonthMarker] {
        var lastMonth = -1
        return (0..<weeks).compactMap { week in
            guard let date = calendar.date(byAdding: .weekOfYear, value: week, to: startDate) else { return nil }
            let month = calendar.component(.month, from: date)
            guard month != lastMonth else { return nil }
            lastMonth = month
            return MonthMarker(week: week, label: date.formatted(.dateTime.month(.abbreviated)))
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: 13, weight: .semibold))
                    Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 3) {
                    if let hoveredDay {
                        HStack(spacing: 5) {
                            Text(hoveredDay.date.formatted(date: .abbreviated, time: .omitted))
                                .foregroundStyle(.secondary)
                            Text(hoveredDay.value.formatted())
                                .fontWeight(.semibold)
                                .foregroundStyle(Color.primary)
                            Text(title.lowercased())
                                .foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 4))
                        .accessibilityLabel("\(hoveredDay.date.formatted(date: .complete, time: .omitted)), \(hoveredDay.value.formatted()) \(title.lowercased())")
                    } else {
                        Text("Hover a cell for its exact count")
                            .foregroundStyle(.tertiary)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                    }
                    Text("\(total.formatted()) total · \(activeDays) active days")
                        .foregroundStyle(.secondary)
                }
                .font(.system(size: 11, weight: .medium))
                .monospacedDigit()
            }

            ScrollView(.horizontal, showsIndicators: false) {
                VStack(alignment: .leading, spacing: 5) {
                    ZStack(alignment: .topLeading) {
                        Color.clear.frame(width: gridWidth, height: 16)
                        ForEach(monthMarkers) { marker in
                            Text(marker.label)
                                .font(.system(size: 9, weight: .medium))
                                .foregroundStyle(.secondary)
                                .offset(x: CGFloat(marker.week) * (cellSize + gap))
                        }
                    }
                    .padding(.leading, 32)
                    HStack(alignment: .top, spacing: 8) {
                        VStack(alignment: .trailing, spacing: gap) {
                            Text("").frame(height: cellSize)
                            Text("Mon")
                            Text("").frame(height: cellSize)
                            Text("Wed")
                            Text("").frame(height: cellSize)
                            Text("Fri")
                            Text("").frame(height: cellSize)
                        }
                        .font(.system(size: 9))
                        .foregroundStyle(.secondary)
                        .frame(width: 24)

                        HStack(alignment: .top, spacing: gap) {
                            ForEach(Array(columns.enumerated()), id: \.offset) { _, column in
                                VStack(spacing: gap) {
                                    ForEach(column) { item in
                                        heatmapCell(item)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            HStack(spacing: 5) {
                Spacer()
                Text("Less")
                ForEach(0..<5, id: \.self) { level in
                    RoundedRectangle(cornerRadius: 2)
                        .fill(level == 0 ? Color.dashboardMutedFill : color.opacity(0.2 + Double(level) * 0.2))
                        .frame(width: cellSize, height: cellSize)
                }
                Text("More")
            }
            .font(.system(size: 10))
            .foregroundStyle(.secondary)
        }
    }

    private func heatmapCell(_ item: HeatmapDay) -> some View {
        let selected = calendar.isDate(item.date, inSameDayAs: selectedDate)
        return Button {
            selectedDate = item.date
        } label: {
            RoundedRectangle(cornerRadius: 2)
                .fill(fillColor(for: item))
                .frame(width: cellSize, height: cellSize)
                .overlay {
                    if selected {
                        RoundedRectangle(cornerRadius: 2)
                            .stroke(Color.primary, lineWidth: 1.5)
                            .padding(-2)
                    }
                }
        }
        .buttonStyle(.plain)
        .disabled(item.isFuture)
        .onHover { hovering in
            if hovering {
                hoveredDay = item
            } else if hoveredDay?.id == item.id {
                hoveredDay = nil
            }
        }
        .help("\(item.date.formatted(date: .abbreviated, time: .omitted)): \(item.value.formatted()) \(title.lowercased())")
        .accessibilityLabel("\(item.date.formatted(date: .complete, time: .omitted)), \(item.value.formatted()) \(title.lowercased())")
    }

    private func fillColor(for item: HeatmapDay) -> Color {
        if item.isFuture { return .clear }
        guard item.value > 0 else { return .dashboardMutedFill }
        let ratio = log1p(Double(item.value)) / log1p(Double(maximum))
        let level = max(1, min(4, Int(ceil(ratio * 4))))
        return color.opacity(0.2 + Double(level) * 0.2)
    }
}

private func dayKey(_ date: Date) -> String {
    let components = Calendar.current.dateComponents([.year, .month, .day], from: date)
    return String(format: "%04d-%02d-%02d", components.year ?? 0, components.month ?? 0, components.day ?? 0)
}

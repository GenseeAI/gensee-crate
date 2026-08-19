import SwiftUI

struct TimelineToolCallGraph: View {
    let calls: [TimelineToolCall]
    let outcomes: [String: TimelinePolicyOutcome]

    private var groups: [TimelineToolGroup] { TimelineDerivation.groups(from: calls) }
    private var minimumTimestamp: Int64 { calls.first?.startTimestamp ?? 0 }
    private var span: Int64 {
        let latestStart = calls.map(\.startTimestamp).max() ?? minimumTimestamp
        let longestDuration = calls.compactMap(\.durationMS).max() ?? 0
        return max(latestStart - minimumTimestamp + longestDuration, 1_000)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Label("Branch lines show call order", systemImage: "arrow.triangle.branch")
                Text("·")
                Text("Overlapping calls are grouped as parallel")
            }
            .font(.system(size: 9))
            .foregroundStyle(.tertiary)
            .padding(.bottom, 6)

            TimelineAxis(minimumTimestamp: minimumTimestamp, span: span)
            ForEach(groups) { group in
                TimelineToolGroupView(
                    group: group,
                    groupCount: groups.count,
                    minimumTimestamp: minimumTimestamp,
                    span: span,
                    outcomes: outcomes
                )
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private enum TimelineColumns {
    static let branch: CGFloat = 28
    static let marker: CGFloat = 14
    static let time: CGFloat = 76
    static let tool: CGFloat = 88
    static let severity: CGFloat = 62
    static let action: CGFloat = 62
    static let command: CGFloat = 220
    static let durationLabel: CGFloat = 64
    static let minimumDurationTrack: CGFloat = 140
    static let spacing: CGFloat = 6
}

private struct TimelineAxis: View {
    let minimumTimestamp: Int64
    let span: Int64

    var body: some View {
        HStack(spacing: 0) {
            Color.clear.frame(width: TimelineColumns.branch)
            HStack(spacing: TimelineColumns.spacing) {
                Color.clear.frame(width: TimelineColumns.marker)
                Color.clear.frame(width: TimelineColumns.time)
                Color.clear.frame(width: TimelineColumns.tool)
                Color.clear.frame(width: TimelineColumns.severity)
                Color.clear.frame(width: TimelineColumns.action)
                Text("COMMAND")
                    .font(.system(size: 8, weight: .semibold))
                    .foregroundStyle(.tertiary)
                    .frame(width: TimelineColumns.command, alignment: .leading)
                Text("DURATION")
                    .font(.system(size: 8, weight: .semibold))
                    .foregroundStyle(.tertiary)
                    .frame(width: TimelineColumns.durationLabel, alignment: .trailing)
                GeometryReader { geometry in
                    ZStack(alignment: .leading) {
                        Rectangle().fill(Color.dashboardLine).frame(height: 1).offset(y: 13)
                        timelineTick(dashboardTime(minimumTimestamp), x: 0, textOffset: 0, alignment: .leading)
                        timelineTick(dashboardTime(minimumTimestamp + span / 2), x: geometry.size.width / 2, textOffset: 38, alignment: .center)
                        timelineTick(dashboardTime(minimumTimestamp + span), x: geometry.size.width, textOffset: 76, alignment: .trailing)
                    }
                }
                .frame(minWidth: TimelineColumns.minimumDurationTrack, maxWidth: .infinity, minHeight: 18, maxHeight: 18)
                .layoutPriority(1)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.bottom, 2)
    }

    private func timelineTick(_ text: String, x: CGFloat, textOffset: CGFloat, alignment: Alignment) -> some View {
        Text(text)
            .font(.system(size: 8))
            .foregroundStyle(.tertiary)
            .fixedSize()
            .frame(width: 76, alignment: alignment)
            .offset(x: x - textOffset)
    }
}

private struct TimelineToolGroupView: View {
    let group: TimelineToolGroup
    let groupCount: Int
    let minimumTimestamp: Int64
    let span: Int64
    let outcomes: [String: TimelinePolicyOutcome]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: group.isParallel ? "arrow.triangle.branch" : group.index == 0 ? "play.fill" : "arrow.down")
                Text(group.isParallel ? "Parallel · \(group.calls.count) calls" : group.index == 0 ? "Start" : "Sequential step \(group.index + 1)")
            }
            .font(.system(size: 9, weight: .medium))
            .foregroundStyle(group.isParallel ? Color.dashboardBlue : Color.secondary)
            .padding(.leading, 2)
            .padding(.top, group.index == 0 ? 2 : 6)
            .padding(.bottom, 2)

            HStack(alignment: .top, spacing: 0) {
                TimelineBranchView(
                    callCount: group.calls.count,
                    connectsFromPrevious: group.index > 0,
                    connectsToNext: group.index < groupCount - 1
                )
                .frame(width: TimelineColumns.branch, height: CGFloat(group.calls.count) * 34)

                VStack(spacing: 0) {
                    ForEach(group.calls) { call in
                        TimelineToolCallRow(
                            call: call,
                            outcome: outcomes[call.id] ?? .allowed,
                            minimumTimestamp: minimumTimestamp,
                            span: span,
                            parallel: group.isParallel
                        )
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct TimelineBranchView: View {
    let callCount: Int
    let connectsFromPrevious: Bool
    let connectsToNext: Bool

    var body: some View {
        Canvas { context, size in
            let lineColor = Color.secondary.opacity(0.42)
            let trunkX: CGFloat = 6
            let rowHeight: CGFloat = 34
            let firstY: CGFloat = rowHeight / 2
            let lastY = firstY + CGFloat(max(0, callCount - 1)) * rowHeight
            var path = Path()
            if connectsFromPrevious { path.move(to: CGPoint(x: trunkX, y: 0)) }
            else { path.move(to: CGPoint(x: trunkX, y: firstY)) }
            path.addLine(to: CGPoint(x: trunkX, y: connectsToNext ? size.height : lastY))
            for index in 0..<callCount {
                let y = firstY + CGFloat(index) * rowHeight
                path.move(to: CGPoint(x: trunkX, y: y))
                path.addLine(to: CGPoint(x: 24, y: y))
            }
            context.stroke(path, with: .color(lineColor), lineWidth: 1.25)
        }
        .accessibilityHidden(true)
    }
}

private struct TimelineToolCallRow: View {
    let call: TimelineToolCall
    let outcome: TimelinePolicyOutcome
    let minimumTimestamp: Int64
    let span: Int64
    let parallel: Bool
    @State private var expanded = false

    var body: some View {
        VStack(spacing: 0) {
            Button { expanded.toggle() } label: {
                HStack(spacing: TimelineColumns.spacing) {
                    Circle()
                        .fill(toolColor(call.toolName))
                        .frame(width: 7, height: 7)
                        .padding(.leading, parallel ? 6 : 0)
                        .frame(width: TimelineColumns.marker)
                    Text(dashboardTime(call.startTimestamp))
                        .foregroundStyle(.secondary)
                        .frame(width: TimelineColumns.time, alignment: .leading)
                    DashboardTag(text: call.toolName, color: toolColor(call.toolName))
                        .frame(width: TimelineColumns.tool, alignment: .leading)
                    DashboardTag(text: outcome.severity, color: severityColor(outcome.severity))
                        .frame(width: TimelineColumns.severity, alignment: .leading)
                    DashboardTag(text: outcome.action, color: actionColor(outcome.action))
                        .frame(width: TimelineColumns.action, alignment: .leading)
                    HStack(spacing: 4) {
                        Text(call.detail ?? "—")
                            .font(.system(size: 10, design: call.detail == nil ? .default : .monospaced))
                            .foregroundStyle(call.detail == nil ? Color.secondary.opacity(0.6) : Color.primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Image(systemName: expanded ? "chevron.up" : "chevron.down")
                            .font(.system(size: 8, weight: .semibold))
                            .foregroundStyle(.tertiary)
                            .frame(width: 10)
                    }
                    .help(expanded ? "Collapse full tool details" : "Expand full command and tool details")
                    .frame(width: TimelineColumns.command, alignment: .leading)
                    .clipped()
                    Text(durationLabel(call))
                        .foregroundStyle(.secondary)
                        .frame(width: TimelineColumns.durationLabel, alignment: .trailing)
                        .help(call.durationSource == .elapsed ? "Approximate elapsed time from PreToolUse to PostToolUse; may include approval wait." : "Provider-reported execution duration.")
                    TimelineDurationBar(
                        startOffset: call.startTimestamp - minimumTimestamp,
                        duration: call.durationMS,
                        span: span,
                        color: toolColor(call.toolName)
                    )
                    .frame(minWidth: TimelineColumns.minimumDurationTrack, maxWidth: .infinity, minHeight: 22, maxHeight: 22)
                    .layoutPriority(1)
                }
                .font(.system(size: 10))
                .padding(.vertical, 5)
                .contentShape(Rectangle())
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.plain)

            if expanded {
                TimelineToolCallDetails(call: call)
                    .transition(.opacity)
            }
            Divider()
        }
    }

    private func durationLabel(_ call: TimelineToolCall) -> String {
        guard let duration = call.durationMS else { return "—" }
        let prefix = call.durationSource == .elapsed ? "~" : ""
        if duration >= 1_000 {
            return String(format: "%@%.2f s", prefix, Double(duration) / 1_000)
        }
        return "\(prefix)\(duration) ms"
    }
}

private struct TimelineDurationBar: View {
    let startOffset: Int64
    let duration: Int64?
    let span: Int64
    let color: Color

    var body: some View {
        GeometryReader { geometry in
            let available = geometry.size.width
            let left = min(available, max(0, CGFloat(Double(startOffset) / Double(span)) * available))
            let rawWidth = CGFloat(Double(duration ?? 0) / Double(span)) * available
            let width = min(max(4, rawWidth), max(4, available - left))
            ZStack(alignment: .leading) {
                Rectangle().fill(Color.dashboardLine.opacity(0.65)).frame(height: 1)
                RoundedRectangle(cornerRadius: 3)
                    .fill(color.opacity(0.88))
                    .frame(width: width, height: 12)
                    .offset(x: left)
            }
            .frame(maxHeight: .infinity)
        }
        .accessibilityLabel("Execution position and duration")
    }
}

private struct TimelineToolCallDetails: View {
    let call: TimelineToolCall

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            if let detail = call.detailFull ?? call.detail, !detail.isEmpty {
                detailRow(commandDetailLabel, detail)
            }
            if !call.affectedFiles.isEmpty {
                detailRow("AFFECTED FILES", call.affectedFiles.joined(separator: "\n"))
            }
            if let input = call.input {
                detailRow("INPUT", timelinePrettyJSON(input))
            }
            if let response = call.response {
                detailRow("RESULT", timelinePrettyJSON(response, limit: 700))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.dashboardMutedFill.opacity(0.55))
    }

    private var commandDetailLabel: String {
        switch call.toolName.lowercased() {
        case "bash", "shell", "runterminalcommand", "runinterminal": "FULL COMMAND"
        default: "FULL DETAIL"
        }
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .foregroundStyle(.tertiary)
                .frame(width: 92, alignment: .leading)
            Text(value)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }
}

private func toolColor(_ toolName: String) -> Color {
    switch toolName.lowercased() {
    case "toolsearch": .purple
    case "websearch": .dashboardBlue
    case "webfetch": .cyan
    case "read": .dashboardGreen
    case "write": .orange
    case "edit", "multiedit": .dashboardGold
    case "bash", "shell", "runterminalcommand", "runinterminal": .dashboardRed
    default: .secondary
    }
}

private func timelinePrettyJSON(_ text: String, limit: Int = 1_200) -> String {
    let rendered: String
    if let data = text.data(using: .utf8),
       let object = try? JSONSerialization.jsonObject(with: data),
       let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    {
        rendered = String(decoding: pretty, as: UTF8.self)
    } else {
        rendered = text
    }
    guard rendered.count > limit else { return rendered }
    return String(rendered.prefix(limit)) + "…"
}

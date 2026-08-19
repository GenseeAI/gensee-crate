import Charts
import SwiftUI

struct DashboardOverviewPage: View {
    @ObservedObject var model: ConsoleModel
    @ObservedObject var sensor: EndpointSecuritySensor

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader(
                    "Overview",
                    description: "Protection health and recent security activity on this Mac."
                ) {
                    if let updated = model.lastUpdated {
                        Text("Updated \(updated.formatted(.relative(presentation: .named)))")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                }

                HStack(spacing: 10) {
                    if model.isDemoMode {
                        DashboardSymbol("rectangle.stack", color: .secondary, size: 13, weight: .regular)
                        Text("Synthetic product tour")
                            .font(.system(size: 12, weight: .semibold))
                        DashboardTag(text: "Demo data", color: .dashboardBlue)
                        Text("Explore the evidence model before connecting a harness.")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                        Spacer()
                        DashboardTag(text: "This Mac untouched", color: .dashboardGreen)
                    } else {
                        DashboardSymbol(
                            sensor.health.connected ? "checkmark.shield" : "exclamationmark.triangle",
                            color: sensor.health.connected ? .dashboardGreen : .dashboardGold,
                            size: 13,
                            weight: .regular
                        )
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
                }
                .padding(12)
                .background(Color.dashboardPanel, in: RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.dashboardLine))

                HStack(spacing: 16) {
                    DashboardStatCard(title: "Sessions", value: model.snapshot.summary.sessionsCount, symbol: "rectangle.stack", color: .dashboardBlue)
                    DashboardStatCard(title: "Requests", value: model.snapshot.summary.requestsCount, symbol: "bubble.left.and.bubble.right", color: .dashboardGreen)
                    DashboardStatCard(title: "Agent events", value: model.snapshot.summary.agentEventsCount, symbol: "terminal", color: .dashboardGold)
                    DashboardStatCard(title: "High-risk findings (24 h)", value: model.snapshot.summary.recentHighAlerts, symbol: "exclamationmark.triangle", color: .dashboardRed)
                        .help("High and critical describe potential impact. The alert action separately shows whether Gensee warned, asked, or blocked.")
                }

                HStack(alignment: .top, spacing: 16) {
                    ActivityChartCard(model: model).frame(maxWidth: .infinity)
                    SeverityBreakdownCard(summary: model.snapshot.summary).frame(width: 360)
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

private enum WorkReviewSelection: Hashable {
    case session(String)
    case request(Int64)
}

private enum WorkReviewSection: String, CaseIterable, Identifiable {
    case timeline = "Timeline"
    case findings = "Findings"
    case files = "Files"

    var id: String { rawValue }
}

private enum WorkReviewFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case attention = "Needs attention"
    case findings = "Has findings"

    var id: String { rawValue }
}

struct DashboardWorkReviewPage: View {
    @ObservedObject var model: ConsoleModel
    let searchText: String

    @State private var selection: WorkReviewSelection?
    @State private var section: WorkReviewSection = .files
    @State private var filter: WorkReviewFilter = .all

    private var sessions: [AgentSessionSummary] {
        AgentCompletionDerivation.sessionSummaries(from: model.snapshot).compactMap { session in
            let requests = session.requests.filter(matches)
            guard !requests.isEmpty else { return nil }
            return AgentSessionSummary(
                sessionID: session.sessionID,
                harness: session.harness,
                startedAt: requests.map(\.startedAt).min() ?? session.startedAt,
                completedAt: requests.map(\.completedAt).max() ?? session.completedAt,
                requests: requests
            )
        }
    }

    private var resolvedSelection: WorkReviewSelection? {
        if let selection, selectionExists(selection) { return selection }
        return sessions.first?.requests.first.map { .request($0.requestID) }
    }

    private var selectedRequestID: Int64? {
        guard case let .request(requestID) = resolvedSelection else { return nil }
        return requestID
    }

    var body: some View {
        VStack(spacing: 0) {
            DashboardPageHeader(
                "Work Review",
                description: "Review completed agent sessions and requests with their evidence in context."
            ) {
                if let updated = model.lastUpdated {
                    Text("Updated \(updated.formatted(.relative(presentation: .named)))")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, 24)

            Divider()

            if sessions.isEmpty {
                EmptyControlCenterCard(activeRunCount: model.activeRunCount)
                    .padding(24)
                Spacer()
            } else {
                HStack(spacing: 0) {
                    workBrowser
                        .frame(width: 340)
                    Divider()
                    ScrollView {
                        reviewDetail
                            .padding(22)
                            .frame(maxWidth: 960, alignment: .leading)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { establishSelection() }
        .onChange(of: sessions.map(\.id)) { _ in establishSelection() }
        .task(id: selectedRequestID) {
            guard let selectedRequestID else { return }
            await model.loadRequestReview(requestID: selectedRequestID)
        }
    }

    private var workBrowser: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("SESSIONS & REQUESTS")
                        .font(.system(size: 9, weight: .bold))
                        .tracking(0.9)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("\(sessions.reduce(0) { $0 + $1.requestCount }) requests")
                        .font(.system(size: 9))
                        .foregroundStyle(.tertiary)
                }
                Picker("Filter", selection: $filter) {
                    ForEach(WorkReviewFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .frame(maxWidth: .infinity)
            }
            .padding(14)
            .background(Color.dashboardMutedFill.opacity(0.55))

            ScrollView {
                LazyVStack(spacing: 6) {
                    ForEach(Array(sessions.enumerated()), id: \.element.id) { index, session in
                        WorkReviewSessionGroup(
                            session: session,
                            selection: Binding(
                                get: { resolvedSelection },
                                set: {
                                    selection = $0
                                    section = .files
                                }
                            ),
                            initiallyExpanded: index == 0
                        )
                    }
                }
                .padding(10)
            }
        }
        .background(Color.dashboardPanel)
    }

    @ViewBuilder
    private var reviewDetail: some View {
        switch resolvedSelection {
        case let .request(requestID):
            if let summary = sessions.flatMap(\.requests).first(where: { $0.requestID == requestID }) {
                RequestReviewDetail(
                    summary: summary,
                    model: model,
                    section: $section
                )
            }
        case let .session(sessionID):
            if let session = sessions.first(where: { $0.sessionID == sessionID }) {
                SessionReviewDetail(
                    session: session,
                    snapshot: model.snapshot,
                    model: model,
                    section: $section
                )
            }
        case nil:
            DashboardEmpty(text: "Select a session or request to review.", symbol: "checklist")
        }
    }

    private func matches(_ request: AgentCompletionSummary) -> Bool {
        let matchesFilter: Bool
        switch filter {
        case .all: matchesFilter = true
        case .attention: matchesFilter = request.reviewState == .attention
        case .findings: matchesFilter = request.alertCount > 0
        }
        return matchesFilter && containsSearch(
            searchText,
            fields: request.prompt, request.harness, request.sessionID,
            request.affectedFiles.joined(separator: " ")
        )
    }

    private func selectionExists(_ selection: WorkReviewSelection) -> Bool {
        switch selection {
        case let .session(id): sessions.contains { $0.sessionID == id }
        case let .request(id): sessions.contains { session in session.requests.contains { $0.requestID == id } }
        }
    }

    private func establishSelection() {
        guard resolvedSelection == nil, let request = sessions.first?.requests.first else { return }
        selection = .request(request.requestID)
    }
}

private struct WorkReviewSessionGroup: View {
    let session: AgentSessionSummary
    @Binding var selection: WorkReviewSelection?
    @State private var expanded: Bool

    init(session: AgentSessionSummary, selection: Binding<WorkReviewSelection?>, initiallyExpanded: Bool) {
        self.session = session
        _selection = selection
        _expanded = State(initialValue: initiallyExpanded)
    }

    var body: some View {
        VStack(spacing: 2) {
            HStack(spacing: 7) {
                Button { expanded.toggle() } label: {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 9, weight: .semibold))
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                        .frame(width: 14)
                }
                .buttonStyle(.plain)
                Button { selection = .session(session.sessionID) } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Circle().fill(reviewStateColor(session.reviewState)).frame(width: 7, height: 7)
                            Text(session.harness).font(.system(size: 11, weight: .semibold))
                            Spacer()
                            Text("\(session.requestCount)").font(.system(size: 10, weight: .semibold))
                            Text("req").font(.system(size: 9)).foregroundStyle(.secondary)
                        }
                        Text("\(relativeTimestamp(session.completedAt)) · \(formattedDuration(session.durationMS))")
                            .font(.system(size: 9))
                            .foregroundStyle(.secondary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
            .padding(9)
            .background(selection == .session(session.sessionID) ? Color.dashboardBlue.opacity(0.10) : Color.dashboardMutedFill)
            .overlay(RoundedRectangle(cornerRadius: 5).stroke(selection == .session(session.sessionID) ? Color.dashboardBlue : Color.clear))
            .clipShape(RoundedRectangle(cornerRadius: 5))

            if expanded {
                VStack(spacing: 2) {
                    ForEach(session.requests) { request in
                        Button { selection = .request(request.requestID) } label: {
                            HStack(alignment: .top, spacing: 8) {
                                Circle().fill(reviewStateColor(request.reviewState)).frame(width: 6, height: 6).padding(.top, 4)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(request.prompt)
                                        .font(.system(size: 10, weight: selection == .request(request.requestID) ? .semibold : .regular))
                                        .lineLimit(2)
                                        .multilineTextAlignment(.leading)
                                    HStack(spacing: 7) {
                                        Text(relativeTimestamp(request.completedAt))
                                        Text("\(request.toolCallCount) tools")
                                        if request.alertCount > 0 { Text("\(request.alertCount) findings") }
                                    }
                                    .font(.system(size: 8))
                                    .foregroundStyle(.secondary)
                                }
                                Spacer(minLength: 0)
                            }
                            .padding(.vertical, 7)
                            .padding(.horizontal, 9)
                            .contentShape(Rectangle())
                            .background(selection == .request(request.requestID) ? Color.dashboardBlue.opacity(0.08) : Color.clear)
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.leading, 18)
            }
        }
    }
}

private struct RequestReviewDetail: View {
    let summary: AgentCompletionSummary
    @ObservedObject var model: ConsoleModel
    @Binding var section: WorkReviewSection
    @State private var restoreCandidate: WorkspaceCheckpointRecord?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            CompletionReviewCard(summary: effectiveSummary)
            if let recoveryPoint {
                RecoveryPointReviewRow(recoveryPoint: recoveryPoint) {
                    restoreCandidate = recoveryPoint
                }
            }
            ReviewSectionPicker(
                section: $section,
                findingCount: effectiveFindingCount,
                fileCount: effectiveSummary.affectedFiles.count
            )
            switch section {
            case .timeline:
                requestEvidenceContent {
                    ReviewTimelinePanel(
                        requests: [effectiveSummary],
                        agentEvents: payload?.agentEvents ?? [],
                        alerts: payload?.alerts ?? []
                    )
                }
            case .findings:
                requestEvidenceContent {
                    ReviewFindingsPanel(alerts: payload?.alerts ?? [], model: model)
                }
            case .files:
                requestEvidenceContent {
                    ReviewFilesPanel(
                        affectedFiles: effectiveSummary.affectedFiles,
                        verifiedFiles: effectiveSummary.verifiedFiles,
                        unmatchedFiles: effectiveSummary.unmatchedFiles,
                        ignoredFileCount: effectiveSummary.ignoredFiles.count
                    )
                }
            }
        }
        .alert("Restore this recovery point?", isPresented: restorePresented, presenting: restoreCandidate) { point in
            Button("Cancel", role: .cancel) { restoreCandidate = nil }
            Button("Create Rescue & Restore", role: .destructive) {
                restoreCandidate = nil
                Task { await model.restoreCheckpoint(point, workspace: point.workspace) }
            }
        } message: { point in
            Text("Gensee will preserve the workspace as it is now, then restore the files captured before this request changed them. Ignored files, databases, remote actions, network effects, and running processes are not restored.")
        }
    }

    private var payload: RequestReviewPayload? {
        guard model.requestReviewPayload?.request.requestID == summary.requestID else { return nil }
        return model.requestReviewPayload
    }

    private var effectiveSummary: AgentCompletionSummary {
        guard let payload else { return summary }
        var scoped = SecuritySnapshot()
        scoped.requests = [payload.request]
        scoped.agentEvents = payload.agentEvents
        scoped.systemEvents = payload.systemEvents
        scoped.alerts = payload.alerts
        scoped.sessions = model.snapshot.sessions.filter { $0.sessionID == payload.request.sessionID }
        return AgentCompletionDerivation.summaries(from: scoped).first ?? summary
    }

    private var effectiveFindingCount: Int {
        payload?.alerts.count ?? summary.alertCount
    }

    private var recoveryPoint: WorkspaceCheckpointRecord? {
        model.recoveryPointsByRequest[summary.requestID]
    }

    private var restorePresented: Binding<Bool> {
        Binding(
            get: { restoreCandidate != nil },
            set: { if !$0 { restoreCandidate = nil } }
        )
    }

    @ViewBuilder
    private func requestEvidenceContent<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        switch model.requestReviewLoadState {
        case let .loaded(requestID) where requestID == summary.requestID:
            content()
        case let .loading(requestID) where requestID == summary.requestID:
            DashboardCard {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text("Loading complete request evidence…")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
            }
        case .idle:
            DashboardCard {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text("Loading complete request evidence…")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
            }
        case let .unavailable(requestID, message) where requestID == summary.requestID:
            DashboardCard {
                DashboardEmpty(text: "Request evidence could not be loaded: \(message)", symbol: "exclamationmark.triangle")
            }
        default:
            DashboardCard {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text("Loading complete request evidence…")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
            }
        }
    }
}

private struct RecoveryPointReviewRow: View {
    let recoveryPoint: WorkspaceCheckpointRecord
    let onRestore: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            DashboardSymbol("arrow.counterclockwise.circle", color: .dashboardGreen, size: 16, weight: .regular)
            VStack(alignment: .leading, spacing: 3) {
                Text("Recovery point created before changes")
                    .font(.system(size: 12, weight: .semibold))
                Text(recoveryPoint.trigger ?? "Captured before the first risky or mutating tool call.")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(Date(timeIntervalSince1970: TimeInterval(recoveryPoint.createdAtMS) / 1_000).formatted(date: .omitted, time: .shortened))
                .font(.system(size: 9, design: .monospaced))
                .foregroundStyle(.tertiary)
            Button("Restore…", action: onRestore)
                .buttonStyle(.bordered)
                .controlSize(.small)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(Color.dashboardGreen.opacity(0.07), in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.dashboardGreen.opacity(0.28)))
        .accessibilityElement(children: .contain)
    }
}

private struct SessionReviewDetail: View {
    let session: AgentSessionSummary
    let snapshot: SecuritySnapshot
    @ObservedObject var model: ConsoleModel
    @Binding var section: WorkReviewSection

    private var findings: [SecurityAlert] {
        let requestIDs = Set(session.requests.map(\.requestID))
        return snapshot.alerts.filter { requestIDs.contains($0.requestID ?? -1) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            SessionReviewCard(session: session)
            ReviewSectionPicker(
                section: $section,
                findingCount: findings.count,
                fileCount: session.affectedFiles.count
            )
            switch section {
            case .timeline:
                ReviewTimelinePanel(
                    requests: Array(session.requests.reversed()),
                    agentEvents: snapshot.agentEvents,
                    alerts: snapshot.alerts
                )
            case .findings:
                ReviewFindingsPanel(alerts: findings, model: model)
            case .files:
                ReviewFilesPanel(
                    affectedFiles: session.affectedFiles,
                    verifiedFiles: session.verifiedFiles,
                    unmatchedFiles: session.unmatchedFiles,
                    ignoredFileCount: session.ignoredFiles.count
                )
            }
        }
    }
}

private struct SessionReviewCard: View {
    let session: AgentSessionSummary

    var body: some View {
        DashboardCard {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .top, spacing: 14) {
                    DashboardSymbol(
                        "rectangle.stack",
                        color: reviewStateColor(session.reviewState),
                        size: 20,
                        weight: .medium
                    )
                    .frame(width: 34, height: 34, alignment: .top)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text("Session summary").font(.system(size: 18, weight: .semibold))
                            DashboardTag(text: session.harness, color: .dashboardBlue)
                        }
                        Text("\(session.requestCount) completed request\(session.requestCount == 1 ? "" : "s") · \(relativeTimestamp(session.completedAt))")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(formattedDuration(session.durationMS)).font(.system(size: 17, weight: .semibold, design: .rounded))
                        Text("session span").font(.system(size: 9)).foregroundStyle(.secondary)
                    }
                }
                HStack(spacing: 0) {
                    ReviewMetric(value: session.requestCount, label: "requests", symbol: "text.bubble")
                    reviewMetricDivider
                    ReviewMetric(value: session.toolCallCount, label: "tool calls", symbol: "hammer")
                    reviewMetricDivider
                    ReviewMetric(value: session.affectedFiles.count, label: "files touched", symbol: "doc.badge.ellipsis")
                    reviewMetricDivider
                    ReviewMetric(value: session.alertCount, label: "findings", symbol: "exclamationmark.triangle")
                }
                .padding(.vertical, 12)
                .background(Color.dashboardMutedFill.opacity(0.72), in: RoundedRectangle(cornerRadius: 7))
            }
            .padding(4)
        }
        .overlay(alignment: .leading) { Rectangle().fill(reviewStateColor(session.reviewState)).frame(width: 3).padding(.vertical, 1) }
    }

    private var reviewMetricDivider: some View {
        Rectangle().fill(Color.dashboardLine).frame(width: 1, height: 34)
    }
}

private struct ReviewSectionPicker: View {
    @Binding var section: WorkReviewSection
    let findingCount: Int
    let fileCount: Int

    var body: some View {
        Picker("Review detail", selection: $section) {
            ForEach(WorkReviewSection.allCases) { item in
                Text(sectionTitle(item)).tag(item)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(maxWidth: 420)
    }

    private func sectionTitle(_ item: WorkReviewSection) -> String {
        switch item {
        case .timeline: "Timeline"
        case .findings: "Findings (\(findingCount))"
        case .files: "Files (\(fileCount))"
        }
    }
}

private struct ReviewFilesPanel: View {
    let affectedFiles: [String]
    let verifiedFiles: [String]
    let unmatchedFiles: [String]
    let ignoredFileCount: Int

    var body: some View {
        DashboardCard("Files touched") {
            VStack(alignment: .leading, spacing: 12) {
                FileTouchBreakdown(
                    affectedFileCount: affectedFiles.count,
                    verifiedFileCount: verifiedFiles.count,
                    unmatchedFileCount: unmatchedFiles.count,
                    ignoredFileCount: ignoredFileCount
                )
                Divider()
                if affectedFiles.isEmpty {
                    Text("No non-ignored file mutation was observed.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                } else {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(affectedFiles, id: \.self) { path in
                            let verified = verifiedFiles.contains(path)
                            Label(
                                abbreviatedPath(path),
                                systemImage: verified ? "checkmark.shield" : "exclamationmark.triangle"
                            )
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(verified ? Color.primary : Color.dashboardGold)
                            .help(verified ? "Declared by the tool and verified by Endpoint Security: \(path)" : "Observed by Endpoint Security outside declared file intent: \(path)")
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
        }
    }
}

private struct FileTouchBreakdown: View {
    let affectedFileCount: Int
    let verifiedFileCount: Int
    let unmatchedFileCount: Int
    let ignoredFileCount: Int

    var body: some View {
        HStack(spacing: 18) {
            breakdown(
                value: affectedFileCount,
                label: "files touched",
                symbol: "doc.badge.ellipsis",
                color: .dashboardBlue
            )
            breakdown(
                value: verifiedFileCount,
                label: "intended & OS-verified",
                symbol: "checkmark.shield",
                color: .dashboardGreen
            )
            breakdown(
                value: unmatchedFileCount,
                label: "outside declared intent",
                symbol: "exclamationmark.triangle",
                color: unmatchedFileCount == 0 ? .secondary : .dashboardGold
            )
            breakdown(
                value: ignoredFileCount,
                label: "temporary/background ignored",
                symbol: "eye.slash",
                color: .secondary
            )
        }
        .font(.system(size: 10, weight: .medium))
        .accessibilityElement(children: .combine)
    }

    private func breakdown(
        value: Int,
        label: String,
        symbol: String,
        color: Color
    ) -> some View {
        Label {
            Text("\(value) \(label)")
        } icon: {
            DashboardSymbol(symbol, color: color, size: 12, weight: .regular)
        }
    }
}

private struct ReviewTimelinePanel: View {
    let requests: [AgentCompletionSummary]
    let agentEvents: [AgentEvent]
    let alerts: [SecurityAlert]

    var body: some View {
        DashboardCard("Execution timeline") {
            VStack(alignment: .leading, spacing: 14) {
                ForEach(requests) { request in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(request.prompt).font(.system(size: 11, weight: .semibold)).lineLimit(2)
                            Spacer()
                            Text("\(calls(for: request).count) tool calls").font(.system(size: 9)).foregroundStyle(.secondary)
                        }
                        if calls(for: request).isEmpty {
                            AnswerOnlyLifecycle(request: request)
                        } else {
                            TimelineToolCallGraph(calls: calls(for: request), outcomes: outcomes(for: request))
                        }
                    }
                    if request.id != requests.last?.id { Divider() }
                }
            }
        }
    }

    private func calls(for request: AgentCompletionSummary) -> [TimelineToolCall] {
        TimelineDerivation.toolCalls(from: agentEvents.filter { $0.requestID == request.requestID })
    }

    private func outcomes(for request: AgentCompletionSummary) -> [String: TimelinePolicyOutcome] {
        TimelineDerivation.policyOutcomes(from: alerts.filter { $0.requestID == request.requestID })
    }
}

private struct AnswerOnlyLifecycle: View {
    let request: AgentCompletionSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 7) {
                DashboardSymbol("text.bubble", color: .secondary, size: 12, weight: .regular)
                Text("No tools called")
                    .font(.system(size: 11, weight: .semibold))
                Text("The agent answered directly.")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 0) {
                LifecycleStop(
                    symbol: "arrow.right.circle.fill",
                    title: "Request started",
                    timestamp: request.startedAt,
                    color: .dashboardBlue
                )
                Rectangle()
                    .fill(Color.dashboardLine)
                    .frame(maxWidth: .infinity, minHeight: 1, maxHeight: 1)
                    .overlay {
                        Text(formattedDuration(request.durationMS))
                            .font(.system(size: 9, weight: .medium))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 8)
                            .background(Color.dashboardPanel)
                    }
                LifecycleStop(
                    symbol: "checkmark.circle.fill",
                    title: "Answer completed",
                    timestamp: request.completedAt,
                    color: .dashboardGreen
                )
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Request started at \(dashboardTime(request.startedAt)) and completed at \(dashboardTime(request.completedAt)) after \(formattedDuration(request.durationMS)). No tools were called.")
        }
        .padding(12)
        .background(Color.dashboardMutedFill.opacity(0.48), in: RoundedRectangle(cornerRadius: 6))
    }
}

private struct LifecycleStop: View {
    let symbol: String
    let title: String
    let timestamp: Int64
    let color: Color

    var body: some View {
        HStack(spacing: 7) {
            DashboardSymbol(symbol, color: color, size: 13, weight: .regular)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.system(size: 10, weight: .semibold))
                Text(dashboardTime(timestamp)).font(.system(size: 9)).foregroundStyle(.secondary)
            }
        }
        .fixedSize()
    }
}

private struct ReviewFindingsPanel: View {
    let alerts: [SecurityAlert]
    @ObservedObject var model: ConsoleModel

    var body: some View {
        DashboardCard("Findings in this review") {
            if alerts.isEmpty {
                DashboardEmpty(text: "No findings were correlated with this selection.", symbol: "checkmark.shield")
            } else {
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

private func reviewStateColor(_ state: AgentReviewState) -> Color {
    switch state {
    case .verified: .dashboardGreen
    case .review: .dashboardGold
    case .attention: .dashboardRed
    }
}

private struct CompletionReviewCard: View {
    let summary: AgentCompletionSummary

    var body: some View {
        DashboardCard {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .top, spacing: 16) {
                    DashboardSymbol(stateSymbol, color: stateColor, size: 21, weight: .medium)
                        .frame(width: 36, height: 36, alignment: .top)

                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 8) {
                            Text(summary.reviewState.title)
                                .font(.system(size: 18, weight: .semibold))
                            DashboardTag(text: summary.harness, color: .dashboardBlue)
                            Text(relativeTimestamp(summary.completedAt))
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                        }
                        Text(summary.prompt)
                            .font(.system(size: 14, weight: .medium))
                            .lineLimit(2)
                            .textSelection(.enabled)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 3) {
                        Text(formattedDuration(summary.durationMS))
                            .font(.system(size: 17, weight: .semibold, design: .rounded))
                        Text("elapsed")
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                    }
                }

                HStack(spacing: 0) {
                    ReviewMetric(value: summary.toolCallCount, label: "tool calls", symbol: "hammer")
                    reviewDivider
                    ReviewMetric(value: summary.commandCount, label: "commands", symbol: "terminal")
                    reviewDivider
                    ReviewMetric(value: summary.affectedFiles.count, label: "files touched", symbol: "doc.badge.ellipsis")
                    reviewDivider
                    ReviewMetric(value: summary.testCommandCount, label: "test runs observed", symbol: "checkmark.diamond")
                }
                .padding(.vertical, 12)
                .background(Color.dashboardMutedFill.opacity(0.72), in: RoundedRectangle(cornerRadius: 7))

                HStack(alignment: .top, spacing: 14) {
                    VerificationLine(
                        symbol: "checkmark.circle",
                        color: .dashboardGreen,
                        title: "Completion captured",
                        detail: "Gensee observed the request lifecycle finish."
                    )
                    VerificationLine(
                        symbol: summary.highRiskAlertCount == 0 ? "checkmark.shield" : "exclamationmark.triangle",
                        color: summary.highRiskAlertCount == 0 ? .dashboardGreen : .dashboardRed,
                        title: summary.highRiskAlertCount == 0 ? "No high-risk findings" : "\(summary.highRiskAlertCount) high-risk finding\(summary.highRiskAlertCount == 1 ? "" : "s")",
                        detail: policyDetail
                    )
                    VerificationLine(
                        symbol: summary.testCommandCount > 0 ? "checkmark.diamond" : "minus.circle",
                        color: summary.testCommandCount > 0 ? .dashboardBlue : .secondary,
                        title: summary.testCommandCount > 0 ? "Test command observed" : "No test command observed",
                        detail: summary.testCommandCount > 0
                            ? "Open Timeline to inspect the command and duration."
                            : "Gensee will not claim tests passed without evidence."
                    )
                }

            }
            .padding(4)
        }
        .overlay(alignment: .leading) {
            Rectangle().fill(stateColor).frame(width: 3).padding(.vertical, 1)
        }
    }

    private var reviewDivider: some View {
        Rectangle().fill(Color.dashboardLine).frame(width: 1, height: 34)
    }

    private var stateColor: Color {
        switch summary.reviewState {
        case .verified: .dashboardGreen
        case .review: .dashboardGold
        case .attention: .dashboardRed
        }
    }

    private var stateSymbol: String {
        switch summary.reviewState {
        case .verified: "checkmark.shield"
        case .review: "eye"
        case .attention: "exclamationmark.triangle"
        }
    }

    private var policyDetail: String {
        if summary.alertCount == 0 { return "Policy checks completed without a surfaced finding." }
        return "Strongest outcome: \(summary.strongestAction.uppercased()) · \(summary.strongestSeverity.uppercased())."
    }
}

private struct ReviewMetric: View {
    let value: Int
    let label: String
    let symbol: String

    var body: some View {
        HStack(spacing: 8) {
            DashboardSymbol(symbol, color: .secondary, size: 12, weight: .regular)
            VStack(alignment: .leading, spacing: 1) {
                Text(value.formatted()).font(.system(size: 15, weight: .semibold))
                Text(label).font(.system(size: 10)).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .center)
    }
}

private struct VerificationLine: View {
    let symbol: String
    let color: Color
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            DashboardSymbol(symbol, color: color, size: 12, weight: .regular).padding(.top, 1)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 11, weight: .semibold))
                Text(detail).font(.system(size: 10)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct EmptyControlCenterCard: View {
    let activeRunCount: Int

    var body: some View {
        DashboardCard {
            HStack(spacing: 18) {
                DashboardSymbol(
                    activeRunCount > 0 ? "gearshape.2" : "checkmark.shield",
                    color: .secondary,
                    size: 23,
                    weight: .regular
                )
                .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 5) {
                    Text(activeRunCount > 0 ? "Your agent is working" : "No completed task to review yet")
                        .font(.system(size: 18, weight: .semibold))
                    Text(activeRunCount > 0
                         ? "You can leave it running. Gensee will surface a concise review when the request finishes."
                         : "Start a request in a protected harness. Gensee will connect tool calls, changed files, policy outcomes, and completion evidence here.")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer()
            }.padding(8)
        }
    }
}

private func formattedDuration(_ milliseconds: Int64) -> String {
    if milliseconds < 1_000 { return "< 1 sec" }
    let seconds = milliseconds / 1_000
    if seconds < 60 { return "\(seconds) sec" }
    let minutes = seconds / 60
    let remainder = seconds % 60
    if minutes < 60 { return remainder == 0 ? "\(minutes) min" : "\(minutes)m \(remainder)s" }
    let hours = minutes / 60
    let minuteRemainder = minutes % 60
    return minuteRemainder == 0 ? "\(hours) hr" : "\(hours)h \(minuteRemainder)m"
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
    let summary: DashboardSummary
    private var severityCounts: [String: Int] { summary.alertsBySeverity }
    private var slices: [AlertSeveritySlice] { AlertSeverityBreakdown.slices(for: severityCounts) }

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
                        Text(summary.alertsCount.formatted()).font(.system(size: 23, weight: .semibold))
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
                    ("Agent Turns", requests, "bubble.left.and.bubble.right", Color.dashboardGold),
                    ("Tool Calls", toolCalls, "terminal", Color.dashboardGreen),
                    ("Alerts", alertCount, "exclamationmark.triangle", Color.dashboardRed),
                    ("Tokens", tokenCount, "textformat.123", Color.purple),
                ])
                if let detail = selectedDetail {
                    metricRow([
                        ("Sessions", detail.sessions, "rectangle.stack", Color.dashboardBlue),
                        ("Files Written / Edited", detail.filesWritten, "square.and.pencil", Color.dashboardBlue),
                        ("Files Read", detail.filesRead, "doc.text.magnifyingglass", Color.dashboardGreen),
                        ("Web Requests", detail.webRequests, "network", Color.dashboardGold),
                    ])
                    HStack(alignment: .top, spacing: 16) {
                        DashboardCard("Alert breakdown") {
                            VStack(alignment: .leading, spacing: 14) {
                                breakdownRow("By action", values: detail.alertsByAction, colors: actionColor)
                                Divider()
                                breakdownRow("By severity", values: detail.alertsBySeverity, colors: severityColor)
                            }
                            .frame(minHeight: 150, alignment: .top)
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

    private func breakdownRow(
        _ title: String,
        values: [DailyCount],
        colors: @escaping (String) -> Color
    ) -> some View {
        let populated = values.filter { $0.count > 0 }
        return VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.secondary)
            if populated.isEmpty {
                Text("No alerts for this date")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
            } else {
                HStack(spacing: 12) {
                    ForEach(populated) { value in
                        HStack(spacing: 6) {
                            Circle()
                                .fill(colors(value.name))
                                .frame(width: 6, height: 6)
                            Text(value.name.uppercased())
                                .font(.system(size: 9, weight: .semibold))
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                            Text(value.count.formatted())
                                .font(.system(size: 12, weight: .semibold))
                                .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("\(value.name), \(value.count.formatted())")
                    }
                }
            }
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

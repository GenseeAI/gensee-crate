import SwiftUI

enum DashboardDestination: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case liveFeed = "Live Feed"
    case today = "Today's Highlight"
    case timeline = "Timeline"
    case transactions = "Transactions"
    case alerts = "Alerts"
    case lineage = "Lineage Graph"
    case feedback = "Feedback"
    case harnesses = "Harnesses"
    case policy = "Policy"
    case settings = "Settings"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .dashboard: "gauge.with.dots.needle.33percent"
        case .liveFeed: "bolt"
        case .today: "star"
        case .timeline: "clock"
        case .transactions: "arrow.triangle.branch"
        case .alerts: "exclamationmark.triangle"
        case .lineage: "point.3.connected.trianglepath.dotted"
        case .feedback: "hand.thumbsup"
        case .harnesses: "switch.2"
        case .policy: "checkmark.shield"
        case .settings: "gearshape"
        }
    }
}

struct DashboardShell: View {
    @ObservedObject var extensionManager: EndpointSecurityExtensionManager
    @ObservedObject var model: ConsoleModel
    @State private var selection: DashboardDestination = .dashboard
    @State private var searchText = ""
    @AppStorage("gensee.dashboard.darkMode") private var darkMode = false

    var body: some View {
        VStack(spacing: 0) {
            topBar
            HStack(spacing: 0) {
                DashboardSidebar(selection: $selection, alertCount: model.snapshot.summary.alertsCount)
                    .frame(width: 220)
                Rectangle().fill(Color.dashboardLine).frame(width: 1)
                ZStack {
                    Color.dashboardCanvas.ignoresSafeArea()
                    destinationView
                    if let command = model.runningCommand {
                        VStack(spacing: 10) {
                            ProgressView()
                            Text(command).font(.caption.weight(.medium))
                        }
                        .padding(18)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
                        .shadow(radius: 12)
                    }
                }
            }
        }
        .preferredColorScheme(darkMode ? .dark : .light)
        .task {
            extensionManager.refreshStatus()
            model.endpointSensor.start()
            await model.refreshAll()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                await model.refreshDashboard()
            }
        }
        .alert("Gensee needs attention", isPresented: errorPresented) {
            Button("Dismiss", role: .cancel) { model.errorMessage = nil }
        } message: { Text(model.errorMessage ?? "Unknown error") }
        .alert("Gensee updated", isPresented: noticePresented) {
            Button("OK", role: .cancel) { model.noticeMessage = nil }
        } message: { Text(model.noticeMessage ?? "") }
    }

    private var topBar: some View {
        HStack(spacing: 16) {
            HStack(spacing: 10) {
                BrandEye(size: 28)
                VStack(alignment: .leading, spacing: 0) {
                    Text("GenseeAI")
                        .font(.system(size: 9, weight: .medium))
                        .tracking(2)
                        .textCase(.uppercase)
                        .foregroundStyle(.secondary)
                    Text("Gensee Crate")
                        .font(.system(size: 14, weight: .bold))
                        .tracking(0.5)
                }
            }
            .frame(width: 204, alignment: .leading)

            HStack(spacing: 7) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search sessions, alerts, artifacts…", text: $searchText)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12))
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                    }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 10)
            .frame(maxWidth: 360, minHeight: 30)
            .background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))

            Spacer()
            Button { selection = .alerts } label: { Image(systemName: "bell") }
                .buttonStyle(.plain).help("Alerts")
            Button { selection = .settings } label: { Image(systemName: "questionmark.circle") }
                .buttonStyle(.plain).help("Help and settings")
            Button { darkMode.toggle() } label: { Image(systemName: darkMode ? "sun.max" : "moon") }
                .buttonStyle(.plain).help(darkMode ? "Switch to light mode" : "Switch to dark mode")
            Circle()
                .fill(Color.dashboardRed)
                .frame(width: 28, height: 28)
                .overlay(Image(systemName: "person.fill").font(.system(size: 12)).foregroundStyle(.white))
            Text("Admin").font(.system(size: 13))
        }
        .padding(.horizontal, 16)
        .frame(height: 56)
        .background(Color.dashboardPanel)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.dashboardLine).frame(height: 1) }
    }

    @ViewBuilder
    private var destinationView: some View {
        switch selection {
        case .dashboard: DashboardOverviewPage(model: model, sensor: model.endpointSensor)
        case .liveFeed: LiveFeedPage(model: model, searchText: searchText)
        case .today: TodayHighlightPage(model: model)
        case .timeline: TimelinePage(model: model, searchText: searchText)
        case .transactions: TransactionsPage(model: model, searchText: searchText)
        case .alerts: DashboardAlertsPage(model: model, searchText: searchText)
        case .lineage: LineagePage(model: model, searchText: searchText)
        case .feedback: FeedbackPage(model: model, searchText: searchText)
        case .harnesses: DashboardHarnessesPage(model: model)
        case .policy: DashboardPolicyPage(model: model)
        case .settings: DashboardSettingsPage(
            model: model,
            extensionManager: extensionManager,
            sensor: model.endpointSensor,
            darkMode: $darkMode
        )
        }
    }

    private var errorPresented: Binding<Bool> {
        Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })
    }

    private var noticePresented: Binding<Bool> {
        Binding(get: { model.noticeMessage != nil }, set: { if !$0 { model.noticeMessage = nil } })
    }
}

private struct DashboardSidebar: View {
    @Binding var selection: DashboardDestination
    let alertCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            navGroup("OVERVIEW", [.dashboard])
            separator
            navGroup("ACTIVITY", [.liveFeed, .today, .timeline, .transactions])
            separator
            navGroup("SECURITY", [.alerts, .lineage, .feedback])
            separator
            navGroup("CONFIGURATION", [.harnesses, .policy, .settings])
            Spacer()
        }
        .padding(.top, 8)
        .background(Color.dashboardPanel)
    }

    private func navGroup(_ title: String, _ destinations: [DashboardDestination]) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.tertiary)
                .padding(.horizontal, 20)
                .padding(.top, 8)
                .padding(.bottom, 5)
            ForEach(destinations) { destination in
                Button { selection = destination } label: {
                    HStack(spacing: 10) {
                        Image(systemName: destination.symbol).frame(width: 16)
                        Text(destination.rawValue)
                        Spacer()
                        if destination == .alerts, alertCount > 0 {
                            Text(alertCount.formatted())
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(Color.dashboardRed, in: Capsule())
                        }
                    }
                    .font(.system(size: 13, weight: selection == destination ? .semibold : .regular))
                    .foregroundStyle(selection == destination ? Color.dashboardRed : Color.primary)
                    .padding(.horizontal, 20)
                    .frame(height: 34)
                    .background(selection == destination ? Color.dashboardRed.opacity(0.09) : .clear)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var separator: some View {
        Rectangle().fill(Color.dashboardLine).frame(height: 1).padding(.vertical, 5)
    }
}

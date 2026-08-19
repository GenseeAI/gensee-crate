import SwiftUI

enum DashboardDestination: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case reviews = "Work Review"
    case today = "Daily Highlight"
    case alerts = "Alerts"
    case lineage = "Lineage Graph"
    case checkpoints = "Checkpoints"
    case harnesses = "Harnesses"
    case policy = "Policy"
    case settings = "Settings"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .overview: "gauge.with.dots.needle.33percent"
        case .reviews: "checklist.checked"
        case .today: "star"
        case .alerts: "exclamationmark.triangle"
        case .lineage: "point.3.connected.trianglepath.dotted"
        case .checkpoints: "arrow.uturn.backward.circle"
        case .harnesses: "switch.2"
        case .policy: "checkmark.shield"
        case .settings: "gearshape"
        }
    }
}

struct DashboardShell: View {
    @ObservedObject var extensionManager: EndpointSecurityExtensionManager
    @ObservedObject var model: ConsoleModel
    @Binding var showsSetupAssistant: Bool
    @State private var selection: DashboardDestination = .overview
    @State private var searchText = ""
    @StateObject private var notifications = CompletionNotificationCoordinator()
    @AppStorage("gensee.dashboard.darkMode") private var darkMode = false

    var body: some View {
        VStack(spacing: 0) {
            topBar
            if model.isDemoMode {
                demoBanner
            }
            HStack(spacing: 0) {
                DashboardSidebar(selection: $selection, alertCount: model.unreadAlertCount)
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
            await notifications.refreshAuthorizationStatus()
            await model.refreshAll()
            await notifications.process(snapshot: model.snapshot)
            while !Task.isCancelled {
                // Dashboard queries intentionally run less frequently than the
                // sensor poll. This keeps UI projection work from competing
                // with durable Endpoint Security ingestion under load.
                try? await Task.sleep(for: .seconds(10))
                await model.refreshDashboard(reportErrors: false)
                await notifications.process(snapshot: model.snapshot)
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
            if !model.isDemoMode {
                Button {
                    model.enterDemoMode()
                    selection = .overview
                } label: {
                    Label("Try Demo", systemImage: "play.rectangle")
                }
                .buttonStyle(.plain)
                .font(.system(size: 10, weight: .semibold))
                .help("Explore synthetic data without changing this Mac")
            }
            if let issue = model.dashboardRefreshIssue {
                Label("Refresh delayed", systemImage: "exclamationmark.arrow.triangle.2.circlepath")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Color.dashboardGold)
                    .help(issue)
            }
            Button { selection = .alerts } label: { Image(systemName: "bell") }
                .buttonStyle(.plain).help("Alerts")
            Button { selection = .settings } label: { Image(systemName: "questionmark.circle") }
                .buttonStyle(.plain).help("Help and settings")
            Button { darkMode.toggle() } label: { Image(systemName: darkMode ? "sun.max" : "moon") }
                .buttonStyle(.plain).help(darkMode ? "Switch to light mode" : "Switch to dark mode")
        }
        .padding(.horizontal, 16)
        .frame(height: 56)
        .background(Color.dashboardPanel)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.dashboardLine).frame(height: 1) }
    }

    private var demoBanner: some View {
        HStack(spacing: 9) {
            Image(systemName: "sparkles.rectangle.stack")
            VStack(alignment: .leading, spacing: 1) {
                Text("Synthetic demo — nothing here came from this Mac")
                    .font(.system(size: 11, weight: .semibold))
                Text("No hooks, database, policy, Apple permissions, or harness settings are changed.")
                    .font(.system(size: 9))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Exit Demo") {
                Task { await model.exitDemoMode() }
            }
            .controlSize(.small)
        }
        .padding(.horizontal, 16)
        .frame(height: 48)
        .foregroundStyle(Color.dashboardBlue)
        .background(Color.dashboardBlue.opacity(0.10))
        .overlay(alignment: .bottom) { Rectangle().fill(Color.dashboardBlue.opacity(0.25)).frame(height: 1) }
    }

    @ViewBuilder
    private var destinationView: some View {
        if model.isDemoMode && [.harnesses, .policy, .checkpoints, .settings].contains(selection) {
            DemoConfigurationPage(destination: selection) {
                Task { await model.exitDemoMode() }
            }
        } else {
            switch selection {
            case .overview: DashboardOverviewPage(model: model, sensor: model.endpointSensor)
            case .reviews: DashboardWorkReviewPage(
                model: model,
                searchText: searchText
            )
            case .today: TodayHighlightPage(model: model)
            case .alerts: DashboardAlertsPage(model: model, searchText: searchText)
            case .lineage: LineagePage(model: model, searchText: searchText)
            case .checkpoints: DashboardRecoveryPage(model: model)
            case .harnesses: DashboardHarnessesPage(model: model)
            case .policy: DashboardPolicyPage(model: model)
            case .settings: DashboardSettingsPage(
                model: model,
                extensionManager: extensionManager,
                sensor: model.endpointSensor,
                notifications: notifications,
                darkMode: $darkMode,
                onRunSetupAssistant: { showsSetupAssistant = true }
            )
            }
        }
    }

    private var errorPresented: Binding<Bool> {
        Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })
    }

    private var noticePresented: Binding<Bool> {
        Binding(get: { model.noticeMessage != nil }, set: { if !$0 { model.noticeMessage = nil } })
    }
}

private struct DemoConfigurationPage: View {
    let destination: DashboardDestination
    let onExit: () -> Void

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader(destination.rawValue, description: "Real configuration is intentionally unavailable in synthetic demo mode.")
                DashboardCard {
                    VStack(spacing: 14) {
                        Image(systemName: "lock.shield")
                            .font(.system(size: 30))
                            .foregroundStyle(Color.dashboardBlue)
                        Text("Your Mac is untouched")
                            .font(.system(size: 18, weight: .semibold))
                        Text("Exit the demo when you are ready to scan installed harnesses, choose a protection level, or change local settings. Gensee will show every required permission before it makes a change.")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: 520)
                        Button("Exit Demo and Configure", action: onExit)
                            .buttonStyle(.borderedProminent)
                            .tint(.dashboardBlue)
                    }
                    .frame(maxWidth: .infinity, minHeight: 300)
                }
            }
        }
    }
}

private struct DashboardSidebar: View {
    @Binding var selection: DashboardDestination
    let alertCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            navGroup("OVERVIEW", [.overview])
            separator
            navGroup("ACTIVITY", [.reviews, .today, .checkpoints])
            separator
            navGroup("SECURITY", [.alerts, .lineage])
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

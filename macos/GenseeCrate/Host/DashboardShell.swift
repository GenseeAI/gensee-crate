import SwiftUI

enum DashboardDestination: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case reviews = "Review Queue"
    case today = "Daily Highlight"
    case lineage = "Watchlist"
    case harnesses = "Harnesses"
    case policy = "Policy"
    case settings = "Settings"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .overview: "rectangle.grid.2x2"
        case .reviews: "doc.text.magnifyingglass"
        case .today: "calendar"
        case .lineage: "eye"
        case .harnesses: "slider.horizontal.3"
        case .policy: "shield"
        case .settings: "gearshape"
        }
    }
}

struct DashboardShell: View {
    @ObservedObject var extensionManager: EndpointSecurityExtensionManager
    @ObservedObject var model: ConsoleModel
    @ObservedObject var notifications: CompletionNotificationCoordinator
    @Binding var showsSetupAssistant: Bool
    @State private var selection: DashboardDestination = .overview
    @State private var searchText = ""
    @AppStorage("gensee.dashboard.darkMode") private var darkMode = false

    var body: some View {
        VStack(spacing: 0) {
            topBar
            if model.isDemoMode {
                demoBanner
            }
            HStack(spacing: 0) {
                DashboardSidebar(selection: $selection)
                    .frame(width: 220)
                Rectangle().fill(Color.dashboardLine).frame(width: 1)
                ZStack {
                    Color.dashboardCanvas.ignoresSafeArea()
                    destinationView
                    if model.lastUpdated == nil, model.runningCommand == nil, !model.isDemoMode {
                        VStack {
                            DashboardLoadingHint(message: "Loading local Gensee data…")
                                .padding(.horizontal, 14)
                                .padding(.vertical, 10)
                                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 7))
                                .shadow(color: .black.opacity(0.10), radius: 8, y: 3)
                            Spacer()
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .padding(.top, 18)
                        .allowsHitTesting(false)
                    }
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
        .onChange(of: searchText) { query in
            guard !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
            if ![DashboardDestination.reviews, .lineage].contains(selection) {
                selection = .reviews
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .genseeOpenAgentReview)) { notification in
            guard let requestID = (notification.userInfo?["request_id"] as? NSNumber)?.int64Value else { return }
            model.requestedReviewRequestID = requestID
            selection = .reviews
        }
        .onChange(of: model.requestedDashboardDestination) { destination in
            guard let destination else { return }
            selection = destination
            model.requestedDashboardDestination = nil
        }
        .task {
            extensionManager.refreshStatus()
            await model.refreshStableHookBackendIfNeeded()
            model.endpointSensor.start()
            await notifications.refreshAuthorizationStatus()
            await model.refreshAll()
            await model.refreshPendingRecoveryRequest()
            if !model.isDemoMode {
                await notifications.process(snapshot: model.snapshot)
            }
            while !Task.isCancelled {
                // Dashboard queries intentionally run less frequently than the
                // sensor poll. This keeps UI projection work from competing
                // with durable Endpoint Security ingestion under load.
                try? await Task.sleep(for: .seconds(model.dashboardPollingSeconds))
                await model.refreshDashboard(reportErrors: false)
                if !model.isDemoMode {
                    await notifications.process(snapshot: model.snapshot)
                }
            }
        }
        .task {
            while !Task.isCancelled {
                await model.refreshPendingRecoveryRequest()
                try? await Task.sleep(for: .seconds(model.pendingRecoveryPollingSeconds))
            }
        }
        .task {
            await model.refreshEndpointSessionRootsIfNeeded(force: true)
            while !Task.isCancelled {
                // This loop stats one small local file. It launches the
                // lightweight roots query only when a hook appends a session
                // lifecycle record, keeping first-tool registration prompt
                // without repeatedly rebuilding the dashboard snapshot.
                try? await Task.sleep(for: .milliseconds(200))
                await model.refreshEndpointSessionRootsIfNeeded()
            }
        }
        .task {
            // Wait for the initial snapshot so stored history becomes the
            // completion watermark rather than triggering old notifications.
            while model.lastUpdated == nil, !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(100))
            }
            guard !Task.isCancelled else { return }
            model.prepareCompletionWatcher()
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(200))
                if await model.refreshRecentCompletionsIfNeeded(), !model.isDemoMode {
                    await notifications.process(snapshot: model.snapshot)
                }
            }
        }
        .alert("Gensee needs attention", isPresented: errorPresented) {
            Button("Dismiss", role: .cancel) { model.errorMessage = nil }
        } message: { Text(model.errorMessage ?? "Unknown error") }
        .alert("Gensee updated", isPresented: noticePresented) {
            Button("OK", role: .cancel) { model.noticeMessage = nil }
        } message: { Text(model.noticeMessage ?? "") }
        .alert(
            "Create a recovery point?",
            isPresented: pendingRecoveryPresented,
            presenting: model.pendingRecoveryRequest
        ) { request in
            Button("Create & Continue") {
                Task { await model.resolvePendingRecoveryRequest(request, create: true) }
            }
            Button("Continue Without") {
                Task { await model.resolvePendingRecoveryRequest(request, create: false) }
            }
            Button("Always create for \(HarnessDisplayName.from(request.provider))") {
                Task {
                    await model.resolvePendingRecoveryRequest(
                        request,
                        create: true,
                        alwaysCreate: true
                    )
                }
            }
            Button("Keep Blocked", role: .cancel) {
                model.dismissPendingRecoveryRequest()
            }
        } message: { request in
            Text("\(HarnessDisplayName.from(request.provider)) is about to make changes to \(abbreviatedPath(request.workspace)). \(request.reason). Recovery points cover Git-workspace files only; they cannot undo database, network, remote repository, process, or ignored-file changes.")
        }
    }

    private var topBar: some View {
        HStack(spacing: 16) {
            HStack(spacing: 10) {
                BrandEye(size: 28)
                Text("Gensee Crate")
                    .font(.system(size: 15, weight: .bold))
                    .tracking(0.3)
            }
            .frame(width: 204, alignment: .leading)

            HStack(spacing: 7) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField(searchPlaceholder, text: $searchText)
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
            toolbarIconButton(symbol: "questionmark.circle", help: "Help and settings") { selection = .settings }
            toolbarIconButton(
                symbol: darkMode ? "sun.max" : "moon",
                help: darkMode ? "Switch to light mode" : "Switch to dark mode"
            ) { darkMode.toggle() }
        }
        .padding(.horizontal, 16)
        .frame(height: 56)
        .background(Color.dashboardPanel)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.dashboardLine).frame(height: 1) }
    }

    private var searchPlaceholder: String {
        switch selection {
        case .reviews: "Search prompts, harnesses, sessions, or files…"
        case .lineage: "Search watched files, risks, or sources…"
        default: "Search Review Queue prompts and files…"
        }
    }

    private func toolbarIconButton(
        symbol: String,
        help: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            DashboardSymbol(symbol, color: .secondary, size: 13, weight: .regular)
                .frame(width: 28, height: 28)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
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
        if model.isDemoMode && [.harnesses, .policy, .settings].contains(selection) {
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
            case .lineage: LineagePage(model: model, searchText: searchText)
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

    private var pendingRecoveryPresented: Binding<Bool> {
        Binding(
            get: { model.pendingRecoveryRequest != nil },
            // Every dismissal path is an explicit alert button. A competing
            // error alert may temporarily drive this binding false; treating
            // that as Keep Blocked would strand a retryable approval.
            set: { _ in }
        )
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

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(DashboardDestination.allCases) { destination in
                navItem(destination)
            }
            Spacer()
        }
        .padding(.top, 12)
        .background(Color.dashboardPanel)
    }

    private func navItem(_ destination: DashboardDestination) -> some View {
        Button { selection = destination } label: {
            HStack(spacing: 10) {
                DashboardSymbol(
                    destination.symbol,
                    color: selection == destination ? .dashboardRed : .secondary,
                    size: 13,
                    weight: selection == destination ? .semibold : .regular
                )
                .frame(width: 16)
                Text(destination.rawValue)
                Spacer()
            }
            .font(.system(size: 13, weight: selection == destination ? .semibold : .regular))
            .foregroundStyle(selection == destination ? Color.dashboardRed : Color.primary)
            .padding(.horizontal, 20)
            .frame(height: 36)
            .background(selection == destination ? Color.dashboardRed.opacity(0.09) : .clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

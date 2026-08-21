import AppKit
import Combine
import SwiftUI

@main
struct GenseeCrateApp: App {
    @NSApplicationDelegateAdaptor(GenseeAppDelegate.self) private var appDelegate
    @StateObject private var extensionManager = EndpointSecurityExtensionManager()
    @StateObject private var consoleModel = ConsoleModel()
    @StateObject private var notifications = CompletionNotificationCoordinator()

    var body: some Scene {
        WindowGroup("Gensee Crate", id: "main") {
            ContentView(
                extensionManager: extensionManager,
                model: consoleModel,
                notifications: notifications
            )
                .frame(minWidth: 1180, minHeight: 720)
                .onAppear {
                    appDelegate.statusItem.start(model: consoleModel)
                }
        }
        .windowResizability(.contentMinSize)
    }
}

@MainActor
private final class GenseeAppDelegate: NSObject, NSApplicationDelegate {
    let statusItem = GenseeStatusItemController()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Register the status item from the AppKit application lifecycle. A
        // SwiftUI view can be restored without re-running its appearance
        // callback, which previously left the app without its durable menu.
        statusItem.install()
    }
}

/// A native status item remains available while the main app is behind an
/// agent harness and provides a durable counterpart to transient notification
/// banners. AppKit is used here because the SwiftUI MenuBarExtra scene did not
/// consistently register after replacing a signed system-extension host app.
@MainActor
private final class GenseeStatusItemController: NSObject, ObservableObject, NSMenuDelegate {
    private static let autosaveName = "GenseeCrate"
    private static let preferredPositionKey = "NSStatusItem Preferred Position \(autosaveName)"
    private static let visibleKey = "NSStatusItem Visible \(autosaveName)"

    private weak var model: ConsoleModel?
    private var statusItem: NSStatusItem?
    private weak var attentionBadge: NSView?
    private var modelChangeSubscription: AnyCancellable?
    private var reviewObserver: NSObjectProtocol?

    func install() {
        guard statusItem == nil else { return }

        // Give AppKit a stable identity so macOS can preserve the item's
        // position instead of appending it at the far-left edge of an already
        // crowded menu bar. On notched MacBooks that fallback position can be
        // physically hidden beneath the camera housing even though AppKit
        // reports the status item as visible.
        let defaults = UserDefaults.standard
        if defaults.object(forKey: Self.preferredPositionKey) == nil {
            // A smaller preferred position keeps Gensee with the always-visible
            // system controls on the right side of the menu bar. Users can
            // still Command-drag it to another position; AppKit persists that.
            defaults.set(120, forKey: Self.preferredPositionKey)
        }
        if defaults.object(forKey: Self.visibleKey) == nil {
            defaults.set(true, forKey: Self.visibleKey)
        }

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.autosaveName = Self.autosaveName
        item.isVisible = true
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        statusItem = item
        installAttentionBadge(on: item.button)
        refreshStatusItem()
    }

    func start(model: ConsoleModel) {
        self.model = model
        install()

        if modelChangeSubscription == nil {
            modelChangeSubscription = model.objectWillChange.sink { [weak self] _ in
                DispatchQueue.main.async { self?.refreshStatusItem() }
            }
        }
        if reviewObserver == nil {
            reviewObserver = NotificationCenter.default.addObserver(
                forName: .genseeOpenAgentReview,
                object: nil,
                queue: .main
            ) { [weak self] notification in
                guard let requestID = (notification.userInfo?["request_id"] as? NSNumber)?.int64Value else { return }
                Task { @MainActor in self?.openReviewQueue(requestID: requestID) }
            }
        }

        refreshStatusItem()
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        rebuildMenu(menu)
    }

    private var actionableReviews: [AgentCompletionSummary] {
        guard let model else { return [] }
        return AgentCompletionDerivation.summaries(from: model.snapshot)
            .filter { model.reviewNeedsAttention($0) }
    }

    private func refreshStatusItem() {
        guard let button = statusItem?.button else { return }
        let count = actionableReviews.count
        let mark = NSImage(named: "MenuBarEye") ?? NSImage(
            systemSymbolName: "eye.circle",
            accessibilityDescription: "Gensee Crate"
        )
        mark?.isTemplate = true
        mark?.size = NSSize(width: 18, height: 18)
        button.image = mark
        button.imageScaling = .scaleProportionallyDown
        button.imagePosition = .imageOnly
        button.title = ""
        button.attributedTitle = NSAttributedString(string: "")
        installAttentionBadge(on: button)
        attentionBadge?.isHidden = count == 0
        button.toolTip = count == 0
            ? "Gensee Crate — all agents clear"
            : "Gensee Crate — \(count) request\(count == 1 ? "" : "s") to review"
        button.setAccessibilityLabel(button.toolTip ?? "Gensee Crate")
    }

    private func installAttentionBadge(on button: NSStatusBarButton?) {
        guard attentionBadge == nil, let button else { return }

        let badge = GenseeStatusBadgeView(frame: .zero)
        badge.translatesAutoresizingMaskIntoConstraints = false
        badge.wantsLayer = true
        badge.layer?.backgroundColor = NSColor.systemRed.cgColor
        badge.layer?.cornerRadius = 2.5
        badge.isHidden = true
        button.addSubview(badge)
        NSLayoutConstraint.activate([
            badge.widthAnchor.constraint(equalToConstant: 5),
            badge.heightAnchor.constraint(equalToConstant: 5),
            badge.topAnchor.constraint(equalTo: button.topAnchor, constant: 2),
            badge.trailingAnchor.constraint(equalTo: button.trailingAnchor, constant: -2),
        ])
        attentionBadge = badge
    }

    private func rebuildMenu(_ menu: NSMenu) {
        menu.removeAllItems()
        let actionable = actionableReviews

        let title = NSMenuItem(title: "Gensee Crate", action: #selector(openStatus(_:)), keyEquivalent: "")
        title.target = self
        menu.addItem(title)

        let statusTitle: String
        if model?.endpointSensor.health.connected == true {
            statusTitle = actionable.isEmpty
                ? "Independent verification is active"
                : "\(actionable.count) request\(actionable.count == 1 ? "" : "s") to review"
        } else {
            statusTitle = "OS verification is off — open Settings to connect"
        }
        let status = NSMenuItem(
            title: statusTitle,
            action: model?.endpointSensor.health.connected == true
                ? (actionable.isEmpty ? #selector(openStatus(_:)) : #selector(openQueue(_:)))
                : #selector(openSettings(_:)),
            keyEquivalent: ""
        )
        status.target = self
        menu.addItem(status)
        menu.addItem(.separator())

        if actionable.isEmpty {
            let clear = NSMenuItem(title: "No reviews pending", action: nil, keyEquivalent: "")
            clear.image = NSImage(systemSymbolName: "checkmark.circle.fill", accessibilityDescription: nil)
            clear.isEnabled = false
            menu.addItem(clear)
        } else {
            for review in actionable.prefix(5) {
                let signal = review.attentionSignal
                let item = NSMenuItem(
                    title: "\(signal?.title ?? "Needs review") — \(review.harness)",
                    action: #selector(openReview(_:)),
                    keyEquivalent: ""
                )
                item.target = self
                item.representedObject = NSNumber(value: review.requestID)
                item.image = NSImage(
                    systemSymbolName: signal?.systemImage ?? "exclamationmark.triangle",
                    accessibilityDescription: nil
                )
                item.toolTip = review.prompt
                menu.addItem(item)
            }
        }
    }

    @objc private func openReview(_ sender: NSMenuItem) {
        guard let requestID = (sender.representedObject as? NSNumber)?.int64Value else { return }
        openReviewQueue(requestID: requestID)
    }

    @objc private func openStatus(_ sender: NSMenuItem) {
        openGensee(destination: .overview, requestID: nil)
    }

    @objc private func openQueue(_ sender: NSMenuItem) {
        openReviewQueue(requestID: nil)
    }

    @objc private func openSettings(_ sender: NSMenuItem) {
        openGensee(destination: .settings, requestID: nil)
    }

    private func openReviewQueue(requestID: Int64?) {
        openGensee(destination: .reviews, requestID: requestID)
    }

    private func openGensee(destination: DashboardDestination, requestID: Int64?) {
        guard let model else { return }
        model.requestedReviewRequestID = requestID
        model.requestedDashboardDestination = destination
        NSApp.activate(ignoringOtherApps: true)

        if let window = NSApp.windows.first(where: {
            $0.title == "Gensee Crate" && $0.canBecomeMain
        }) {
            window.makeKeyAndOrderFront(nil)
        }
    }
}

/// The attention badge is visual state for the status item, not a separate
/// click target. Let clicks anywhere in the square icon continue to open the
/// menu, including directly over the badge.
private final class GenseeStatusBadgeView: NSView {
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
}

private struct GenseeMenuBarLabel: View {
    @ObservedObject var model: ConsoleModel
    @Environment(\.openWindow) private var openWindow
    let actionableReviewCount: Int

    var body: some View {
        ZStack(alignment: .topTrailing) {
            // Status-bar images are rendered as monochrome templates by
            // macOS. BrandEye is the full-color application artwork, whose
            // opaque pixels can collapse into an invisible square here. Use a
            // purpose-built transparent glyph so the eye stays legible in
            // light, dark, and highlighted menu-bar states.
            Image("MenuBarEye")
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: 17, height: 17)
            if actionableReviewCount > 0 {
                Circle()
                    .fill(Color.dashboardGold)
                    .frame(width: 5, height: 5)
                    .offset(x: 2, y: -1)
            }
        }
        .frame(width: 20, height: 18)
        .accessibilityLabel("Gensee Crate, \(actionableReviewCount) requests to review")
        .onReceive(NotificationCenter.default.publisher(for: .genseeOpenAgentReview)) { notification in
            guard let requestID = (notification.userInfo?["request_id"] as? NSNumber)?.int64Value else { return }
            model.requestedReviewRequestID = requestID
            model.requestedDashboardDestination = .reviews
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}

private struct GenseeMenuBarView: View {
    @ObservedObject var model: ConsoleModel
    @ObservedObject var extensionManager: EndpointSecurityExtensionManager
    @Environment(\.openWindow) private var openWindow

    private var reviews: [AgentCompletionSummary] {
        AgentCompletionDerivation.summaries(from: model.snapshot)
    }

    private var actionableReviews: [AgentCompletionSummary] {
        reviews.filter { model.reviewNeedsAttention($0) }
    }

    private var attentionByHarness: [(harness: String, count: Int)] {
        Dictionary(grouping: actionableReviews, by: \.harness)
            .map { (harness: $0.key, count: $0.value.count) }
            .sorted { lhs, rhs in
                lhs.count == rhs.count ? lhs.harness < rhs.harness : lhs.count > rhs.count
            }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 9) {
                BrandEye(size: 28)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Gensee Crate").font(.system(size: 13, weight: .semibold))
                    Text(statusLine).font(.system(size: 10)).foregroundStyle(.secondary)
                }
                Spacer()
                Circle()
                    .fill(model.endpointSensor.health.connected ? Color.dashboardGreen : Color.dashboardGold)
                    .frame(width: 8, height: 8)
            }

            Divider()

            if actionableReviews.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Label("No reviews pending", systemImage: "checkmark.circle.fill")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color.dashboardGreen)
                    Text("Completed requests remain available under All.")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                    Button("Open History") { openMain(.reviews) }
                        .controlSize(.small)
                }
            } else {
                VStack(alignment: .leading, spacing: 5) {
                    Text("TO REVIEW").font(.system(size: 8, weight: .bold)).tracking(0.8).foregroundStyle(.secondary)
                    HStack(spacing: 7) {
                        ForEach(attentionByHarness, id: \.harness) { item in
                            Text("\(item.harness) \(item.count)")
                                .font(.system(size: 9, weight: .semibold))
                                .padding(.horizontal, 7)
                                .padding(.vertical, 3)
                                .background(Color.dashboardGold.opacity(0.12), in: Capsule())
                        }
                    }

                    ForEach(actionableReviews.prefix(4)) { request in
                        Button {
                            model.requestedReviewRequestID = request.requestID
                            openMain(.reviews)
                        } label: {
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: request.attentionSignal?.systemImage ?? "exclamationmark.triangle")
                                    .foregroundStyle(Color.dashboardGold)
                                    .frame(width: 15)
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack {
                                        Text(request.attentionSignal?.title ?? "Needs review")
                                            .font(.system(size: 10, weight: .semibold))
                                        Spacer()
                                        Text(request.harness)
                                            .font(.system(size: 9))
                                            .foregroundStyle(.secondary)
                                    }
                                    Text(request.prompt)
                                        .font(.system(size: 9))
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }

            Divider()

            HStack {
                Label(
                    actionableReviews.isEmpty ? "All agents clear" : "\(actionableReviews.count) to review",
                    systemImage: actionableReviews.isEmpty ? "checkmark.circle" : "bell.badge"
                )
                    .font(.system(size: 10, weight: .medium))
                Spacer()
                Button(actionableReviews.isEmpty ? "Open Gensee" : "Open Review Queue") {
                    openMain(actionableReviews.isEmpty ? .overview : .reviews)
                }
                    .controlSize(.small)
            }
        }
        .padding(14)
        .frame(width: 360)
        .task {
            extensionManager.refreshStatus()
            model.endpointSensor.start()
            await model.refreshDashboard(reportErrors: false)
        }
    }

    private var statusLine: String {
        if !model.endpointSensor.health.connected { return "OS verification is off — open Settings to connect" }
        if let issue = model.dashboardRefreshIssue { return issue }
        return "Independent verification is active"
    }

    private func openMain(_ destination: DashboardDestination) {
        model.requestedDashboardDestination = destination
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}

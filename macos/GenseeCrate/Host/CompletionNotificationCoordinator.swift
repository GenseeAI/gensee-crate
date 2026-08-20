import AppKit
import Foundation
import OSLog
import UserNotifications

struct AlertNotificationDigest: Equatable {
    let title: String
    let body: String
    let highestAlertID: Int64
    let highestSeverity: String
}

@MainActor
final class CompletionNotificationCoordinator: NSObject, ObservableObject {
    @Published private(set) var authorizationStatus: UNAuthorizationStatus = .notDetermined
    @Published private(set) var lastDeliveryError: String?
    @Published var completionNotificationsEnabled: Bool {
        didSet { defaults.set(completionNotificationsEnabled, forKey: Self.completionEnabledKey) }
    }
    @Published var dailyBriefingEnabled: Bool {
        didSet { defaults.set(dailyBriefingEnabled, forKey: Self.dailyEnabledKey) }
    }
    @Published var alertNotificationsEnabled: Bool {
        didSet { defaults.set(alertNotificationsEnabled, forKey: Self.alertEnabledKey) }
    }
    @Published var minimumAlertSeverity: NotificationSeverity {
        didSet { defaults.set(minimumAlertSeverity.rawValue, forKey: Self.minimumAlertSeverityKey) }
    }

    private let center = UNUserNotificationCenter.current()
    private let defaults = UserDefaults.standard
    private let logger = Logger(subsystem: "ai.gensee.crate", category: "notifications")
    private var hasSeededCurrentStore = false
    // Only requests that have actually produced an actionable completion
    // notification belong here. Clean completions must remain eligible to
    // notify later when delayed Endpoint Security evidence turns them into a
    // needs-you result.
    private var notifiedRequestIDs: Set<Int64>
    private var notifiedAlertIDs: Set<Int64>

    override init() {
        completionNotificationsEnabled = UserDefaults.standard.object(forKey: Self.completionEnabledKey) as? Bool ?? true
        dailyBriefingEnabled = UserDefaults.standard.bool(forKey: Self.dailyEnabledKey)
        alertNotificationsEnabled = UserDefaults.standard.bool(forKey: Self.alertEnabledKey)
        minimumAlertSeverity = NotificationSeverity(
            rawValue: UserDefaults.standard.string(forKey: Self.minimumAlertSeverityKey) ?? "high"
        ) ?? .high
        notifiedRequestIDs = Set(
            (UserDefaults.standard.array(forKey: Self.notifiedRequestsKey) ?? []).compactMap { value in
                if let number = value as? NSNumber {
                    return number.int64Value
                }
                if let string = value as? String {
                    return Int64(string)
                }
                return nil
            }
        )
        notifiedAlertIDs = Set(
            (UserDefaults.standard.array(forKey: Self.notifiedAlertsKey) ?? []).compactMap { value in
                if let number = value as? NSNumber { return number.int64Value }
                if let string = value as? String { return Int64(string) }
                return nil
            }
        )
        super.init()
        center.delegate = self
        center.setNotificationCategories([
            UNNotificationCategory(
                identifier: Self.agentReviewCategoryIdentifier,
                actions: [
                    UNNotificationAction(
                        identifier: Self.openReviewActionIdentifier,
                        title: "Open Review",
                        options: [.foreground]
                    ),
                ],
                intentIdentifiers: []
            ),
        ])
    }

    var isAuthorized: Bool {
        authorizationStatus == .authorized || authorizationStatus == .provisional
    }

    var authorizationDescription: String {
        switch authorizationStatus {
        case .notDetermined: "Not requested"
        case .denied: "Denied"
        case .authorized: "Allowed"
        case .provisional: "Provisional"
        case .ephemeral: "Temporary"
        @unknown default: "Unknown"
        }
    }

    func refreshAuthorizationStatus() async {
        authorizationStatus = await center.notificationSettings().authorizationStatus
    }

    func requestAuthorization() async {
        do {
            _ = try await center.requestAuthorization(options: [.alert, .badge, .sound])
            await refreshAuthorizationStatus()
        } catch {
            authorizationStatus = .denied
            lastDeliveryError = error.localizedDescription
            logger.error("Notification authorization failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    func sendTestNotification() async {
        await refreshAuthorizationStatus()
        guard isAuthorized else {
            lastDeliveryError = "macOS notification permission is \(authorizationDescription.lowercased())."
            logger.error("Test notification skipped: authorization is \(self.authorizationDescription, privacy: .public)")
            return
        }

        let content = UNMutableNotificationContent()
        content.title = "Gensee notifications are working"
        content.body = "Gensee will notify you when agent work is ready for review."
        content.sound = .default
        content.interruptionLevel = .active
        let request = UNNotificationRequest(
            identifier: "gensee-notification-test-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        do {
            try await center.add(request)
            lastDeliveryError = nil
            logger.notice("Test notification submitted successfully")
        } catch {
            lastDeliveryError = error.localizedDescription
            logger.error("Test notification delivery failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    func openSystemNotificationSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") else { return }
        NSWorkspace.shared.open(url)
    }

    func process(snapshot: SecuritySnapshot, now: Date = Date()) async {
        let summaries = AgentCompletionDerivation.summaries(from: snapshot)
        guard hasSeededCurrentStore else {
            // The first refresh is history, not a burst of newly completed work.
            notifiedRequestIDs.formUnion(summaries.map(\.requestID))
            notifiedAlertIDs.formUnion(snapshot.alerts.map(\.alertID))
            persistNotifiedRequests()
            persistNotifiedAlerts()
            hasSeededCurrentStore = true
            await sendDailyBriefingIfNeeded(snapshot: snapshot, now: now)
            return
        }

        let actionable = Self.newlyActionableSummaries(
            summaries,
            excluding: notifiedRequestIDs
        )
        if completionNotificationsEnabled, !actionable.isEmpty {
            // Authorization can change while the app is running and the
            // cached value can be stale after rebuilding or moving the app.
            // Re-read it at the delivery boundary instead of silently
            // dropping an actionable completion.
            await refreshAuthorizationStatus()
        }
        if completionNotificationsEnabled, isAuthorized {
            for summary in actionable.reversed() {
                if await sendCompletion(summary) {
                    notifiedRequestIDs.insert(summary.requestID)
                }
            }
        } else if completionNotificationsEnabled, !actionable.isEmpty {
            lastDeliveryError = "macOS notification permission is \(authorizationDescription.lowercased())."
            logger.error(
                "Skipped \(actionable.count) actionable completion notification(s): authorization is \(self.authorizationDescription, privacy: .public)"
            )
        }
        if alertNotificationsEnabled, isAuthorized {
            let newAlerts = snapshot.alerts.filter {
                !notifiedAlertIDs.contains($0.alertID) && minimumAlertSeverity.includes($0.severity)
            }
            if !newAlerts.isEmpty {
                await sendAlertDigest(newAlerts)
            }
        }
        notifiedAlertIDs.formUnion(snapshot.alerts.map(\.alertID))
        persistNotifiedRequests()
        persistNotifiedAlerts()
        await sendDailyBriefingIfNeeded(snapshot: snapshot, now: now)
    }

    static func newlyActionableSummaries(
        _ summaries: [AgentCompletionSummary],
        excluding notifiedRequestIDs: Set<Int64>
    ) -> [AgentCompletionSummary] {
        summaries.filter {
            $0.needsIntervention && !notifiedRequestIDs.contains($0.requestID)
        }
    }

    @discardableResult
    private func sendCompletion(_ summary: AgentCompletionSummary) async -> Bool {
        guard let signal = summary.attentionSignal else { return false }
        let content = UNMutableNotificationContent()
        content.title = signal.title
        content.subtitle = "\(summary.harness) · Review recommended"
        content.body = AgentCompletionDerivation.notificationBody(for: summary)
        content.sound = .default
        // Keep the default active interruption level. Time-sensitive delivery
        // requires an additional Apple entitlement; setting it without that
        // entitlement causes UNUserNotificationCenter.add to reject the entire
        // request, which previously failed silently.
        content.interruptionLevel = .active
        content.categoryIdentifier = Self.agentReviewCategoryIdentifier
        content.userInfo = ["request_id": summary.requestID]
        let request = UNNotificationRequest(
            identifier: "gensee-completion-\(summary.requestID)",
            content: content,
            trigger: nil
        )
        do {
            logger.notice("Submitting completion notification for request \(summary.requestID)")
            try await center.add(request)
            lastDeliveryError = nil
            logger.notice("Completion notification submitted for request \(summary.requestID)")
            return true
        } catch {
            lastDeliveryError = error.localizedDescription
            logger.error(
                "Completion notification failed for request \(summary.requestID): \(error.localizedDescription, privacy: .public)"
            )
            return false
        }
    }

    private func sendAlertDigest(_ alerts: [SecurityAlert]) async {
        guard let digest = Self.alertDigest(for: alerts) else { return }

        let content = UNMutableNotificationContent()
        content.title = digest.title
        content.body = digest.body
        content.sound = NotificationSeverity.rank(for: digest.highestSeverity) >= NotificationSeverity.rank(for: "high")
            ? .default
            : nil
        content.userInfo = ["alert_id": digest.highestAlertID]
        let request = UNNotificationRequest(
            identifier: "gensee-alerts-\(digest.highestAlertID)",
            content: content,
            trigger: nil
        )
        try? await center.add(request)
    }

    static func alertDigest(for alerts: [SecurityAlert]) -> AlertNotificationDigest? {
        let ordered = alerts.sorted {
            let left = NotificationSeverity.rank(for: $0.severity)
            let right = NotificationSeverity.rank(for: $1.severity)
            return left == right ? $0.createdAt > $1.createdAt : left > right
        }
        guard let highest = ordered.first else { return nil }
        return AlertNotificationDigest(
            title: ordered.count == 1
                ? "\(highest.severity.capitalized) finding needs review"
                : "\(ordered.count) new findings need review",
            body: ordered.count == 1
                ? highest.message
                : "\(highest.message) · \(ordered.count - 1) more",
            highestAlertID: highest.alertID,
            highestSeverity: highest.severity
        )
    }

    private func sendDailyBriefingIfNeeded(snapshot: SecuritySnapshot, now: Date) async {
        guard dailyBriefingEnabled, isAuthorized, Calendar.current.component(.hour, from: now) >= 17 else { return }
        let day = Self.dayFormatter.string(from: now)
        guard defaults.string(forKey: Self.lastDailyBriefingKey) != day,
              let activity = snapshot.dailyActivity.first(where: { $0.date == day }),
              activity.requests + activity.toolCalls + activity.alerts > 0
        else { return }

        let content = UNMutableNotificationContent()
        content.title = "Your Gensee daily briefing is ready"
        content.body = "\(activity.requests) agent turns · \(activity.toolCalls) tool calls · \(activity.alerts) findings"
        let request = UNNotificationRequest(
            identifier: "gensee-daily-\(day)",
            content: content,
            trigger: nil
        )
        try? await center.add(request)
        defaults.set(day, forKey: Self.lastDailyBriefingKey)
    }

    private func persistNotifiedRequests() {
        let recent = notifiedRequestIDs.sorted(by: >).prefix(500)
        notifiedRequestIDs = Set(recent)
        defaults.set(Array(recent), forKey: Self.notifiedRequestsKey)
    }

    private func persistNotifiedAlerts() {
        let recent = notifiedAlertIDs.sorted(by: >).prefix(2_000)
        notifiedAlertIDs = Set(recent)
        defaults.set(Array(recent), forKey: Self.notifiedAlertsKey)
    }

    private static let completionEnabledKey = "gensee.notifications.completions.enabled"
    private static let dailyEnabledKey = "gensee.notifications.daily.enabled"
    private static let alertEnabledKey = "gensee.notifications.alerts.enabled"
    private static let minimumAlertSeverityKey = "gensee.notifications.alerts.minimum-severity"
    // v2 intentionally leaves behind the old key, which contained every clean
    // completion and could suppress a later needs-you transition forever.
    private static let notifiedRequestsKey = "gensee.notifications.actionable-request-ids.v2"
    private static let notifiedAlertsKey = "gensee.notifications.alert-ids"
    private static let lastDailyBriefingKey = "gensee.notifications.last-daily-briefing"
    private static let agentReviewCategoryIdentifier = "gensee.agent-review"
    private static let openReviewActionIdentifier = "gensee.open-review"
    private static let dayFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.calendar = .current
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter
    }()
}

extension CompletionNotificationCoordinator: UNUserNotificationCenterDelegate {
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        Task { @MainActor in
            let requestID: Int64? = {
                let value = response.notification.request.content.userInfo["request_id"]
                if let number = value as? NSNumber { return number.int64Value }
                if let string = value as? String { return Int64(string) }
                return nil
            }()
            if let requestID {
                NotificationCenter.default.post(
                    name: .genseeOpenAgentReview,
                    object: nil,
                    userInfo: ["request_id": requestID]
                )
            }
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first(where: { $0.title == "Gensee Crate" })?.makeKeyAndOrderFront(nil)
            completionHandler()
        }
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list, .sound])
    }
}

extension Notification.Name {
    static let genseeOpenAgentReview = Notification.Name("ai.gensee.crate.open-agent-review")
}

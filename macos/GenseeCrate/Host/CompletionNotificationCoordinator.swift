import AppKit
import Foundation
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
    private var hasSeededCurrentStore = false
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
    }

    var isAuthorized: Bool {
        authorizationStatus == .authorized || authorizationStatus == .provisional
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

        if completionNotificationsEnabled, isAuthorized {
            for summary in summaries.reversed()
            where summary.isLargeTask && !notifiedRequestIDs.contains(summary.requestID) {
                await sendCompletion(summary)
            }
        }
        if alertNotificationsEnabled, isAuthorized {
            let newAlerts = snapshot.alerts.filter {
                !notifiedAlertIDs.contains($0.alertID) && minimumAlertSeverity.includes($0.severity)
            }
            if !newAlerts.isEmpty {
                await sendAlertDigest(newAlerts)
            }
        }
        notifiedRequestIDs.formUnion(summaries.map(\.requestID))
        notifiedAlertIDs.formUnion(snapshot.alerts.map(\.alertID))
        persistNotifiedRequests()
        persistNotifiedAlerts()
        await sendDailyBriefingIfNeeded(snapshot: snapshot, now: now)
    }

    private func sendCompletion(_ summary: AgentCompletionSummary) async {
        let content = UNMutableNotificationContent()
        content.title = "\(summary.harness) task ready for review"
        content.subtitle = summary.reviewState.title
        content.body = AgentCompletionDerivation.notificationBody(for: summary)
        content.sound = summary.reviewState == .attention ? .default : nil
        content.userInfo = ["request_id": summary.requestID]
        let request = UNNotificationRequest(
            identifier: "gensee-completion-\(summary.requestID)",
            content: content,
            trigger: nil
        )
        try? await center.add(request)
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
    private static let notifiedRequestsKey = "gensee.notifications.completed-request-ids"
    private static let notifiedAlertsKey = "gensee.notifications.alert-ids"
    private static let lastDailyBriefingKey = "gensee.notifications.last-daily-briefing"
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
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first?.makeKeyAndOrderFront(nil)
            completionHandler()
        }
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner])
    }
}

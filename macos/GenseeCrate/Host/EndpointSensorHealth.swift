import Foundation

struct EndpointSensorHealth: Equatable {
    var bootID = ""
    var connected = false
    var running = false
    var mode = "observe"
    var configuredMode: String?
    var receivedMessages: UInt64 = 0
    var maxCallbackLatencyUS: UInt64 = 0
    var pendingEvidence: UInt64 = 0
    var maxPendingEvidence: UInt64 = 0
    var maxQueueDelayUS: UInt64 = 0
    var totalEvents: UInt64 = 0
    var bufferedEvents: UInt64 = 0
    var backlogEvents: UInt64 = 0
    var kernelDrops: UInt64 = 0
    var ringDrops: UInt64 = 0
    var lastGlobalSequence: UInt64 = 0
    var ingestedEvents: UInt64 = 0
    var persistedEvents: UInt64 = 0
    var suppressedEvents: UInt64 = 0
    var prunedSystemEvents: UInt64 = 0
    var prunedLowSeverityAlerts: UInt64 = 0
    var lastBatchDurationMS: UInt64 = 0
    var rejectedEvents: UInt64 = 0
    var authorizationCount: UInt64 = 0
    var deniedCount: UInt64 = 0
    var maxAuthorizationLatencyUS: UInt64 = 0
    var configuredMaxAuthorizationLatencyUS: UInt64 = 10_000
    var managedProcesses: UInt64 = 0
    var lastEventAt: Date?
    var lastSuccessfulPollAt: SuspendingClock.Instant?
    var error: String?
    var configurationWarning: String?
    var ingestionWarning: String?
    var launchContinuityIssue: EndpointEvidenceContinuityIssue?

    // Availability describes the sensor, while warnings describe degraded
    // configuration or evidence. Neither warning implies a transport outage.
    var isAvailable: Bool { connected && running }
    var needsAttention: Bool {
        !isAvailable || error != nil || configurationWarning != nil ||
            ingestionWarning != nil || hasDataLoss || hasBackpressure
    }

    var hasDataLoss: Bool {
        kernelDrops > 0 || ringDrops > 0 || rejectedEvents > 0 || launchContinuityIssue != nil
    }
    var hasBackpressure: Bool { backlogEvents >= 1_000 || pendingEvidence >= 1_000 || lastBatchDurationMS >= 1_000 }
    var exceedsAuthorizationLatencyBudget: Bool {
        maxAuthorizationLatencyUS > configuredMaxAuthorizationLatencyUS
    }
}

enum MonitoringHealthIncident: Equatable {
    case events(UInt64), unavailable, stalled
}

// SuspendingClock is monotonic and excludes system sleep. Wall-clock changes
// cannot extend cooldowns. Counters survive pauses; outage timers get wake grace.
struct MonitoringGapAlarmTracker {
    private enum OutageKind: Hashable { case unavailable, stalled }
    private var previous: EndpointSensorHealth?
    private var pending: UInt64 = 0
    private var dismissedLossBootID: String?
    private var lossQuietSince: SuspendingClock.Instant?
    private var lastAlarm: SuspendingClock.Instant?
    private var unavailableSince: SuspendingClock.Instant?
    private var healthySince: SuspendingClock.Instant?
    private var restoredOutageBanner = false
    private var displayedOutageKind: OutageKind?
    private var eventLossBanner: MonitoringHealthIncident?
    private var interruptions: [SuspendingClock.Instant] = []
    private var alarmedKinds: Set<OutageKind> = []
    private var graceUntil: SuspendingClock.Instant?
    private(set) var bannerIncident: MonitoringHealthIncident?
    private(set) var bannerRevision: UInt64 = 0

    private mutating func resetOutageWindow() {
        unavailableSince = nil
        healthySince = nil
        interruptions.removeAll()
    }

    private mutating func setBanner(_ incident: MonitoringHealthIncident?, newIncident: Bool = false) {
        if bannerIncident != incident || newIncident { bannerRevision &+= 1 }
        bannerIncident = incident
    }

    mutating func dismissBanner() {
        if case .events = bannerIncident {
            // Acknowledge the entire observed episode, including loss counts
            // waiting for the notification cooldown. Continued loss remains in
            // sensor health; only a new episode should interrupt again.
            pending = 0
            dismissedLossBootID = previous?.bootID
            lossQuietSince = nil
            eventLossBanner = nil
            setBanner(nil)
        } else {
            // Dismiss the visible outage only; an undisclosed history gap
            // remains independently actionable and becomes visible underneath.
            setBanner(eventLossBanner)
        }
    }

    private mutating func clearOutageBanner() {
        if bannerIncident == .unavailable || bannerIncident == .stalled {
            setBanner(eventLossBanner)
        }
    }

    mutating func resumeAfterSleep(now: SuspendingClock.Instant) {
        resetOutageWindow()
        graceUntil = now.advanced(by: .seconds(30))
    }

    mutating func observe(_ health: EndpointSensorHealth, now: SuspendingClock.Instant) -> MonitoringHealthIncident? {
        // Only an intentional host configuration can silence monitoring. A
        // stale/off report from the extension cannot disable its own alarm.
        guard let configuredMode = health.configuredMode, configuredMode != "off" else {
            resetOutageWindow()
            lossQuietSince = nil
            alarmedKinds.removeAll()
            clearOutageBanner()
            return nil
        }
        if let graceUntil {
            if now < graceUntil { return nil }
            self.graceUntil = nil
        }
        let stale = health.lastSuccessfulPollAt.map { $0.duration(to: now) >= .seconds(15) } ?? false
        let unavailable = !health.connected || !health.running || health.mode == "off"
        if unavailable || stale {
            lossQuietSince = nil
            healthySince = nil
            interruptions.removeAll { $0.duration(to: now) > .seconds(60) }
            let newOutage = unavailableSince == nil
            if newOutage {
                unavailableSince = now
                interruptions.append(now)
                restoredOutageBanner = false
                displayedOutageKind = nil
            }
            let kind: OutageKind = unavailable ? .unavailable : .stalled
            let incident: MonitoringHealthIncident = unavailable ? .unavailable : .stalled
            if unavailableSince!.duration(to: now) >= .seconds(10) || interruptions.count >= 3 {
                // A re-outage also gets grace before restoring a dismissed
                // banner. Native notifications remain latched until recovery.
                if !restoredOutageBanner || displayedOutageKind != kind {
                    setBanner(incident, newIncident: true)
                    restoredOutageBanner = true
                    displayedOutageKind = kind
                }
                if alarmedKinds.insert(kind).inserted { return incident }
            }
            return nil
        }
        unavailableSince = nil
        if healthySince == nil { healthySince = now }
        if healthySince!.duration(to: now) >= .seconds(30) {
            alarmedKinds.removeAll()
            resetOutageWindow()
            healthySince = now
            // Recovery restores availability, not the missing event history.
            clearOutageBanner()
        }
        defer { previous = health }
        guard let previous, previous.bootID == health.bootID,
              health.kernelDrops >= previous.kernelDrops, health.ringDrops >= previous.ringDrops else {
            self.pending = 0
            dismissedLossBootID = nil
            lossQuietSince = nil
            return nil
        }
        let newLoss = health.kernelDrops - previous.kernelDrops + health.ringDrops - previous.ringDrops
        if dismissedLossBootID == health.bootID {
            // Require a full minute of healthy, loss-free polling before a
            // later loss can be a new episode. Outages interrupt this window.
            if let quietSince = lossQuietSince, quietSince.duration(to: now) >= .seconds(60) {
                dismissedLossBootID = nil
                lossQuietSince = nil
            } else {
                if newLoss > 0 { lossQuietSince = nil }
                else if lossQuietSince == nil { lossQuietSince = now }
                return nil
            }
        }
        pending += newLoss
        guard pending >= 100, lastAlarm.map({ $0.duration(to: now) >= .seconds(60) }) ?? true else { return nil }
        let count = pending
        pending = 0; lastAlarm = now
        let previousLoss: UInt64
        if case .events(let existing) = eventLossBanner { previousLoss = existing } else { previousLoss = 0 }
        eventLossBanner = .events(previousLoss + count)
        if bannerIncident != .unavailable && bannerIncident != .stalled {
            setBanner(eventLossBanner, newIncident: true)
        }
        return .events(count)
    }
}

/// Transport identity is independent of the last displayed health sample.
/// Late callbacks from replaced XPC connections cannot invalidate their successor.
struct EndpointConnectionRecovery {
    private(set) var generation: UInt64 = 0
    private(set) var needsConnection = true

    mutating func installed() -> UInt64 {
        generation &+= 1
        needsConnection = false
        return generation
    }

    @discardableResult
    mutating func failed(generation: UInt64) -> Bool {
        guard generation == self.generation else { return false }
        needsConnection = true
        return true
    }
}

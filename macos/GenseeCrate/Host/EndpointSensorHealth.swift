import Foundation

struct EndpointSensorHealth: Equatable {
    var bootID = ""
    var connected = false
    var running = false
    var mode = "observe"
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

// Runtime deltas only: restarting the app must not alarm on historical counters.
struct MonitoringGapAlarmTracker {
    private var previous: EndpointSensorHealth?
    private var pending: UInt64 = 0
    private var lastAlarm: Date?
    mutating func observe(_ health: EndpointSensorHealth, now: Date) -> UInt64? {
        guard health.connected, health.running else { return nil }
        defer { previous = health }
        guard let previous, previous.bootID == health.bootID,
              health.kernelDrops >= previous.kernelDrops, health.ringDrops >= previous.ringDrops else {
            pending = 0; lastAlarm = nil
            return nil
        }
        pending += health.kernelDrops - previous.kernelDrops
        pending += health.ringDrops - previous.ringDrops
        guard pending >= 100, lastAlarm.map({ now.timeIntervalSince($0) >= 60 }) ?? true else { return nil }
        let count = pending
        pending = 0; lastAlarm = now
        return count
    }
}

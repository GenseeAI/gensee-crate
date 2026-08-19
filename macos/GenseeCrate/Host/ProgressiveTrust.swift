import Foundation
import SwiftUI

enum ProtectionLevel: String, CaseIterable, Identifiable {
    case observe
    case guarded
    case unattended

    var id: String { rawValue }

    var title: String {
        switch self {
        case .observe: "Observe"
        case .guarded: "Guarded"
        case .unattended: "Unattended"
        }
    }

    var tagline: String {
        switch self {
        case .observe: "See what agents do before adding OS enforcement."
        case .guarded: "Stop configured high-confidence risks; keep asks interactive."
        case .unattended: "Fail closed instead of waiting for you to approve an ask."
        }
    }

    var detail: String {
        switch self {
        case .observe:
            "Endpoint Security records managed-agent activity but does not deny it. Harness hooks still apply the decision rules in your policy, including any existing ask or block actions."
        case .guarded:
            "Endpoint Security authorizes configured protected paths and executables. Ambiguous hook decisions can still ask you before the harness continues."
        case .unattended:
            "Strict OS protection is enabled and medium-or-higher ask decisions become deny. This removes approval waits by stopping the risky operation instead."
        }
    }

    var endpointMode: String {
        switch self {
        case .observe: "observe"
        case .guarded: "protect"
        case .unattended: "strict"
        }
    }

    var noninteractive: Bool { self == .unattended }

    var symbol: String {
        switch self {
        case .observe: "eye"
        case .guarded: "shield"
        case .unattended: "bolt.shield"
        }
    }

    var tint: Color {
        switch self {
        case .observe: .blue
        case .guarded: .green
        case .unattended: .red
        }
    }

    static func current(endpointMode: String, noninteractive: Bool) -> ProtectionLevel? {
        switch (endpointMode, noninteractive) {
        case ("observe", false): .observe
        case ("protect", false): .guarded
        case ("strict", true): .unattended
        default: nil
        }
    }
}

enum DemoSnapshotFactory {
    static func make(now: Date = Date()) -> SecuritySnapshot {
        let nowMS = Int64(now.timeIntervalSince1970 * 1_000)
        let minute: Int64 = 60_000
        let sessionOne = "demo-codex-checkout"
        let sessionTwo = "demo-claude-tests"

        var snapshot = SecuritySnapshot()
        var summary = DashboardSummary()
        summary.sessionsCount = 2
        summary.requestsCount = 3
        summary.agentEventsCount = 12
        summary.alertsCount = 2
        summary.recentHighAlerts = 1
        summary.artifactsCount = 4
        summary.highAlertsCount = 1
        summary.mediumAlertsCount = 1
        snapshot.summary = summary

        snapshot.sessions = [
            RecordedSession(
                sessionID: sessionOne,
                agentID: "codex",
                firstEventAt: nowMS - 38 * minute,
                lastEventAt: nowMS - 24 * minute,
                flagged: 1,
                requestCount: 2,
                eventCount: 8
            ),
            RecordedSession(
                sessionID: sessionTwo,
                agentID: "claude-code",
                firstEventAt: nowMS - 82 * minute,
                lastEventAt: nowMS - 71 * minute,
                flagged: 0,
                requestCount: 1,
                eventCount: 4
            ),
        ]
        snapshot.requests = [
            RecordedRequest(
                requestID: 9003,
                sessionID: sessionOne,
                originalUserPrompt: "Add validation to checkout and run the focused tests.",
                finalResponse: nil,
                createdAt: nowMS - 38 * minute,
                completedAt: nowMS - 24 * minute
            ),
            RecordedRequest(
                requestID: 9002,
                sessionID: sessionOne,
                originalUserPrompt: "Trace the flaky retry path without changing production code.",
                finalResponse: nil,
                createdAt: nowMS - 58 * minute,
                completedAt: nowMS - 49 * minute
            ),
            RecordedRequest(
                requestID: 9001,
                sessionID: sessionTwo,
                originalUserPrompt: "Refactor the parser and keep its behavior covered by tests.",
                finalResponse: nil,
                createdAt: nowMS - 82 * minute,
                completedAt: nowMS - 71 * minute
            ),
        ]

        snapshot.agentEvents = [
            event(1, request: 9003, session: sessionOne, at: nowMS - 37 * minute, type: "PreToolUse", tool: "Read", input: #"{"file_path":"/Users/demo/Shop/Sources/Checkout.swift"}"#, use: "demo-read"),
            event(2, request: 9003, session: sessionOne, at: nowMS - 36 * minute, type: "PostToolUse", tool: "Read", response: #"{"duration_ms":420}"#, use: "demo-read"),
            event(3, request: 9003, session: sessionOne, at: nowMS - 34 * minute, type: "PreToolUse", tool: "Edit", input: #"{"file_path":"/Users/demo/Shop/Sources/Checkout.swift"}"#, use: "demo-edit"),
            event(4, request: 9003, session: sessionOne, at: nowMS - 31 * minute, type: "PostToolUse", tool: "Edit", response: #"{"duration_ms":126000}"#, use: "demo-edit"),
            event(5, request: 9003, session: sessionOne, at: nowMS - 29 * minute, type: "PreToolUse", tool: "Bash", input: #"{"command":"swift test --filter CheckoutTests"}"#, use: "demo-test"),
            event(6, request: 9003, session: sessionOne, at: nowMS - 24 * minute, type: "PostToolUse", tool: "Bash", response: #"{"duration_ms":287000}"#, use: "demo-test"),
            event(7, request: 9002, session: sessionOne, at: nowMS - 57 * minute, type: "PreToolUse", tool: "Search", input: #"{"query":"retry checkout"}"#, use: "demo-search"),
            event(8, request: 9002, session: sessionOne, at: nowMS - 55 * minute, type: "PostToolUse", tool: "Search", response: #"{"duration_ms":910}"#, use: "demo-search"),
            event(9, request: 9001, session: sessionTwo, at: nowMS - 81 * minute, type: "PreToolUse", tool: "Edit", input: #"{"file_path":"/Users/demo/Parser/Sources/Parser.swift"}"#, use: "demo-parser"),
            event(10, request: 9001, session: sessionTwo, at: nowMS - 77 * minute, type: "PostToolUse", tool: "Edit", response: #"{"duration_ms":191000}"#, use: "demo-parser"),
            event(11, request: 9001, session: sessionTwo, at: nowMS - 76 * minute, type: "PreToolUse", tool: "Bash", input: #"{"command":"swift test --filter ParserTests"}"#, use: "demo-parser-test"),
            event(12, request: 9001, session: sessionTwo, at: nowMS - 71 * minute, type: "PostToolUse", tool: "Bash", response: #"{"duration_ms":302000}"#, use: "demo-parser-test"),
        ]

        snapshot.alerts = [
            alert(
                id: 7002,
                request: 9003,
                session: sessionOne,
                severity: "high",
                action: "block",
                rule: "secret_path_read",
                message: "Prevented an attempted read outside the project",
                path: "/Users/demo/.ssh/id_ed25519",
                at: nowMS - 35 * minute,
                prompt: "Add validation to checkout and run the focused tests.",
                tool: "Read",
                input: #"{"file_path":"/Users/demo/.ssh/id_ed25519"}"#,
                use: "demo-secret"
            ),
            alert(
                id: 7001,
                request: 9001,
                session: sessionTwo,
                severity: "medium",
                action: "warn",
                rule: "persistence_write",
                message: "Agent proposed changing a persistent editor task",
                path: "/Users/demo/Parser/.vscode/tasks.json",
                at: nowMS - 79 * minute,
                prompt: "Refactor the parser and keep its behavior covered by tests.",
                tool: "Edit",
                input: #"{"file_path":"/Users/demo/Parser/.vscode/tasks.json"}"#,
                use: "demo-task"
            ),
        ]

        snapshot.artifacts = [
            artifact("/Users/demo/Shop/Sources/Checkout.swift", at: nowMS - 24 * minute, source: "codex", risk: nil),
            artifact("/Users/demo/Shop/Tests/CheckoutTests.swift", at: nowMS - 24 * minute, source: "codex", risk: nil),
            artifact("/Users/demo/Parser/Sources/Parser.swift", at: nowMS - 71 * minute, source: "claude-code", risk: nil),
            artifact("/Users/demo/.ssh/id_ed25519", at: nowMS - 35 * minute, source: "codex", risk: "high"),
        ]
        snapshot.relations = [
            ArtifactEdge(type: "modified_with", confidence: 0.98, sourceURI: "file:///Users/demo/Shop/Sources/Checkout.swift", destinationURI: "file:///Users/demo/Shop/Tests/CheckoutTests.swift"),
            ArtifactEdge(type: "attempted_read", confidence: 1, sourceURI: "file:///Users/demo/Shop/Sources/Checkout.swift", destinationURI: "file:///Users/demo/.ssh/id_ed25519"),
        ]
        snapshot.dailyActivity = dailyActivity(now: now)
        return snapshot
    }

    static func dailyDetail(for day: String, snapshot: SecuritySnapshot) -> DailyDetail? {
        guard let activity = snapshot.dailyActivity.first(where: { $0.date == day }) else { return nil }
        return DailyDetail(
            date: day,
            sessions: activity.requests == 0 ? 0 : max(1, activity.requests / 2),
            requests: activity.requests,
            toolCalls: activity.toolCalls,
            alerts: activity.alerts,
            tokens: activity.tokens,
            filesWritten: max(0, activity.toolCalls / 4),
            filesRead: max(0, activity.toolCalls / 2),
            webRequests: max(0, activity.toolCalls / 8),
            topTools: [DailyCount(name: "Read", count: max(1, activity.toolCalls / 3)), DailyCount(name: "Bash", count: max(1, activity.toolCalls / 4))],
            alertsByAction: [DailyCount(name: "block", count: activity.alerts > 0 ? 1 : 0)],
            alertsBySeverity: [DailyCount(name: "high", count: activity.alerts > 0 ? 1 : 0)]
        )
    }

    private static func event(
        _ id: Int64,
        request: Int64,
        session: String,
        at timestamp: Int64,
        type: String,
        tool: String,
        input: String? = nil,
        response: String? = nil,
        use: String
    ) -> AgentEvent {
        AgentEvent(eventID: id, pid: 4242, requestID: request, timestamp: timestamp, source: "synthetic-demo", type: type, cwd: "/Users/demo/Projects", toolName: tool, sessionID: session, permissionMode: "demo", toolInput: input, toolResponse: response, durationMS: nil, toolUseID: use)
    }

    private static func alert(
        id: Int64,
        request: Int64,
        session: String,
        severity: String,
        action: String,
        rule: String,
        message: String,
        path: String,
        at timestamp: Int64,
        prompt: String,
        tool: String,
        input: String,
        use: String
    ) -> SecurityAlert {
        SecurityAlert(alertID: id, requestID: request, sessionID: session, severity: severity, action: action, ruleID: rule, message: message, path: path, evidence: #"{"source":"synthetic-demo"}"#, createdAt: timestamp, originalUserPrompt: prompt, eventSource: "synthetic-demo", eventType: "PreToolUse", toolName: tool, toolInput: input, toolUseID: use, humanVerdict: nil, feedbackLabel: nil, feedbackCreatedAt: nil)
    }

    private static func artifact(_ path: String, at timestamp: Int64, source: String, risk: String?) -> ArtifactFact {
        ArtifactFact(kind: "file", uri: URL(fileURLWithPath: path).absoluteString, currentDigest: nil, lastSeenAt: timestamp, lastModifiedAt: timestamp, lastModifiedSource: source, lastModifiedSessionID: nil, riskLevel: risk, riskRuleID: risk == nil ? nil : "secret_path_read", isAgentAuthored: risk == nil ? 1 : 0, isUnmatchedModified: 0, isMemoryArtifact: 0, isPersistentTarget: 0, isControlPlane: 0)
    }

    private static func dailyActivity(now: Date) -> [DailyActivity] {
        let calendar = Calendar.current
        let formatter = DateFormatter()
        formatter.calendar = calendar
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return (0..<84).compactMap { offset in
            guard let date = calendar.date(byAdding: .day, value: -offset, to: now) else { return nil }
            let weekday = calendar.component(.weekday, from: date)
            let active = ![1, 7].contains(weekday) || offset % 3 == 0
            let requests = active ? 1 + (offset * 7) % 9 : 0
            let tools = requests == 0 ? 0 : requests * (3 + offset % 4)
            let alerts = tools == 0 ? 0 : (offset % 11 == 0 ? 2 : offset % 5 == 0 ? 1 : 0)
            return DailyActivity(date: formatter.string(from: date), requests: requests, toolCalls: tools, alerts: alerts, tokens: tools * (420 + (offset % 5) * 85))
        }
    }
}

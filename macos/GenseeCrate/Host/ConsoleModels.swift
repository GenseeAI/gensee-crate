import Foundation

enum AlertReadState {
    static func storeWasReset(alertCount: Int, readAlertBaselineCount: Int) -> Bool {
        alertCount < readAlertBaselineCount
    }
}

struct SecuritySnapshot: Decodable {
    var summary = DashboardSummary()
    var alerts: [SecurityAlert] = []
    var agentEvents: [AgentEvent] = []
    var systemEvents: [SystemEvent] = []
    var sessions: [RecordedSession] = []
    var requests: [RecordedRequest] = []
    var artifacts: [ArtifactFact] = []
    var relations: [ArtifactEdge] = []
    var humanFeedback: [HumanFeedback] = []
    var workspaceEffects: [WorkspaceEffect] = []
    var jsonSessions: [AgentSessionRecord] = []
    var dailyActivity: [DailyActivity] = []

    enum CodingKeys: String, CodingKey {
        case summary, alerts, agentEvents, systemEvents, sessions, requests, artifacts
        case relations, humanFeedback, workspaceEffects, jsonSessions, dailyActivity
    }

    init() {}

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        summary = try values.decodeIfPresent(DashboardSummary.self, forKey: .summary) ?? DashboardSummary()
        alerts = try values.decodeIfPresent([SecurityAlert].self, forKey: .alerts) ?? []
        agentEvents = try values.decodeIfPresent([AgentEvent].self, forKey: .agentEvents) ?? []
        systemEvents = try values.decodeIfPresent([SystemEvent].self, forKey: .systemEvents) ?? []
        sessions = try values.decodeIfPresent([RecordedSession].self, forKey: .sessions) ?? []
        requests = try values.decodeIfPresent([RecordedRequest].self, forKey: .requests) ?? []
        artifacts = try values.decodeIfPresent([ArtifactFact].self, forKey: .artifacts) ?? []
        relations = try values.decodeIfPresent([ArtifactEdge].self, forKey: .relations) ?? []
        humanFeedback = try values.decodeIfPresent([HumanFeedback].self, forKey: .humanFeedback) ?? []
        workspaceEffects = try values.decodeIfPresent([WorkspaceEffect].self, forKey: .workspaceEffects) ?? []
        jsonSessions = try values.decodeIfPresent([AgentSessionRecord].self, forKey: .jsonSessions) ?? []
        dailyActivity = try values.decodeIfPresent([DailyActivity].self, forKey: .dailyActivity) ?? []
    }
}

struct DailyActivity: Decodable, Identifiable {
    let date: String
    let requests: Int
    let toolCalls: Int
    let alerts: Int
    let tokens: Int

    var id: String { date }

    enum CodingKeys: String, CodingKey {
        case date, requests, alerts, tokens
        case toolCalls = "tool_calls"
    }
}

struct DailyDetail: Decodable {
    let date: String
    let sessions: Int
    let requests: Int
    let toolCalls: Int
    let alerts: Int
    let tokens: Int
    let filesWritten: Int
    let filesRead: Int
    let webRequests: Int
    let topTools: [DailyCount]
    let alertsByAction: [DailyCount]
    let alertsBySeverity: [DailyCount]

    enum CodingKeys: String, CodingKey {
        case date, sessions, requests, alerts, tokens
        case toolCalls = "tool_calls"
        case filesWritten = "files_written"
        case filesRead = "files_read"
        case webRequests = "web_requests"
        case topTools = "top_tools"
        case alertsByAction = "alerts_by_action"
        case alertsBySeverity = "alerts_by_severity"
    }
}

enum DailyDetailLoadState: Equatable {
    case idle
    case loading(String)
    case loaded(String)
    case unavailable(day: String, message: String)
}

struct DailyCount: Decodable, Identifiable {
    let name: String
    let count: Int
    var id: String { name }
}

struct AgentSessionRecord: Decodable, Identifiable {
    let sessionID: String
    let rootPID: UInt32
    let agentBinary: String
    let mode: String?
    let endedAtMS: UInt64?

    var id: String { sessionID }
    var isActive: Bool { endedAtMS == nil }

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case rootPID = "root_pid"
        case agentBinary = "agent_binary"
        case mode
        case endedAtMS = "ended_at_ms"
    }
}

enum EndpointSessionScope {
    static func isEnabled(
        _ session: AgentSessionRecord,
        enabledHarnesses: Set<String>
    ) -> Bool {
        guard session.mode == "hook" else { return true }
        guard let provider = harnessProvider(agentBinary: session.agentBinary) else {
            return false
        }
        return enabledHarnesses.contains(provider)
    }

    static func harnessProvider(agentBinary: String) -> String? {
        let lower = agentBinary.lowercased()
        let name = URL(fileURLWithPath: lower).lastPathComponent
        if name == "codex" || lower.contains("/codex.app/contents/macos/codex") {
            return "codex"
        }
        if name == "claude" || name == "claude-code" || lower.contains("/claude.app/") {
            return "claude-code"
        }
        if name == "antigravity" || name == "gemini" || lower.contains("/antigravity.app/") {
            return "antigravity"
        }
        if name == "cursor" || lower.contains("/cursor.app/") {
            return "cursor"
        }
        if name == "code" || name == "code-insiders" || lower.contains("visual studio code") {
            return "vscode"
        }
        if name == "omnigent" {
            return "omnigent"
        }
        return nil
    }
}

struct DashboardSummary: Decodable {
    var sessionsCount: Int = 0
    var requestsCount: Int = 0
    var agentEventsCount: Int = 0
    var systemEventsCount: Int = 0
    var alertsCount: Int = 0
    var recentHighAlerts: Int = 0
    var artifactsCount: Int = 0

    enum CodingKeys: String, CodingKey {
        case sessionsCount = "sessions_count"
        case requestsCount = "requests_count"
        case agentEventsCount = "agent_events_count"
        case systemEventsCount = "system_events_count"
        case alertsCount = "alerts_count"
        case recentHighAlerts = "recent_high_alerts"
        case artifactsCount = "artifacts_count"
    }
}

struct SecurityAlert: Decodable, Identifiable {
    let alertID: Int64
    let requestID: Int64?
    let sessionID: String?
    let severity: String
    let action: String
    let ruleID: String
    let message: String
    let path: String?
    let evidence: String?
    let createdAt: Int64
    let originalUserPrompt: String?
    let eventSource: String?
    let eventType: String?
    let toolName: String?
    let toolInput: String?
    let toolUseID: String?
    let humanVerdict: String?
    let feedbackLabel: String?
    let feedbackCreatedAt: Int64?

    var id: Int64 { alertID }

    enum CodingKeys: String, CodingKey {
        case alertID = "alert_id"
        case requestID = "request_id"
        case sessionID = "session_id"
        case severity, action
        case ruleID = "rule_id"
        case message, path, evidence
        case createdAt = "created_at"
        case originalUserPrompt = "original_user_prompt"
        case eventSource = "event_source"
        case eventType = "event_type"
        case toolName = "tool_name"
        case toolInput = "tool_input"
        case toolUseID = "tool_use_id"
        case humanVerdict = "human_verdict"
        case feedbackLabel = "feedback_label"
        case feedbackCreatedAt = "feedback_created_at"
    }
}

struct AgentEvent: Decodable, Identifiable {
    let eventID: Int64
    let pid: Int64
    let requestID: Int64
    let timestamp: Int64
    let source: String
    let type: String
    let cwd: String
    let toolName: String?
    let sessionID: String?
    let permissionMode: String?
    let toolInput: String?
    let toolResponse: String?
    let durationMS: Int64?
    let toolUseID: String?

    var id: String { "agent-\(eventID)" }

    enum CodingKeys: String, CodingKey {
        case eventID = "event_id"
        case pid
        case requestID = "request_id"
        case timestamp = "ts"
        case source, type, cwd
        case toolName = "tool_name"
        case sessionID = "session_id"
        case permissionMode = "permission_mode"
        case toolInput = "tool_input"
        case toolResponse = "tool_response"
        case durationMS = "duration_ms"
        case toolUseID = "tool_use_id"
    }
}

struct SystemEvent: Decodable, Identifiable {
    let eventID: Int64
    let pid: Int64
    let requestID: Int64
    let timestamp: Int64
    let source: String
    let type: String
    let cwd: String
    let args: String?

    var id: String { "system-\(eventID)" }

    enum CodingKeys: String, CodingKey {
        case eventID = "event_id"
        case pid
        case requestID = "request_id"
        case timestamp = "ts"
        case source, type, cwd, args
    }
}

struct RecordedSession: Decodable, Identifiable {
    let sessionID: String
    let agentID: String
    let firstEventAt: Int64
    let lastEventAt: Int64?
    let flagged: Int
    let requestCount: Int?
    let eventCount: Int?

    var id: String { sessionID }

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case agentID = "agent_id"
        case firstEventAt = "first_event_at"
        case lastEventAt = "last_event_at"
        case flagged
        case requestCount = "req_count"
        case eventCount = "event_count"
    }
}

struct RecordedRequest: Decodable, Identifiable {
    let requestID: Int64
    let sessionID: String
    let originalUserPrompt: String?
    let finalResponse: String?
    let createdAt: Int64?
    let completedAt: Int64?

    var id: Int64 { requestID }

    enum CodingKeys: String, CodingKey {
        case requestID = "request_id"
        case sessionID = "session_id"
        case originalUserPrompt = "original_user_prompt"
        case finalResponse = "final_response"
        case createdAt = "created_at"
        case completedAt = "completed_at"
    }
}

struct ArtifactFact: Decodable, Identifiable {
    let kind: String
    let uri: String
    let currentDigest: String?
    let lastSeenAt: Int64
    let lastModifiedAt: Int64?
    let lastModifiedSource: String?
    let lastModifiedSessionID: String?
    let riskLevel: String?
    let riskRuleID: String?
    let isAgentAuthored: Int
    let isUnmatchedModified: Int
    let isMemoryArtifact: Int
    let isPersistentTarget: Int
    let isControlPlane: Int

    var id: String { "\(kind):\(uri)" }

    var filePath: String {
        guard let url = URL(string: uri), url.isFileURL else { return uri }
        return url.path
    }

    var displayName: String {
        let name = URL(fileURLWithPath: filePath).lastPathComponent
        return name.isEmpty ? filePath : name
    }

    var isSensitive: Bool {
        if riskLevel != nil || isMemoryArtifact != 0 || isControlPlane != 0 || isPersistentTarget != 0 {
            return true
        }

        let normalized = filePath.lowercased()
        let protectedDirectories = [
            "/.ssh/", "/.aws/", "/.gnupg/", "/.kube/", "/.docker/",
            "/.config/gcloud/", "/.config/gh/", "/library/keychains/",
        ]
        if protectedDirectories.contains(where: normalized.contains) {
            return true
        }

        let protectedFiles = [".netrc", ".npmrc", ".pypirc"]
        return protectedFiles.contains(URL(fileURLWithPath: normalized).lastPathComponent)
    }

    enum CodingKeys: String, CodingKey {
        case kind, uri
        case currentDigest = "current_digest"
        case lastSeenAt = "last_seen_at"
        case lastModifiedAt = "last_modified_at"
        case lastModifiedSource = "last_modified_source"
        case lastModifiedSessionID = "last_modified_session_id"
        case riskLevel = "risk_level"
        case riskRuleID = "risk_rule_id"
        case isAgentAuthored = "is_agent_authored"
        case isUnmatchedModified = "is_unmatched_modified"
        case isMemoryArtifact = "is_memory_artifact"
        case isPersistentTarget = "is_persistent_target"
        case isControlPlane = "is_control_plane"
    }
}

struct ArtifactEdge: Decodable, Identifiable {
    let type: String
    let confidence: Double
    let sourceURI: String
    let destinationURI: String

    var id: String { "\(sourceURI)|\(type)|\(destinationURI)" }

    enum CodingKeys: String, CodingKey {
        case type, confidence
        case sourceURI = "src_uri"
        case destinationURI = "dst_uri"
    }
}

struct HumanFeedback: Decodable, Identifiable {
    let eventKey: String?
    let toolUseID: String?
    let sessionID: String?
    let genseeAction: String?
    let humanVerdict: String
    let label: String?
    let ruleID: String?
    let path: String?
    let note: String?
    let createdAt: Int64

    var id: String { "\(createdAt)-\(eventKey ?? toolUseID ?? sessionID ?? humanVerdict)" }

    enum CodingKeys: String, CodingKey {
        case eventKey = "event_key"
        case toolUseID = "tool_use_id"
        case sessionID = "session_id"
        case genseeAction = "gensee_action"
        case humanVerdict = "human_verdict"
        case label
        case ruleID = "rule_id"
        case path, note
        case createdAt = "created_at"
    }
}

struct WorkspaceEffect: Decodable, Identifiable {
    let source: String
    let sessionID: String?
    let workspace: String
    let path: String
    let effectType: String
    let observedAtMS: UInt64
    let attribution: String
    let confidence: String

    var id: String { "\(observedAtMS)-\(path)-\(effectType)" }

    enum CodingKeys: String, CodingKey {
        case source
        case sessionID = "session_id"
        case workspace, path
        case effectType = "effect_type"
        case observedAtMS = "observed_at_ms"
        case attribution, confidence
    }
}

struct RunListResponse: Decodable {
    var sessions: [AgentRun] = []
    var tcloneRuns: [TransactionalRun] = []

    enum CodingKeys: String, CodingKey {
        case sessions
        case tcloneRuns = "tclone_runs"
    }
}

struct AgentRun: Decodable, Identifiable {
    let sessionID: String
    let agentBinary: String
    let rootPID: Int
    let cwd: String
    let mode: String?
    let workspaceMode: String?
    let startedAtMS: UInt64
    let endedAtMS: UInt64?
    let exitCode: Int?

    var id: String { sessionID }
    var isActive: Bool { endedAtMS == nil }

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case agentBinary = "agent_binary"
        case rootPID = "root_pid"
        case cwd, mode
        case workspaceMode = "workspace_mode"
        case startedAtMS = "started_at_ms"
        case endedAtMS = "ended_at_ms"
        case exitCode = "exit_code"
    }
}

struct TransactionalRun: Decodable, Identifiable {
    let runID: String
    let parentRunID: String?
    let role: String
    let status: String
    let taskStatus: String?
    let workspace: String
    let containerName: String
    let startedAtMS: UInt64

    var id: String { runID }

    enum CodingKeys: String, CodingKey {
        case runID = "run_id"
        case parentRunID = "parent_run_id"
        case role, status, workspace
        case taskStatus = "task_status"
        case containerName = "container_name"
        case startedAtMS = "started_at_ms"
    }
}

struct PolicySummary {
    var source = "Checking…"
    var systemEvents = "endpoint-security"
    var endpointSecurityMode = "observe"
    var noninteractive = false
    var requireProxy = false
    var maxRuntimeSeconds: Int?
}

struct IntegrationDescriptor: Identifiable, Equatable {
    let id: String
    let name: String
    let detail: String
    let configPath: String
    let symbolName: String
    let installed: Bool
    let supportsDirectHooks: Bool
    let installationDetail: String
    let configurationIssue: String?
    let configurationNote: String?
    let canRepair: Bool
    let configuredBackendPath: String?
    var configured: Bool

    var canToggle: Bool { installed && supportsDirectHooks }
    var isHealthy: Bool { configured && configurationIssue == nil }
    var requiresRepair: Bool { canToggle && configured && configurationIssue != nil && canRepair }

    var statusLabel: String {
        if !installed { return "Not installed" }
        if !supportsDirectHooks { return "Managed launch only" }
        if configurationIssue != nil { return canRepair ? "Needs repair" : "Manual fix needed" }
        return configured ? "Protected" : "Ready to enable"
    }
}

struct ActivityItem: Identifiable {
    enum Kind {
        case agent, system
    }

    let id: String
    let kind: Kind
    let timestamp: Int64
    let title: String
    let detail: String
    let source: String
}

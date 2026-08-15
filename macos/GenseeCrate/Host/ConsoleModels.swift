import Foundation

struct SecuritySnapshot: Decodable {
    var summary = DashboardSummary()
    var alerts: [SecurityAlert] = []
    var agentEvents: [AgentEvent] = []
    var systemEvents: [SystemEvent] = []
    var sessions: [RecordedSession] = []
    var artifacts: [ArtifactFact] = []
    var relations: [ArtifactEdge] = []
    var humanFeedback: [HumanFeedback] = []
    var transactionEvents: [TransactionEvent] = []
    var workspaceEffects: [WorkspaceEffect] = []
    var jsonSessions: [AgentSessionRecord] = []

    enum CodingKeys: String, CodingKey {
        case summary, alerts, agentEvents, systemEvents, sessions, artifacts
        case relations, humanFeedback, transactionEvents, workspaceEffects, jsonSessions
    }

    init() {}

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        summary = try values.decodeIfPresent(DashboardSummary.self, forKey: .summary) ?? DashboardSummary()
        alerts = try values.decodeIfPresent([SecurityAlert].self, forKey: .alerts) ?? []
        agentEvents = try values.decodeIfPresent([AgentEvent].self, forKey: .agentEvents) ?? []
        systemEvents = try values.decodeIfPresent([SystemEvent].self, forKey: .systemEvents) ?? []
        sessions = try values.decodeIfPresent([RecordedSession].self, forKey: .sessions) ?? []
        artifacts = try values.decodeIfPresent([ArtifactFact].self, forKey: .artifacts) ?? []
        relations = try values.decodeIfPresent([ArtifactEdge].self, forKey: .relations) ?? []
        humanFeedback = try values.decodeIfPresent([HumanFeedback].self, forKey: .humanFeedback) ?? []
        transactionEvents = try values.decodeIfPresent([TransactionEvent].self, forKey: .transactionEvents) ?? []
        workspaceEffects = try values.decodeIfPresent([WorkspaceEffect].self, forKey: .workspaceEffects) ?? []
        jsonSessions = try values.decodeIfPresent([AgentSessionRecord].self, forKey: .jsonSessions) ?? []
    }
}

struct AgentSessionRecord: Decodable, Identifiable {
    let sessionID: String
    let rootPID: UInt32
    let agentBinary: String
    let endedAtMS: UInt64?

    var id: String { sessionID }
    var isActive: Bool { endedAtMS == nil }

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case rootPID = "root_pid"
        case agentBinary = "agent_binary"
        case endedAtMS = "ended_at_ms"
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
    let sessionID: String?
    let severity: String
    let action: String
    let ruleID: String
    let message: String
    let path: String?
    let createdAt: Int64

    var id: Int64 { alertID }

    enum CodingKeys: String, CodingKey {
        case alertID = "alert_id"
        case sessionID = "session_id"
        case severity, action
        case ruleID = "rule_id"
        case message, path
        case createdAt = "created_at"
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

struct TransactionEvent: Decodable, Identifiable {
    let transactionEventID: Int64
    let operationID: String
    let environmentKind: String
    let operation: String
    let phase: String
    let sourceRunID: String?
    let targetRunID: String?
    let parentRunID: String?
    let workspace: String?
    let summary: String
    let errorKind: String?
    let errorMessage: String?
    let occurredAt: Int64

    var id: Int64 { transactionEventID }

    enum CodingKeys: String, CodingKey {
        case transactionEventID = "transaction_event_id"
        case operationID = "operation_id"
        case environmentKind = "environment_kind"
        case operation, phase
        case sourceRunID = "source_run_id"
        case targetRunID = "target_run_id"
        case parentRunID = "parent_run_id"
        case workspace, summary
        case errorKind = "error_kind"
        case errorMessage = "error_message"
        case occurredAt = "occurred_at"
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
    var configured: Bool

    var canToggle: Bool { installed && supportsDirectHooks }
    var isHealthy: Bool { configured && configurationIssue == nil }
    var requiresRepair: Bool { canToggle && configured && configurationIssue != nil }

    var statusLabel: String {
        if !installed { return "Not installed" }
        if !supportsDirectHooks { return "Managed launch only" }
        if requiresRepair { return "Needs repair" }
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

import Foundation

struct WorkspaceCheckpointRecord: Decodable, Identifiable, Equatable {
    let schemaVersion: Int
    let id: String
    let createdAtMS: Int64
    let workspace: String
    let commit: String
    let baseHead: String?
    let label: String?
    let rescueOf: String?
    let requestID: Int64?
    let sessionID: String?
    let provider: String?
    let trigger: String?

    enum CodingKeys: String, CodingKey {
        case id, workspace, commit, label, provider, trigger
        case schemaVersion = "schema_version"
        case createdAtMS = "created_at_ms"
        case baseHead = "base_head"
        case rescueOf = "rescue_of"
        case requestID = "request_id"
        case sessionID = "session_id"
    }
}

enum RecoveryPointMode: String, CaseIterable, Identifiable {
    case auto
    case ask
    case off

    var id: String { rawValue }
    var title: String { rawValue.capitalized }
}

enum RecoveryFailureBehavior: String, CaseIterable, Identifiable {
    case continueWithWarning = "continue-with-warning"
    case block

    var id: String { rawValue }
    var title: String {
        switch self {
        case .continueWithWarning: "Continue with warning"
        case .block: "Stop the change"
        }
    }
}

struct RecoveryPointSettings: Equatable {
    var harnessModes: [String: RecoveryPointMode] = [:]
    var retentionHours = 168
    var failureBehavior: RecoveryFailureBehavior = .continueWithWarning

    func mode(for provider: String) -> RecoveryPointMode {
        harnessModes[provider] ?? .auto
    }
}

struct PendingRecoveryRequest: Decodable, Identifiable, Equatable {
    let id: String
    let requestID: Int64
    let sessionID: String
    let provider: String
    let workspace: String
    let reason: String
    let createdAtMS: Int64
    let status: String

    enum CodingKeys: String, CodingKey {
        case id, provider, workspace, reason, status
        case requestID = "request_id"
        case sessionID = "session_id"
        case createdAtMS = "created_at_ms"
    }
}

struct CheckpointListResponse: Decodable, Equatable {
    let workspace: String
    let checkpoints: [WorkspaceCheckpointRecord]
}

struct CheckpointRestoreResponse: Decodable, Equatable {
    let restored: WorkspaceCheckpointRecord
    let rescue: WorkspaceCheckpointRecord
}

struct CheckpointDeleteResponse: Decodable, Equatable {
    let deleted: [String]
}

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

    enum CodingKeys: String, CodingKey {
        case id, workspace, commit, label
        case schemaVersion = "schema_version"
        case createdAtMS = "created_at_ms"
        case baseHead = "base_head"
        case rescueOf = "rescue_of"
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

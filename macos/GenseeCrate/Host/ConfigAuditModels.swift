import Foundation

struct ConfigAuditHistoryEntry: Codable, Identifiable, Equatable {
    let id: UUID
    let auditedAt: Date
    let target: String
    let findingFingerprints: [String]
    let sourceDigests: [String: String]
    let inventorySignature: String
}

struct ConfigAuditDrift: Equatable {
    let addedFindingCount: Int
    let resolvedFindingCount: Int
    let changedSourceCount: Int

    var hasChanges: Bool {
        addedFindingCount > 0 || resolvedFindingCount > 0 || changedSourceCount > 0
    }
}

struct ConfigAuditBundle: Decodable {
    let requestedTarget: String
    let resolvedTargets: [String]
    let summary: ConfigAuditSummary
    let reports: [ConfigAuditTargetReport]

    enum CodingKeys: String, CodingKey {
        case requestedTarget = "requested_target"
        case resolvedTargets = "resolved_targets"
        case summary, reports
    }

    var includedReports: [ConfigAuditTargetReport] {
        reports.filter { $0.applicability != "not_detected" }
    }

    var auditedHarnessID: String? {
        guard !includedReports.isEmpty else { return nil }
        switch requestedTarget {
        case "codex", "codex-cli": return "codex"
        case "vscode", "github-copilot-vscode", "vscode-agent-host": return "vscode"
        default: return nil
        }
    }

    func historyEntry(at date: Date = Date()) -> ConfigAuditHistoryEntry {
        let reports = includedReports
        let findings = reports.flatMap(\.report.findings).map(\.fingerprint).sorted()
        var sourceDigests: [String: String] = [:]
        for source in reports.flatMap(\.report.sources) {
            sourceDigests[source.path] = source.sha256 ?? "missing"
        }
        let inventory = reports.map { report in
            let value = report.report.inventory
            return [
                report.target,
                String(value.skills.count),
                String(value.mcpServers.count),
                String(value.hookCommands),
                String(value.extensions.count),
                String(value.instructionFiles),
            ].joined(separator: ":")
        }.sorted().joined(separator: "|")
        return ConfigAuditHistoryEntry(
            id: UUID(),
            auditedAt: date,
            target: requestedTarget,
            findingFingerprints: findings,
            sourceDigests: sourceDigests,
            inventorySignature: inventory
        )
    }
}

struct ConfigAuditTargetReport: Decodable, Identifiable {
    let target: String
    let applicability: String
    let applicabilityReason: String?
    let report: ConfigAuditReport

    var id: String { target }

    enum CodingKeys: String, CodingKey {
        case target, applicability, report
        case applicabilityReason = "applicability_reason"
    }
}

struct ConfigAuditReport: Decodable {
    let ruleset: ConfigAuditRuleset
    let target: ConfigAuditTarget
    let summary: ConfigAuditSummary
    let sources: [ConfigAuditSource]
    let effectiveSecurityConfig: [String: AuditJSONValue]
    let inventory: ConfigAuditInventory
    let findings: [ConfigAuditFinding]
    let manualChecks: [ConfigAuditManualCheck]
    let limitations: [String]

    enum CodingKeys: String, CodingKey {
        case ruleset, target, summary, sources, inventory, findings, limitations
        case effectiveSecurityConfig = "effective_security_config"
        case manualChecks = "manual_checks"
    }
}

struct ConfigAuditRuleset: Decodable {
    let id: String
    let version: String
}

struct ConfigAuditTarget: Decodable {
    let provider: String
    let workspace: String
    let codexHome: String?
    let surfaces: [String]
    let vscodeUserData: String?

    enum CodingKeys: String, CodingKey {
        case provider, workspace, surfaces
        case codexHome = "codex_home"
        case vscodeUserData = "vscode_user_data"
    }
}

struct ConfigAuditSummary: Decodable {
    let assessment: String
    let maxSeverity: String?
    let counts: [String: Int]
    let manualChecks: Int

    enum CodingKeys: String, CodingKey {
        case assessment, counts
        case maxSeverity = "max_severity"
        case manualChecks = "manual_checks"
    }

    func count(_ severity: String) -> Int { counts[severity] ?? 0 }
    var findingCount: Int { counts.values.reduce(0, +) }
}

struct ConfigAuditFinding: Decodable, Identifiable {
    let fingerprint: String
    let ruleID: String
    let category: String
    let severity: String
    let confidence: String
    let assessment: String
    let title: String
    let description: String
    let evidence: [ConfigAuditEvidence]
    let remediation: ConfigAuditRemediation
    let references: [String]
    let mappings: [String]

    var id: String { fingerprint }

    enum CodingKeys: String, CodingKey {
        case fingerprint, category, severity, confidence, assessment, title, description
        case evidence, remediation, references, mappings
        case ruleID = "rule_id"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        fingerprint = try values.decode(String.self, forKey: .fingerprint)
        ruleID = try values.decode(String.self, forKey: .ruleID)
        category = try values.decode(String.self, forKey: .category)
        severity = try values.decode(String.self, forKey: .severity)
        confidence = try values.decode(String.self, forKey: .confidence)
        assessment = try values.decode(String.self, forKey: .assessment)
        title = try values.decode(String.self, forKey: .title)
        description = try values.decode(String.self, forKey: .description)
        evidence = try values.decodeIfPresent([ConfigAuditEvidence].self, forKey: .evidence) ?? []
        remediation = try values.decode(ConfigAuditRemediation.self, forKey: .remediation)
        references = try values.decodeIfPresent([String].self, forKey: .references) ?? []
        mappings = try values.decodeIfPresent([String].self, forKey: .mappings) ?? []
    }
}

struct ConfigAuditEvidence: Decodable, Identifiable {
    let source: String
    let key: String?
    let value: String?

    var id: String { [source, key, value].compactMap { $0 }.joined(separator: "|") }
}

struct ConfigAuditRemediation: Decodable {
    let summary: String
}

struct ConfigAuditSource: Decodable, Identifiable {
    let kind: String
    let path: String
    let exists: Bool
    let applied: Bool
    let trusted: Bool
    let sha256: String?
    let ignoredKeys: [String]
    let errors: [String]

    var id: String { "\(kind):\(path)" }

    enum CodingKeys: String, CodingKey {
        case kind, path, exists, applied, trusted, sha256, errors
        case ignoredKeys = "ignored_keys"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        kind = try values.decode(String.self, forKey: .kind)
        path = try values.decode(String.self, forKey: .path)
        exists = try values.decode(Bool.self, forKey: .exists)
        applied = try values.decode(Bool.self, forKey: .applied)
        trusted = try values.decode(Bool.self, forKey: .trusted)
        sha256 = try values.decodeIfPresent(String.self, forKey: .sha256)
        ignoredKeys = try values.decodeIfPresent([String].self, forKey: .ignoredKeys) ?? []
        errors = try values.decodeIfPresent([String].self, forKey: .errors) ?? []
    }
}

struct ConfigAuditInventory: Decodable {
    let skills: [ConfigAuditSkill]
    let mcpServers: [ConfigAuditMCPServer]
    let hookCommands: Int
    let pluginManifests: Int
    let marketplaceFiles: Int
    let ruleFiles: Int
    let instructionFiles: Int
    let managedRequirementFiles: Int
    let extensions: [ConfigAuditExtension]
    let customAgents: Int

    enum CodingKeys: String, CodingKey {
        case skills, extensions
        case mcpServers = "mcp_servers"
        case hookCommands = "hook_commands"
        case pluginManifests = "plugin_manifests"
        case marketplaceFiles = "marketplace_files"
        case ruleFiles = "rule_files"
        case instructionFiles = "instruction_files"
        case managedRequirementFiles = "managed_requirement_files"
        case customAgents = "custom_agents"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        skills = try values.decodeIfPresent([ConfigAuditSkill].self, forKey: .skills) ?? []
        mcpServers = try values.decodeIfPresent([ConfigAuditMCPServer].self, forKey: .mcpServers) ?? []
        hookCommands = try values.decodeIfPresent(Int.self, forKey: .hookCommands) ?? 0
        pluginManifests = try values.decodeIfPresent(Int.self, forKey: .pluginManifests) ?? 0
        marketplaceFiles = try values.decodeIfPresent(Int.self, forKey: .marketplaceFiles) ?? 0
        ruleFiles = try values.decodeIfPresent(Int.self, forKey: .ruleFiles) ?? 0
        instructionFiles = try values.decodeIfPresent(Int.self, forKey: .instructionFiles) ?? 0
        managedRequirementFiles = try values.decodeIfPresent(Int.self, forKey: .managedRequirementFiles) ?? 0
        extensions = try values.decodeIfPresent([ConfigAuditExtension].self, forKey: .extensions) ?? []
        customAgents = try values.decodeIfPresent(Int.self, forKey: .customAgents) ?? 0
    }
}

struct ConfigAuditSkill: Decodable, Identifiable {
    let name: String
    let path: String
    let scope: String
    let enabled: Bool
    let hasScripts: Bool
    let reviewState: String

    var id: String { path }

    enum CodingKeys: String, CodingKey {
        case name, path, scope, enabled
        case hasScripts = "has_scripts"
        case reviewState = "review_state"
    }
}

struct ConfigAuditMCPServer: Decodable, Identifiable {
    let id: String
    let transport: String
    let enabled: Bool
    let hasToolAllowlist: Bool
    let endpoint: String?

    enum CodingKeys: String, CodingKey {
        case id, transport, enabled, endpoint
        case hasToolAllowlist = "has_tool_allowlist"
    }
}

struct ConfigAuditExtension: Decodable, Identifiable {
    let id: String
    let version: String
    let path: String
    let enabledState: String
    let capabilities: [String]

    enum CodingKeys: String, CodingKey {
        case id, version, path, capabilities
        case enabledState = "enabled_state"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        version = try values.decode(String.self, forKey: .version)
        path = try values.decode(String.self, forKey: .path)
        enabledState = try values.decode(String.self, forKey: .enabledState)
        capabilities = try values.decodeIfPresent([String].self, forKey: .capabilities) ?? []
    }
}

struct ConfigAuditManualCheck: Decodable, Identifiable {
    let checkID: String
    let priority: String
    let title: String
    let reason: String
    let action: String
    let references: [String]

    var id: String { checkID }

    enum CodingKeys: String, CodingKey {
        case priority, title, reason, action, references
        case checkID = "check_id"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        checkID = try values.decode(String.self, forKey: .checkID)
        priority = try values.decode(String.self, forKey: .priority)
        title = try values.decode(String.self, forKey: .title)
        reason = try values.decode(String.self, forKey: .reason)
        action = try values.decode(String.self, forKey: .action)
        references = try values.decodeIfPresent([String].self, forKey: .references) ?? []
    }
}

enum AuditJSONValue: Decodable {
    case string(String)
    case number(Double)
    case boolean(Bool)
    case object([String: AuditJSONValue])
    case array([AuditJSONValue])
    case null

    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        if value.decodeNil() { self = .null }
        else if let decoded = try? value.decode(Bool.self) { self = .boolean(decoded) }
        else if let decoded = try? value.decode(Double.self) { self = .number(decoded) }
        else if let decoded = try? value.decode(String.self) { self = .string(decoded) }
        else if let decoded = try? value.decode([AuditJSONValue].self) { self = .array(decoded) }
        else { self = .object(try value.decode([String: AuditJSONValue].self)) }
    }

    var displayValue: String {
        switch self {
        case let .string(value): value
        case let .number(value): value.rounded() == value ? Int(value).formatted() : value.formatted()
        case let .boolean(value): value ? "true" : "false"
        case let .array(values): values.map(\.displayValue).joined(separator: ", ")
        case let .object(values): values.sorted { $0.key < $1.key }
                .map { "\($0.key): \($0.value.displayValue)" }.joined(separator: ", ")
        case .null: "null"
        }
    }
}

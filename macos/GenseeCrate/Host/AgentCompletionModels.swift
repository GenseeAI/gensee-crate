import Foundation

func searchTermsMatch(_ search: String, fields: [String?]) -> Bool {
    let terms = search
        .split(whereSeparator: { $0.isWhitespace })
        .map(String.init)
    guard !terms.isEmpty else { return true }

    let searchableText = fields.compactMap { $0 }.joined(separator: "\n")
    return terms.allSatisfy { searchableText.localizedCaseInsensitiveContains($0) }
}

enum NotificationSeverity: String, CaseIterable, Identifiable {
    case critical
    case high
    case medium
    case low
    case info

    var id: String { rawValue }

    var title: String {
        switch self {
        case .critical: "Critical only"
        case .high: "High and critical"
        case .medium: "Medium and above"
        case .low: "Low and above"
        case .info: "All findings"
        }
    }

    func includes(_ severity: String) -> Bool {
        Self.rank(for: severity) >= Self.rank(for: rawValue)
    }

    static func rank(for severity: String) -> Int {
        switch severity.lowercased() {
        case "critical": 5
        case "high": 4
        case "medium": 3
        case "low": 2
        default: 1
        }
    }
}

enum AgentReviewState: String, Equatable {
    case verified
    case review
    case attention
    case incomplete

    var title: String {
        switch self {
        case .verified: "Verified"
        case .review: "Review recommended"
        case .attention: "Needs attention"
        case .incomplete: "Incomplete evidence"
        }
    }
}

enum AgentAttentionKind: String, Equatable {
    case scopeDrift
    case blockedAction
    case highRiskActivity
    case staleVerification
}

struct AgentAttentionSignal: Equatable {
    let kind: AgentAttentionKind
    let title: String
    let detail: String
    let systemImage: String
}

struct AgentCompletionSummary: Identifiable, Equatable {
    let requestID: Int64
    let sessionID: String
    let harness: String
    let prompt: String
    let startedAt: Int64
    let completedAt: Int64
    let durationMS: Int64
    let toolCallCount: Int
    let commandCount: Int
    let affectedFiles: [String]
    let verifiedFiles: [String]
    let declaredOnlyFiles: [String]
    let unmatchedFiles: [String]
    let ignoredFiles: [String]
    let ignoredFileTouchEventsOmitted: Int
    let ignoredFileTouchPathsTruncated: Bool
    let testCommandCount: Int
    let alertCount: Int
    let decisionCount: Int
    let highRiskAlertCount: Int
    let strongestAction: String
    let strongestSeverity: String
    let lastTestAt: Int64?
    let lastMutationAt: Int64?
    let sensitiveFiles: [FileTouchEvidence]
    let reviewState: AgentReviewState

    var id: Int64 { requestID }

    var isLargeTask: Bool {
        toolCallCount >= 5
            || durationMS >= 120_000
            || affectedFiles.count >= 2
            || highRiskAlertCount > 0
            || ["ask", "block", "deny"].contains(strongestAction.lowercased())
    }

    var testEvidenceIsStale: Bool {
        guard let lastTestAt, let lastMutationAt else { return false }
        return lastMutationAt > lastTestAt
    }

    /// The deliberately narrow signal shared by the Review Queue, menu bar,
    /// and native notifications. Routine warnings and clean completions stay
    /// in history instead of interrupting the developer.
    var attentionSignal: AgentAttentionSignal? {
        let action = strongestAction.lowercased()
        if ["block", "deny"].contains(action) {
            return AgentAttentionSignal(
                kind: .blockedAction,
                title: "Action blocked",
                detail: "Gensee stopped a \(strongestSeverity.lowercased())-risk action. Review the finding before retrying.",
                systemImage: "hand.raised.fill"
            )
        }
        if !unmatchedFiles.isEmpty {
            let first = URL(fileURLWithPath: unmatchedFiles[0]).lastPathComponent
            return AgentAttentionSignal(
                kind: .scopeDrift,
                title: "Scope drift detected",
                detail: "\(unmatchedFiles.count) file\(unmatchedFiles.count == 1 ? "" : "s") changed outside declared tool intent, including \(first).",
                systemImage: "arrow.triangle.branch"
            )
        }
        if testEvidenceIsStale {
            return AgentAttentionSignal(
                kind: .staleVerification,
                title: "Verification is stale",
                detail: "Files changed after the last observed test, build, lint, or type-check command.",
                systemImage: "checkmark.diamond"
            )
        }
        if highRiskAlertCount > 0 {
            return AgentAttentionSignal(
                kind: .highRiskActivity,
                title: "High-risk activity needs review",
                detail: "Gensee grouped \(highRiskAlertCount) high-risk finding\(highRiskAlertCount == 1 ? "" : "s") from this request.",
                systemImage: "exclamationmark.shield.fill"
            )
        }
        return nil
    }

    var needsIntervention: Bool { attentionSignal != nil }

    /// Changes whenever the actionable evidence for a request changes. A
    /// dismissed item therefore stays out of Needs You until new evidence
    /// materially changes the decision, instead of hiding the request forever.
    var attentionFingerprint: String? {
        guard let signal = attentionSignal else { return nil }
        return [
            signal.kind.rawValue,
            strongestAction.lowercased(),
            strongestSeverity.lowercased(),
            String(lastMutationAt ?? 0),
            String(highRiskAlertCount),
            unmatchedFiles.sorted().joined(separator: "\u{1F}"),
        ].joined(separator: "|")
    }
}

struct AgentSessionSummary: Identifiable, Equatable {
    let sessionID: String
    let harness: String
    let startedAt: Int64
    let completedAt: Int64
    let requests: [AgentCompletionSummary]

    var id: String { sessionID }
    var durationMS: Int64 { max(0, completedAt - startedAt) }
    var requestCount: Int { requests.count }
    var toolCallCount: Int { requests.reduce(0) { $0 + $1.toolCallCount } }
    var commandCount: Int { requests.reduce(0) { $0 + $1.commandCount } }
    var testCommandCount: Int { requests.reduce(0) { $0 + $1.testCommandCount } }
    var alertCount: Int { requests.reduce(0) { $0 + $1.alertCount } }
    var highRiskAlertCount: Int { requests.reduce(0) { $0 + $1.highRiskAlertCount } }
    var affectedFiles: [String] {
        var seen = Set<String>()
        return requests.flatMap(\.affectedFiles).filter { seen.insert($0).inserted }
    }
    var verifiedFiles: [String] {
        var seen = Set<String>()
        return requests.flatMap(\.verifiedFiles).filter { seen.insert($0).inserted }
    }
    var unmatchedFiles: [String] {
        var seen = Set<String>()
        return requests.flatMap(\.unmatchedFiles).filter { seen.insert($0).inserted }
    }
    var declaredOnlyFiles: [String] {
        var seen = Set<String>()
        return requests.flatMap(\.declaredOnlyFiles).filter { seen.insert($0).inserted }
    }
    var ignoredFiles: [String] {
        var seen = Set<String>()
        return requests.flatMap(\.ignoredFiles).filter { seen.insert($0).inserted }
    }
    var sensitiveFiles: [FileTouchEvidence] {
        var seen = Set<String>()
        return requests.flatMap(\.sensitiveFiles).filter { seen.insert($0.path).inserted }
    }
    var ignoredFileTouchEventsOmitted: Int {
        requests.reduce(0) { $0 + $1.ignoredFileTouchEventsOmitted }
    }
    var ignoredFileTouchPathsTruncated: Bool {
        requests.contains(where: \.ignoredFileTouchPathsTruncated)
    }
    var reviewState: AgentReviewState {
        if requests.contains(where: { $0.reviewState == .attention }) { return .attention }
        if requests.contains(where: { $0.reviewState == .review }) { return .review }
        if requests.contains(where: { $0.reviewState == .incomplete }) { return .incomplete }
        return .verified
    }
    var needsIntervention: Bool { requests.contains(where: \.needsIntervention) }
    var interventionCount: Int { requests.filter(\.needsIntervention).count }
}

enum HarnessDisplayName {
    static func from(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "Agent" }

        let provider = EndpointSessionScope.harnessProvider(agentBinary: trimmed)
        switch provider ?? normalizedProvider(trimmed) {
        case "codex": return "Codex"
        case "claude-code": return "Claude"
        case "vscode": return "GitHub Copilot"
        case "antigravity": return "Antigravity"
        case "cursor": return "Cursor"
        case "omnigent": return "Omnigent"
        case "sidecar-watch": return "Sidecar"
        case "system-monitor": return "System"
        default:
            let component = URL(fileURLWithPath: trimmed).lastPathComponent
            let fallback = component.isEmpty ? trimmed : component
            return fallback.replacingOccurrences(of: "-", with: " ").capitalized
        }
    }

    private static func normalizedProvider(_ value: String) -> String {
        let lower = value.lowercased()
        if lower == "claude" || lower == "claude-code" || lower.contains("/claude.app/") { return "claude-code" }
        if lower == "codex" || lower.contains("/codex.app/") || lower.contains("@openai/codex") { return "codex" }
        if lower == "github-copilot" || lower == "vscode" || lower.contains("visual studio code") { return "vscode" }
        if lower == "antigravity" || lower == "gemini" || lower.contains("/antigravity.app/") { return "antigravity" }
        if lower == "cursor" || lower.contains("/cursor.app/") { return "cursor" }
        if lower == "omnigent" { return "omnigent" }
        return lower
    }
}

enum RequestPromptDisplay {
    static func title(from value: String?) -> String {
        // Ambient UI context is stripped and bounded by the backend so every
        // client sees the same canonical request. The app only owns display
        // whitespace and the empty-state fallback.
        guard let prompt = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !prompt.isEmpty
        else { return "Completed agent request" }
        return prompt
    }
}

enum AgentCompletionDerivation {
    static func summaries(from snapshot: SecuritySnapshot) -> [AgentCompletionSummary] {
        let sessions = Dictionary(uniqueKeysWithValues: snapshot.sessions.map { ($0.sessionID, $0) })

        return snapshot.requests.compactMap { request in
            guard request.sessionID != "system",
                  let startedAt = request.createdAt,
                  let completedAt = request.completedAt,
                  completedAt >= startedAt
            else { return nil }

            let events = snapshot.agentEvents.filter { $0.requestID == request.requestID }
            let calls = TimelineDerivation.toolCalls(from: events)
            let alerts = snapshot.alerts.filter { $0.requestID == request.requestID }
            let classifiedTouches = request.fileTouches.isEmpty
                ? request.summaryFileTouches
                : request.fileTouches
            let affectedFiles = classifiedTouches.isEmpty
                ? request.summaryFileTouchPaths
                : classifiedTouches.map(\.path)
            let verifiedFiles = classifiedTouches
                .filter(\.intendedAndVerified)
                .map(\.path)
            let declaredOnlyFiles = classifiedTouches
                .filter { $0.declaredByHarness && !$0.osVerified }
                .map(\.path)
            let unmatchedFiles = classifiedTouches
                .filter { $0.osVerified && !$0.declaredByHarness }
                .map(\.path)
            let strongestAction = request.strongestAction
                ?? alerts.map(\.action).max(by: { actionRank($0) < actionRank($1) })
                ?? "allow"
            let strongestSeverity = request.strongestSeverity
                ?? alerts.map(\.severity).max(by: { severityRank($0) < severityRank($1) })
                ?? "info"
            let highRiskCount = request.highRiskAlertCount ?? alerts.filter {
                ["high", "critical"].contains($0.severity.lowercased())
            }.count
            let alertCount = request.alertCount ?? alerts.count
            let decisionCount = request.decisionCount ?? Set(alerts.map {
                "\($0.ruleID)|\($0.path ?? "")|\($0.action.lowercased())"
            }).count
            let incompleteToolEvidence = calls.contains { $0.endTimestamp == nil }
            let lastTestAt = calls
                .filter(isTestCall)
                .map { $0.endTimestamp ?? $0.startTimestamp }
                .max()
            let lastMutationAt = classifiedTouches.compactMap(\.lastObservedAt).max()
            let staleVerification = lastTestAt != nil && lastMutationAt != nil && lastMutationAt! > lastTestAt!
            let reviewState: AgentReviewState
            if highRiskCount > 0 || ["block", "deny"].contains(strongestAction.lowercased()) {
                reviewState = .attention
            } else if decisionCount > 0 || staleVerification || !unmatchedFiles.isEmpty || ["warn", "ask"].contains(strongestAction.lowercased()) {
                reviewState = .review
            } else if incompleteToolEvidence {
                reviewState = .incomplete
            } else {
                reviewState = .verified
            }

            let harness = sessions[request.sessionID]?.agentID
                ?? events.first?.source
                ?? "Agent"
            let prompt = RequestPromptDisplay.title(from: request.originalUserPrompt)

            return AgentCompletionSummary(
                requestID: request.requestID,
                sessionID: request.sessionID,
                harness: HarnessDisplayName.from(harness),
                prompt: prompt,
                startedAt: startedAt,
                completedAt: completedAt,
                durationMS: completedAt - startedAt,
                toolCallCount: request.toolCallCount ?? calls.count,
                commandCount: calls.filter { isCommandTool($0.toolName) }.count,
                affectedFiles: affectedFiles,
                verifiedFiles: verifiedFiles,
                declaredOnlyFiles: declaredOnlyFiles,
                unmatchedFiles: unmatchedFiles,
                ignoredFiles: request.ignoredFileTouchPaths,
                ignoredFileTouchEventsOmitted: request.ignoredFileTouchEventsOmitted,
                ignoredFileTouchPathsTruncated: request.ignoredFileTouchPathsTruncated,
                testCommandCount: calls.filter(isTestCall).count,
                alertCount: alertCount,
                decisionCount: decisionCount,
                highRiskAlertCount: highRiskCount,
                strongestAction: strongestAction,
                strongestSeverity: strongestSeverity,
                lastTestAt: lastTestAt,
                lastMutationAt: lastMutationAt,
                sensitiveFiles: classifiedTouches.filter { !$0.riskLabels.isEmpty },
                reviewState: reviewState
            )
        }
        .sorted { lhs, rhs in
            lhs.completedAt == rhs.completedAt
                ? lhs.requestID > rhs.requestID
                : lhs.completedAt > rhs.completedAt
        }
    }

    static func sessionSummaries(from snapshot: SecuritySnapshot) -> [AgentSessionSummary] {
        let requests = Dictionary(grouping: summaries(from: snapshot), by: \.sessionID)
        let sessions = Dictionary(uniqueKeysWithValues: snapshot.sessions.map { ($0.sessionID, $0) })

        return requests.compactMap { sessionID, sessionRequests in
            guard let first = sessionRequests.min(by: { $0.startedAt < $1.startedAt }),
                  let last = sessionRequests.max(by: { $0.completedAt < $1.completedAt })
            else { return nil }
            let ordered = sessionRequests.sorted { $0.completedAt > $1.completedAt }
            return AgentSessionSummary(
                sessionID: sessionID,
                harness: HarnessDisplayName.from(sessions[sessionID]?.agentID ?? first.harness),
                startedAt: first.startedAt,
                completedAt: last.completedAt,
                requests: ordered
            )
        }
        .sorted { lhs, rhs in
            lhs.completedAt == rhs.completedAt ? lhs.sessionID > rhs.sessionID : lhs.completedAt > rhs.completedAt
        }
    }

    static func notificationBody(for summary: AgentCompletionSummary) -> String {
        if let signal = summary.attentionSignal {
            return signal.detail
        }
        var parts = ["\(summary.toolCallCount) tool call\(summary.toolCallCount == 1 ? "" : "s")"]
        if !summary.affectedFiles.isEmpty {
            parts.append("\(summary.affectedFiles.count) file\(summary.affectedFiles.count == 1 ? "" : "s") touched")
        }
        if summary.highRiskAlertCount > 0 {
            parts.append("\(summary.highRiskAlertCount) high-risk finding\(summary.highRiskAlertCount == 1 ? "" : "s")")
        } else {
            parts.append("no high-risk findings")
        }
        return parts.joined(separator: " · ")
    }

    private static func isCommandTool(_ tool: String) -> Bool {
        let normalized = tool.lowercased()
        return ["bash", "shell", "terminal", "exec", "command"].contains {
            normalized.contains($0)
        }
    }

    static func verificationCommand(for call: TimelineToolCall) -> String? {
        guard isCommandTool(call.toolName), let command = shellCommand(from: call) else { return nil }
        let patterns = [
            #"(?im)(?:^|[;&|]\s*)(?:env\s+(?:\w+=\S+\s+)+)?cargo\s+(?:test|check|clippy|build|nextest\s+run)\b"#,
            #"(?im)(?:^|[;&|]\s*)swift\s+(?:test|build)\b"#,
            #"(?im)(?:^|[;&|]\s*)go\s+(?:test|build)\b"#,
            #"(?im)(?:^|[;&|]\s*)(?:python(?:3(?:\.\d+)?)?\s+-m\s+pytest|pytest)\b"#,
            #"(?im)(?:^|[;&|]\s*)(?:npm|pnpm|yarn|bun)\s+(?:(?:run|run-script)\s+)?(?:test|build|lint|typecheck|type-check|check)\b"#,
            #"(?im)(?:^|[;&|]\s*)(?:make|gradle|gradlew|\.\/gradlew)\s+(?:test|check|build|lint)\b"#,
            #"(?im)(?:^|[;&|]\s*)mvn\s+(?:test|verify|package)\b"#,
            #"(?im)(?:^|[;&|]\s*)dotnet\s+(?:test|build)\b"#,
            #"(?im)(?:^|[;&|]\s*)xcodebuild\b[^;&|\n]*\btest\b"#,
            #"(?im)(?:^|[;&|]\s*)(?:tsc|eslint|mypy|pyright)\b"#,
            #"(?im)(?:^|[;&|]\s*)ruff\s+check\b"#,
        ]
        return patterns.contains { command.range(of: $0, options: .regularExpression) != nil }
            ? command
            : nil
    }

    private static func isTestCall(_ call: TimelineToolCall) -> Bool {
        verificationCommand(for: call) != nil
    }

    private static func shellCommand(from call: TimelineToolCall) -> String? {
        if let input = call.input,
           let data = input.data(using: .utf8),
           let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let command = object["command"] as? String,
           !command.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        {
            return command
        }
        if let detail = call.detail, !detail.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return detail
        }
        return nil
    }

    private static func actionRank(_ action: String) -> Int {
        ["allow": 0, "warn": 1, "ask": 2, "block": 3, "deny": 3][action.lowercased()] ?? 0
    }

    private static func severityRank(_ severity: String) -> Int {
        ["info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4][severity.lowercased()] ?? 0
    }
}

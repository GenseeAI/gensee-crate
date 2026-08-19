import Foundation

enum AgentReviewState: String, Equatable {
    case verified
    case review
    case attention

    var title: String {
        switch self {
        case .verified: "Ready for review"
        case .review: "Review recommended"
        case .attention: "Needs attention"
        }
    }
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
    let testCommandCount: Int
    let alertCount: Int
    let highRiskAlertCount: Int
    let strongestAction: String
    let strongestSeverity: String
    let reviewState: AgentReviewState

    var id: Int64 { requestID }

    var isLargeTask: Bool {
        toolCallCount >= 5
            || durationMS >= 120_000
            || affectedFiles.count >= 2
            || highRiskAlertCount > 0
            || ["ask", "block", "deny"].contains(strongestAction.lowercased())
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
            let affectedFiles = uniqueMutationPaths(from: calls)
            let strongestAction = alerts.map(\.action).max(by: { actionRank($0) < actionRank($1) }) ?? "allow"
            let strongestSeverity = alerts.map(\.severity).max(by: { severityRank($0) < severityRank($1) }) ?? "info"
            let highRiskCount = alerts.filter {
                ["high", "critical"].contains($0.severity.lowercased())
            }.count
            let reviewState: AgentReviewState
            if highRiskCount > 0 || ["block", "deny"].contains(strongestAction.lowercased()) {
                reviewState = .attention
            } else if !alerts.isEmpty || ["warn", "ask"].contains(strongestAction.lowercased()) {
                reviewState = .review
            } else {
                reviewState = .verified
            }

            let harness = sessions[request.sessionID]?.agentID
                ?? events.first?.source
                ?? "Agent"
            let prompt = request.originalUserPrompt?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .nonEmpty
                ?? "Completed agent request"

            return AgentCompletionSummary(
                requestID: request.requestID,
                sessionID: request.sessionID,
                harness: displayHarness(harness),
                prompt: prompt,
                startedAt: startedAt,
                completedAt: completedAt,
                durationMS: completedAt - startedAt,
                toolCallCount: calls.count,
                commandCount: calls.filter { isCommandTool($0.toolName) }.count,
                affectedFiles: affectedFiles,
                testCommandCount: calls.filter(isTestCall).count,
                alertCount: alerts.count,
                highRiskAlertCount: highRiskCount,
                strongestAction: strongestAction,
                strongestSeverity: strongestSeverity,
                reviewState: reviewState
            )
        }
        .sorted { lhs, rhs in
            lhs.completedAt == rhs.completedAt
                ? lhs.requestID > rhs.requestID
                : lhs.completedAt > rhs.completedAt
        }
    }

    static func notificationBody(for summary: AgentCompletionSummary) -> String {
        var parts = ["\(summary.toolCallCount) tool call\(summary.toolCallCount == 1 ? "" : "s")"]
        if !summary.affectedFiles.isEmpty {
            parts.append("\(summary.affectedFiles.count) file\(summary.affectedFiles.count == 1 ? "" : "s") changed")
        }
        if summary.highRiskAlertCount > 0 {
            parts.append("\(summary.highRiskAlertCount) high-risk finding\(summary.highRiskAlertCount == 1 ? "" : "s")")
        } else {
            parts.append("no high-risk findings")
        }
        return parts.joined(separator: " · ")
    }

    private static func uniqueMutationPaths(from calls: [TimelineToolCall]) -> [String] {
        var seen = Set<String>()
        return calls
            .filter { isMutationTool($0.toolName) }
            .flatMap(\.affectedFiles)
            .filter { seen.insert($0).inserted }
    }

    private static func isMutationTool(_ tool: String) -> Bool {
        let normalized = tool.lowercased()
        return ["write", "edit", "multiedit", "notebookedit", "apply_patch", "create"]
            .contains { normalized.contains($0) }
    }

    private static func isCommandTool(_ tool: String) -> Bool {
        let normalized = tool.lowercased()
        return ["bash", "shell", "terminal", "exec", "command"].contains {
            normalized.contains($0)
        }
    }

    private static func isTestCall(_ call: TimelineToolCall) -> Bool {
        guard isCommandTool(call.toolName), let input = call.input?.lowercased() else { return false }
        return [" test", "test ", "pytest", "xcodebuild test", "npm test", "pnpm test", "yarn test", "cargo test", "go test", "swift test"]
            .contains { input.contains($0) }
    }

    private static func displayHarness(_ value: String) -> String {
        switch value.lowercased() {
        case "codex": "Codex"
        case "claude", "claude-code": "Claude Code"
        case "vscode", "github-copilot": "GitHub Copilot"
        case "antigravity", "gemini": "Antigravity"
        case "cursor": "Cursor"
        case "omnigent": "Omnigent"
        default: value.replacingOccurrences(of: "-", with: " ").capitalized
        }
    }

    private static func actionRank(_ action: String) -> Int {
        ["allow": 0, "warn": 1, "ask": 2, "block": 3, "deny": 3][action.lowercased()] ?? 0
    }

    private static func severityRank(_ severity: String) -> Int {
        ["info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4][severity.lowercased()] ?? 0
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}

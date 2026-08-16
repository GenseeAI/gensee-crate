import Foundation

enum TimelineDurationSource: Equatable {
    case reported
    case elapsed
}

struct TimelineToolCall: Identifiable, Equatable {
    let id: String
    let toolName: String
    let startTimestamp: Int64
    let endTimestamp: Int64?
    let durationMS: Int64?
    let durationSource: TimelineDurationSource?
    let detail: String?
    let detailFull: String?
    let affectedFiles: [String]
    let input: String?
    let response: String?
}

struct TimelineToolGroup: Identifiable, Equatable {
    let index: Int
    let calls: [TimelineToolCall]

    var id: Int { index }
    var isParallel: Bool { calls.count > 1 }
}

struct TimelinePolicyOutcome: Equatable {
    let action: String
    let severity: String

    static let allowed = TimelinePolicyOutcome(action: "allow", severity: "info")
}

enum TimelineDerivation {
    static func toolCalls(from events: [AgentEvent]) -> [TimelineToolCall] {
        struct EventPair {
            var pre: AgentEvent?
            var post: AgentEvent?
        }

        var pairs: [String: EventPair] = [:]
        for event in events {
            let key = event.toolUseID ?? "event-\(event.eventID)"
            var pair = pairs[key] ?? EventPair()
            switch event.type {
            case "PreToolUse": pair.pre = event
            case "PostToolUse": pair.post = event
            default: pair.pre = pair.pre ?? event
            }
            pairs[key] = pair
        }

        return pairs.compactMap { id, pair in
            guard let pre = pair.pre else { return nil }
            let inputObject = jsonObject(pre.toolInput)
            let responseObject = jsonObject(pair.post?.toolResponse)
            let reportedDuration = integer(responseObject?["duration_ms"])
            let elapsedDuration = pair.post.flatMap { post in
                post.timestamp >= pre.timestamp ? post.timestamp - pre.timestamp : nil
            }
            let detail = toolDetail(inputObject)
            return TimelineToolCall(
                id: id,
                toolName: pre.toolName ?? "Unknown",
                startTimestamp: pre.timestamp,
                endTimestamp: pair.post?.timestamp,
                durationMS: reportedDuration ?? elapsedDuration,
                durationSource: reportedDuration != nil ? .reported : elapsedDuration != nil ? .elapsed : nil,
                detail: detail?.label,
                detailFull: detail?.full,
                affectedFiles: affectedFiles(inputObject),
                input: pre.toolInput,
                response: pair.post?.toolResponse
            )
        }
        .sorted { lhs, rhs in
            lhs.startTimestamp == rhs.startTimestamp
                ? lhs.id < rhs.id
                : lhs.startTimestamp < rhs.startTimestamp
        }
    }

    static func groups(from calls: [TimelineToolCall]) -> [TimelineToolGroup] {
        guard let first = calls.first else { return [] }
        var result: [TimelineToolGroup] = []
        var current = [first]
        var groupEnd = first.endTimestamp ?? first.startTimestamp + 1

        for call in calls.dropFirst() {
            if call.startTimestamp >= groupEnd {
                result.append(TimelineToolGroup(index: result.count, calls: current))
                current = [call]
                groupEnd = call.endTimestamp ?? call.startTimestamp + 1
            } else {
                current.append(call)
                if let end = call.endTimestamp {
                    groupEnd = max(groupEnd, end)
                }
            }
        }
        result.append(TimelineToolGroup(index: result.count, calls: current))
        return result
    }

    static func policyOutcomes(from alerts: [SecurityAlert]) -> [String: TimelinePolicyOutcome] {
        var outcomes: [String: TimelinePolicyOutcome] = [:]
        for alert in alerts {
            guard let toolUseID = alert.toolUseID else { continue }
            let incoming = TimelinePolicyOutcome(action: alert.action, severity: alert.severity)
            guard let current = outcomes[toolUseID] else {
                outcomes[toolUseID] = incoming
                continue
            }
            if actionRank(incoming.action) > actionRank(current.action)
                || severityRank(incoming.severity) > severityRank(current.severity)
            {
                outcomes[toolUseID] = incoming
            }
        }
        return outcomes
    }

    private static func jsonObject(_ text: String?) -> [String: Any]? {
        guard let text, let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data)
        else { return nil }
        return object as? [String: Any]
    }

    private static func integer(_ value: Any?) -> Int64? {
        switch value {
        case let number as NSNumber: number.int64Value
        case let text as String: Int64(text)
        default: nil
        }
    }

    private static func toolDetail(_ input: [String: Any]?) -> (label: String, full: String?)? {
        guard let input else { return nil }
        for key in ["query", "url", "path", "file_path", "notebook_path", "command", "description"] {
            guard let value = input[key] as? String, !value.isEmpty else { continue }
            if ["path", "file_path", "notebook_path"].contains(key) {
                return (URL(fileURLWithPath: value).lastPathComponent, value)
            }
            return (value, nil)
        }
        return nil
    }

    private static func affectedFiles(_ input: [String: Any]?) -> [String] {
        guard let input else { return [] }
        let pathKeys = ["path", "file_path", "notebook_path", "target_file"]
        let pathsKeys = ["paths", "file_paths"]
        var files: [String] = []
        for key in pathKeys {
            if let value = input[key] as? String, !value.isEmpty {
                files.append(value)
            }
        }
        for key in pathsKeys {
            if let values = input[key] as? [String] {
                files.append(contentsOf: values.filter { !$0.isEmpty })
            }
        }
        if let changes = input["changes"] as? [[String: Any]] {
            files.append(contentsOf: changes.compactMap { change in
                guard let path = change["path"] as? String, !path.isEmpty else { return nil }
                return path
            })
        }
        var seen = Set<String>()
        return files.filter { seen.insert($0).inserted }
    }

    private static func actionRank(_ action: String) -> Int {
        ["allow": 0, "warn": 1, "ask": 2, "block": 3][action.lowercased()] ?? 0
    }

    private static func severityRank(_ severity: String) -> Int {
        ["info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4][severity.lowercased()] ?? 0
    }
}

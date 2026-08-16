import Foundation

struct AlertSeveritySlice: Identifiable, Equatable {
    let severity: String
    let count: Int
    let startFraction: Double
    let endFraction: Double

    var id: String { severity }
}

enum AlertSeverityBreakdown {
    static let orderedSeverities = ["critical", "high", "medium", "low", "info"]

    static func counts(for severities: [String]) -> [String: Int] {
        severities.reduce(into: Dictionary(uniqueKeysWithValues: orderedSeverities.map { ($0, 0) })) { result, severity in
            let normalized = severity.lowercased()
            let bucket = orderedSeverities.contains(normalized) ? normalized : "info"
            result[bucket, default: 0] += 1
        }
    }

    static func slices(for severities: [String]) -> [AlertSeveritySlice] {
        slices(for: counts(for: severities))
    }

    static func slices(for severityCounts: [String: Int]) -> [AlertSeveritySlice] {
        let total = severityCounts.values.reduce(0, +)
        guard total > 0 else { return [] }

        var cumulativeCount = 0
        return orderedSeverities.compactMap { severity in
            let count = severityCounts[severity, default: 0]
            guard count > 0 else { return nil }

            let start = Double(cumulativeCount) / Double(total)
            cumulativeCount += count
            return AlertSeveritySlice(
                severity: severity,
                count: count,
                startFraction: start,
                endFraction: Double(cumulativeCount) / Double(total)
            )
        }
    }
}

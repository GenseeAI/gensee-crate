import Foundation
import SwiftUI

enum ProtectionLevel: String, CaseIterable, Identifiable {
    case observe
    case guarded
    case unattended

    var id: String { rawValue }

    var title: String {
        switch self {
        case .observe: "Fast"
        case .guarded: "Review"
        case .unattended: "Sensitive"
        }
    }

    var tagline: String {
        switch self {
        case .observe: "Let agents work; interrupt only through your existing high-confidence hook rules."
        case .guarded: "Ask before broad or sensitive changes and enforce protected targets at the OS layer."
        case .unattended: "Tightly control reads, writes, and execution; stop risky work instead of waiting."
        }
    }

    var detail: String {
        switch self {
        case .observe:
            "Harness hooks continue to stop configured dangerous actions. Endpoint Security independently records managed-agent activity but does not add OS authorization prompts."
        case .guarded:
            "Endpoint Security enforces configured protected paths and executables. Recovery points default to Auto, and ambiguous hook decisions can ask before the harness continues."
        case .unattended:
            "Strict OS protection is enabled and medium-or-higher ask decisions become deny. This is intended for sensitive repositories and unattended work."
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
        let hour = 60 * minute
        let day = 24 * hour
        let checkoutSession = "demo-claude-checkout"
        let securitySession = "demo-codex-security"
        let docsSession = "demo-cursor-docs"
        let releaseSession = "demo-copilot-release"
        let migrationSession = "demo-codex-migration"
        let researchSession = "demo-antigravity-research"

        var snapshot = SecuritySnapshot()
        var events: [AgentEvent] = []
        var eventID: Int64 = 1
        func addCall(
            request: Int64,
            session: String,
            start: Int64,
            duration: Int64,
            tool: String,
            input: String,
            response: String,
            use: String
        ) {
            events.append(event(eventID, request: request, session: session, at: start, type: "PreToolUse", tool: tool, input: input, use: use))
            eventID += 1
            events.append(event(eventID, request: request, session: session, at: start + duration, type: "PostToolUse", tool: tool, response: response, use: use))
            eventID += 1
        }

        // The newest request is intentionally the most useful product tour:
        // ordinary feature work, independent file verification, one scope-drift
        // finding, a passing test, and a recovery point created before changes.
        addCall(request: 9108, session: checkoutSession, start: nowMS - 24 * minute, duration: 1_200, tool: "Read", input: #"{"file_path":"/Users/demo/AcmeShop/apps/storefront/src/checkout/OrderSummary.tsx"}"#, response: #"{"lines":184}"#, use: "demo-checkout-read")
        addCall(request: 9108, session: checkoutSession, start: nowMS - 22 * minute, duration: 86_000, tool: "Edit", input: #"{"file_path":"/Users/demo/AcmeShop/apps/storefront/src/checkout/OrderSummary.tsx"}"#, response: #"{"changed":true}"#, use: "demo-checkout-edit")
        addCall(request: 9108, session: checkoutSession, start: nowMS - 20 * minute, duration: 74_000, tool: "Edit", input: #"{"file_path":"/Users/demo/AcmeShop/packages/pricing/src/taxTotals.ts"}"#, response: #"{"changed":true}"#, use: "demo-tax-edit")
        addCall(request: 9108, session: checkoutSession, start: nowMS - 18 * minute, duration: 3_800, tool: "Bash", input: #"{"command":"python3 scripts/sync_release_matrix.py --service storefront"}"#, response: #"{"exit_code":0,"stdout":"updated release matrix"}"#, use: "demo-release-script")
        addCall(request: 9108, session: checkoutSession, start: nowMS - 16 * minute, duration: 91_000, tool: "Bash", input: #"{"command":"pnpm test --filter storefront -- taxTotals"}"#, response: #"{"exit_code":0,"summary":"18 tests passed in 8.4s"}"#, use: "demo-checkout-test")

        addCall(request: 9107, session: securitySession, start: nowMS - 48 * minute, duration: 640, tool: "Read", input: #"{"file_path":"/Users/demo/AcmeShop/.env.production"}"#, response: #"{"decision":"blocked","reason":"protected credential file"}"#, use: "demo-secret-read")
        addCall(request: 9107, session: securitySession, start: nowMS - 46 * minute, duration: 2_100, tool: "Read", input: #"{"file_path":"/Users/demo/AcmeShop/.env.example"}"#, response: #"{"lines":24}"#, use: "demo-template-read")

        addCall(request: 9106, session: docsSession, start: nowMS - 94 * minute, duration: 1_400, tool: "Read", input: #"{"file_path":"/Users/demo/AcmeShop/docs/onboarding.md"}"#, response: #"{"lines":218}"#, use: "demo-docs-read")
        addCall(request: 9106, session: docsSession, start: nowMS - 91 * minute, duration: 63_000, tool: "Edit", input: #"{"file_path":"/Users/demo/AcmeShop/docs/onboarding.md"}"#, response: #"{"changed":true}"#, use: "demo-docs-edit")
        addCall(request: 9106, session: docsSession, start: nowMS - 88 * minute, duration: 22_000, tool: "Bash", input: #"{"command":"pnpm lint:docs"}"#, response: #"{"exit_code":0,"summary":"42 documents checked"}"#, use: "demo-docs-lint")

        addCall(request: 9105, session: checkoutSession, start: nowMS - 4 * hour, duration: 112_000, tool: "Edit", input: #"{"file_path":"/Users/demo/AcmeShop/packages/payments/src/retryPolicy.ts"}"#, response: #"{"changed":true}"#, use: "demo-retry-edit")
        addCall(request: 9105, session: checkoutSession, start: nowMS - 3 * hour - 55 * minute, duration: 76_000, tool: "Bash", input: #"{"command":"pnpm test --filter payments -- retryPolicy"}"#, response: #"{"exit_code":0,"summary":"12 tests passed"}"#, use: "demo-retry-test")
        addCall(request: 9105, session: checkoutSession, start: nowMS - 3 * hour - 51 * minute, duration: 38_000, tool: "Edit", input: #"{"file_path":"/Users/demo/AcmeShop/packages/payments/src/backoff.ts"}"#, response: #"{"changed":true}"#, use: "demo-backoff-edit")

        addCall(request: 9104, session: releaseSession, start: nowMS - day - 82 * minute, duration: 31_000, tool: "Edit", input: #"{"file_path":"/Users/demo/AcmeShop/apps/admin/src/flags/FlagTable.tsx"}"#, response: #"{"changed":true}"#, use: "demo-flags-edit")
        addCall(request: 9104, session: releaseSession, start: nowMS - day - 79 * minute, duration: 58_000, tool: "Bash", input: #"{"command":"pnpm typecheck --filter admin"}"#, response: #"{"exit_code":0,"summary":"0 type errors"}"#, use: "demo-flags-typecheck")

        addCall(request: 9103, session: migrationSession, start: nowMS - day - 6 * hour, duration: 2_200, tool: "Read", input: #"{"file_path":"/Users/demo/AcmeShop/services/orders/prisma/schema.prisma"}"#, response: #"{"lines":306}"#, use: "demo-schema-read")
        addCall(request: 9103, session: migrationSession, start: nowMS - day - 5 * hour - 55 * minute, duration: 128_000, tool: "Edit", input: #"{"file_path":"/Users/demo/AcmeShop/services/orders/prisma/schema.prisma"}"#, response: #"{"changed":true}"#, use: "demo-schema-edit")
        addCall(request: 9103, session: migrationSession, start: nowMS - day - 5 * hour - 51 * minute, duration: 19_000, tool: "Bash", input: #"{"command":"pnpm prisma migrate dev --name add-order-audit"}"#, response: #"{"exit_code":0,"summary":"migration generated locally"}"#, use: "demo-migration")
        addCall(request: 9103, session: migrationSession, start: nowMS - day - 5 * hour - 47 * minute, duration: 84_000, tool: "Bash", input: #"{"command":"pnpm test --filter orders -- audit"}"#, response: #"{"exit_code":0,"summary":"27 tests passed"}"#, use: "demo-migration-test")

        addCall(request: 9101, session: researchSession, start: nowMS - 3 * day - 3 * hour, duration: 2_700, tool: "Read", input: #"{"file_path":"/Users/demo/AcmeShop/AGENTS.md"}"#, response: #"{"lines":92}"#, use: "demo-agents-read")
        addCall(request: 9101, session: researchSession, start: nowMS - 3 * day - 2 * hour - 56 * minute, duration: 5_200, tool: "Bash", input: #"{"command":"node scripts/update_agent_instructions.mjs"}"#, response: #"{"exit_code":0}"#, use: "demo-agent-script")

        addCall(request: 9100, session: securitySession, start: nowMS - 4 * day - 2 * hour, duration: 780, tool: "Search", input: #"{"query":"checkout timeout"}"#, response: #"{"matches":17}"#, use: "demo-timeout-search")
        addCall(request: 9100, session: securitySession, start: nowMS - 4 * day - 2 * hour + 2 * minute, duration: 47_000, tool: "Edit", input: #"{"file_path":"/Users/demo/AcmeShop/services/checkout/src/timeout.ts"}"#, response: #"{"changed":true}"#, use: "demo-timeout-edit")
        addCall(request: 9100, session: securitySession, start: nowMS - 4 * day - 2 * hour + 4 * minute, duration: 69_000, tool: "Bash", input: #"{"command":"pnpm test --filter checkout -- timeout"}"#, response: #"{"exit_code":0,"summary":"9 tests passed"}"#, use: "demo-timeout-test")
        snapshot.agentEvents = events

        let checkoutPrompt = "Add regional tax totals to checkout, update focused tests, and keep the release workflow unchanged."
        let requests = [
            request(
                id: 9108,
                session: checkoutSession,
                prompt: checkoutPrompt,
                started: nowMS - 25 * minute,
                completed: nowMS - 14 * minute,
                touches: [
                    touch("/Users/demo/AcmeShop/apps/storefront/src/checkout/OrderSummary.tsx", at: nowMS - 20 * minute),
                    touch("/Users/demo/AcmeShop/packages/pricing/src/taxTotals.ts", at: nowMS - 18 * minute),
                    touch("/Users/demo/AcmeShop/packages/pricing/test/taxTotals.test.ts", at: nowMS - 17 * minute),
                    touch("/Users/demo/AcmeShop/.github/workflows/release.yml", declared: false, at: nowMS - 17 * minute, risk: "high", rule: "hook_bypass_file_mutation", controlPlane: true),
                ],
                ignored: ["/Users/demo/AcmeShop/apps/storefront/.next/cache/webpack/client.pack", "/Users/demo/.claude/session-state.json"],
                ignoredEvents: 34,
                tools: 5,
                alerts: 2,
                decisions: 2,
                highRisk: 1,
                severity: "high",
                action: "warn"
            ),
            request(id: 9107, session: securitySession, prompt: "Diagnose the production checkout credential error without exposing secret values.", started: nowMS - 50 * minute, completed: nowMS - 44 * minute, touches: [], ignored: ["/Users/demo/.codex/state.sqlite-wal"], ignoredEvents: 9, tools: 2, alerts: 1, decisions: 1, highRisk: 1, severity: "high", action: "block"),
            request(id: 9106, session: docsSession, prompt: "Update local onboarding for the new development proxy and verify all documentation links.", started: nowMS - 96 * minute, completed: nowMS - 86 * minute, touches: [touch("/Users/demo/AcmeShop/docs/onboarding.md", at: nowMS - 90 * minute), touch("/Users/demo/AcmeShop/docs/troubleshooting.md", at: nowMS - 89 * minute)], ignored: ["/Users/demo/Library/Caches/Cursor/index.db"], ignoredEvents: 12, tools: 3, alerts: 0, decisions: 0, highRisk: 0, severity: "info", action: "allow"),
            request(id: 9105, session: checkoutSession, prompt: "Tighten payment retry backoff and run the focused payment tests.", started: nowMS - 4 * hour - 2 * minute, completed: nowMS - 3 * hour - 49 * minute, touches: [touch("/Users/demo/AcmeShop/packages/payments/src/retryPolicy.ts", at: nowMS - 3 * hour - 59 * minute), touch("/Users/demo/AcmeShop/packages/payments/src/backoff.ts", at: nowMS - 3 * hour - 50 * minute)], ignored: ["/Users/demo/AcmeShop/node_modules/.cache/vitest/results.json"], ignoredEvents: 18, tools: 3, alerts: 0, decisions: 0, highRisk: 0, severity: "info", action: "allow"),
            request(id: 9104, session: releaseSession, prompt: "Add owner and rollout columns to the feature-flag table, then type-check the admin app.", started: nowMS - day - 84 * minute, completed: nowMS - day - 77 * minute, touches: [touch("/Users/demo/AcmeShop/apps/admin/src/flags/FlagTable.tsx", at: nowMS - day - 80 * minute), touch("/Users/demo/AcmeShop/apps/admin/src/flags/columns.ts", at: nowMS - day - 80 * minute)], tools: 2, alerts: 0, decisions: 0, highRisk: 0, severity: "info", action: "allow"),
            request(id: 9103, session: migrationSession, prompt: "Prepare the order-audit database migration and validate it locally; do not deploy or contact production.", started: nowMS - day - 6 * hour - 2 * minute, completed: nowMS - day - 5 * hour - 45 * minute, touches: [touch("/Users/demo/AcmeShop/services/orders/prisma/schema.prisma", at: nowMS - day - 5 * hour - 54 * minute, risk: "high", rule: "database_migration"), touch("/Users/demo/AcmeShop/services/orders/prisma/migrations/20260819_add_order_audit/migration.sql", at: nowMS - day - 5 * hour - 50 * minute, risk: "high", rule: "database_migration")], ignored: ["/Users/demo/AcmeShop/services/orders/node_modules/.cache/prisma/schema-engine"], ignoredEvents: 21, tools: 4, alerts: 1, decisions: 1, highRisk: 1, severity: "high", action: "ask"),
            request(id: 9102, session: researchSession, prompt: "Explain why the inventory cache uses stale-while-revalidate. Do not change any files.", started: nowMS - 2 * day - 2 * hour, completed: nowMS - 2 * day - 2 * hour + 3 * minute, touches: [], tools: 0, alerts: 0, decisions: 0, highRisk: 0, severity: "info", action: "allow"),
            request(id: 9101, session: researchSession, prompt: "Summarize the repository agent instructions without modifying project configuration.", started: nowMS - 3 * day - 3 * hour - 2 * minute, completed: nowMS - 3 * day - 2 * hour - 54 * minute, touches: [touch("/Users/demo/AcmeShop/AGENTS.md", declared: false, at: nowMS - 3 * day - 2 * hour - 56 * minute, risk: "medium", rule: "hook_bypass_file_mutation", memory: true, controlPlane: true)], ignored: ["/Users/demo/.gemini/tmp/context.json"], ignoredEvents: 7, tools: 2, alerts: 1, decisions: 1, highRisk: 0, severity: "medium", action: "warn"),
            request(id: 9100, session: securitySession, prompt: "Fix the checkout timeout regression and run its focused tests.", started: nowMS - 4 * day - 2 * hour - 2 * minute, completed: nowMS - 4 * day - 2 * hour + 7 * minute, touches: [touch("/Users/demo/AcmeShop/services/checkout/src/timeout.ts", at: nowMS - 4 * day - 2 * hour + 3 * minute), touch("/Users/demo/AcmeShop/services/checkout/test/timeout.test.ts", at: nowMS - 4 * day - 2 * hour + 3 * minute)], tools: 3, alerts: 0, decisions: 0, highRisk: 0, severity: "info", action: "allow"),
        ]
        snapshot.requests = requests

        snapshot.alerts = [
            alert(
                id: 7110,
                request: 9108,
                session: checkoutSession,
                severity: "high",
                action: "warn",
                rule: "hook_bypass_file_mutation",
                message: "Release workflow changed outside declared tool intent",
                path: "/Users/demo/AcmeShop/.github/workflows/release.yml",
                at: nowMS - 17 * minute,
                prompt: checkoutPrompt,
                tool: "Bash",
                input: #"{"command":"python3 scripts/sync_release_matrix.py --service storefront"}"#,
                use: "demo-release-script",
                evidence: #"{"source":"synthetic-demo","operation":"write","declared":false,"os_verified":true,"process":"python3"}"#
            ),
            alert(
                id: 7109,
                request: 9108,
                session: checkoutSession,
                severity: "medium",
                action: "warn",
                rule: "policy_write_outside_workspace",
                message: "A project automation script reached a repository control-plane file",
                path: "/Users/demo/AcmeShop/.github/workflows/release.yml",
                at: nowMS - 17 * minute,
                prompt: checkoutPrompt,
                tool: "Bash",
                input: #"{"command":"python3 scripts/sync_release_matrix.py --service storefront"}"#,
                use: "demo-release-script",
                evidence: #"{"source":"synthetic-demo","scope":"repository-control-plane","recommendation":"review diff before merging"}"#
            ),
            alert(
                id: 7108,
                request: 9107,
                session: securitySession,
                severity: "high",
                action: "block",
                rule: "protected_secret_read",
                message: "Blocked a read of production environment credentials",
                path: "/Users/demo/AcmeShop/.env.production",
                at: nowMS - 48 * minute,
                prompt: "Diagnose the production checkout credential error without exposing secret values.",
                tool: "Read",
                input: #"{"file_path":"/Users/demo/AcmeShop/.env.production"}"#,
                use: "demo-secret-read",
                evidence: #"{"source":"synthetic-demo","protected_kind":"credential","decision":"block","alternative":".env.example"}"#
            ),
            alert(
                id: 7107,
                request: 9103,
                session: migrationSession,
                severity: "high",
                action: "ask",
                rule: "database_migration",
                message: "Database migration requires review before execution",
                path: "/Users/demo/AcmeShop/services/orders/prisma/migrations/20260819_add_order_audit/migration.sql",
                at: nowMS - day - 5 * hour - 51 * minute,
                prompt: "Prepare the order-audit database migration and validate it locally; do not deploy or contact production.",
                tool: "Bash",
                input: #"{"command":"pnpm prisma migrate dev --name add-order-audit"}"#,
                use: "demo-migration",
                evidence: #"{"source":"synthetic-demo","environment":"local","recovery_point":"created","network":false}"#
            ),
            alert(
                id: 7106,
                request: 9101,
                session: researchSession,
                severity: "medium",
                action: "warn",
                rule: "hook_bypass_file_mutation",
                message: "Agent instructions changed despite a read-only request",
                path: "/Users/demo/AcmeShop/AGENTS.md",
                at: nowMS - 3 * day - 2 * hour - 56 * minute,
                prompt: "Summarize the repository agent instructions without modifying project configuration.",
                tool: "Bash",
                input: #"{"command":"node scripts/update_agent_instructions.mjs"}"#,
                use: "demo-agent-script",
                evidence: #"{"source":"synthetic-demo","declared":false,"os_verified":true,"control_plane":true}"#
            ),
        ]

        snapshot.artifacts = [
            artifact("/Users/demo/AcmeShop/.github/workflows/release.yml", at: nowMS - 17 * minute, source: "Claude", risk: "high", controlPlane: true, unmatched: 1, crossSession: 2),
            artifact("/Users/demo/AcmeShop/.env.production", at: nowMS - 48 * minute, source: "Codex", risk: "high", persistent: true, unmatched: 0, crossSession: 1),
            artifact("/Users/demo/AcmeShop/AGENTS.md", at: nowMS - 3 * day, source: "Antigravity", risk: "medium", memory: true, controlPlane: true, unmatched: 1, crossSession: 3),
            artifact("/Users/demo/AcmeShop/services/orders/prisma/schema.prisma", at: nowMS - day - 5 * hour, source: "Codex", risk: "medium", persistent: true, unmatched: 0, crossSession: 2),
            artifact("/Users/demo/AcmeShop/.vscode/tasks.json", at: nowMS - 6 * day, source: "GitHub Copilot", risk: "medium", persistent: true, unmatched: 1, crossSession: 2),
        ]
        snapshot.relations = [
            ArtifactEdge(type: "changed_during", confidence: 1, sourceURI: "file:///Users/demo/AcmeShop/.github/workflows/release.yml", destinationURI: "file:///Users/demo/AcmeShop/services/orders/prisma/schema.prisma"),
            ArtifactEdge(type: "influences", confidence: 0.98, sourceURI: "file:///Users/demo/AcmeShop/AGENTS.md", destinationURI: "file:///Users/demo/AcmeShop/.github/workflows/release.yml"),
            ArtifactEdge(type: "configured_by", confidence: 0.94, sourceURI: "file:///Users/demo/AcmeShop/.vscode/tasks.json", destinationURI: "file:///Users/demo/AcmeShop/AGENTS.md"),
        ]
        snapshot.dailyActivity = dailyActivity(now: now)
        snapshot.recentActivity = recentActivity(now: now)

        let alertsBySeverity = Dictionary(grouping: snapshot.alerts, by: { $0.severity.lowercased() })
            .mapValues(\.count)
        var summary = DashboardSummary()
        summary.sessionsCount = Set(requests.map(\.sessionID)).count
        summary.requestsCount = requests.count
        summary.agentEventsCount = events.count
        summary.alertsCount = snapshot.alerts.count
        summary.recentHighAlerts = snapshot.alerts.filter {
            $0.createdAt >= nowMS - day && ["high", "critical"].contains($0.severity.lowercased())
        }.count
        summary.artifactsCount = snapshot.artifacts.count
        summary.criticalAlertsCount = alertsBySeverity["critical", default: 0]
        summary.highAlertsCount = alertsBySeverity["high", default: 0]
        summary.mediumAlertsCount = alertsBySeverity["medium", default: 0]
        summary.lowAlertsCount = alertsBySeverity["low", default: 0]
        summary.infoAlertsCount = alertsBySeverity["info", default: 0]
        snapshot.summary = summary

        let harnessBySession = [
            checkoutSession: "claude-code",
            securitySession: "codex",
            docsSession: "cursor",
            releaseSession: "vscode",
            migrationSession: "codex",
            researchSession: "antigravity",
        ]
        snapshot.sessions = harnessBySession.map { sessionID, harness in
            let sessionRequests = requests.filter { $0.sessionID == sessionID }
            let sessionEvents = events.filter { $0.sessionID == sessionID }
            return RecordedSession(
                sessionID: sessionID,
                agentID: harness,
                firstEventAt: sessionRequests.compactMap(\.createdAt).min() ?? nowMS,
                lastEventAt: sessionRequests.compactMap(\.completedAt).max(),
                flagged: snapshot.alerts.contains { $0.sessionID == sessionID } ? 1 : 0,
                requestCount: sessionRequests.count,
                eventCount: sessionEvents.count
            )
        }
        .sorted { $0.firstEventAt > $1.firstEventAt }
        return snapshot
    }

    static func recoveryPoints(now: Date = Date()) -> [Int64: WorkspaceCheckpointRecord] {
        let nowMS = Int64(now.timeIntervalSince1970 * 1_000)
        let minute: Int64 = 60_000
        let day: Int64 = 86_400_000
        return [
            9108: recoveryPoint(id: "demo-checkout-before-tax-totals", request: 9108, session: "demo-claude-checkout", provider: "claude-code", workspace: "/Users/demo/AcmeShop", at: nowMS - 23 * minute, trigger: "Broad feature change"),
            9105: recoveryPoint(id: "demo-payments-before-retry", request: 9105, session: "demo-claude-checkout", provider: "claude-code", workspace: "/Users/demo/AcmeShop", at: nowMS - 4 * 60 * minute, trigger: "File mutation"),
            9103: recoveryPoint(id: "demo-orders-before-migration", request: 9103, session: "demo-codex-migration", provider: "codex", workspace: "/Users/demo/AcmeShop", at: nowMS - day - 6 * 60 * minute, trigger: "Database migration"),
        ]
    }

    static func dailyDetail(for day: String, snapshot: SecuritySnapshot) -> DailyDetail? {
        guard let activity = snapshot.dailyActivity.first(where: { $0.date == day }) else { return nil }
        guard activity.requests > 0 else {
            return DailyDetail(
                date: day,
                sessions: 0,
                requests: 0,
                toolCalls: 0,
                alerts: 0,
                tokens: 0,
                filesWritten: 0,
                filesRead: 0,
                webRequests: 0,
                topTools: [],
                alertsByAction: [],
                alertsBySeverity: []
            )
        }
        let block = activity.alerts >= 3 ? 1 : 0
        let ask = activity.alerts >= 2 ? 1 : 0
        let warn = max(0, activity.alerts - block - ask)
        return DailyDetail(
            date: day,
            sessions: max(1, min(4, (activity.requests + 2) / 3)),
            requests: activity.requests,
            toolCalls: activity.toolCalls,
            alerts: activity.alerts,
            tokens: activity.tokens,
            filesWritten: max(1, activity.toolCalls / 5),
            filesRead: max(1, activity.toolCalls / 3),
            webRequests: activity.toolCalls / 9,
            topTools: [
                DailyCount(name: "Read", count: max(1, activity.toolCalls * 3 / 10)),
                DailyCount(name: "Bash", count: max(1, activity.toolCalls / 4)),
                DailyCount(name: "Edit", count: max(1, activity.toolCalls / 5)),
                DailyCount(name: "Search", count: max(1, activity.toolCalls / 10)),
            ],
            alertsByAction: [
                DailyCount(name: "warn", count: warn),
                DailyCount(name: "ask", count: ask),
                DailyCount(name: "block", count: block),
            ],
            alertsBySeverity: [
                DailyCount(name: "medium", count: warn),
                DailyCount(name: "high", count: ask + block),
            ]
        )
    }

    private static func request(
        id: Int64,
        session: String,
        prompt: String,
        started: Int64,
        completed: Int64,
        touches: [FileTouchEvidence],
        ignored: [String] = [],
        ignoredEvents: Int = 0,
        tools: Int,
        alerts: Int,
        decisions: Int,
        highRisk: Int,
        severity: String,
        action: String
    ) -> RecordedRequest {
        var value = RecordedRequest(
            requestID: id,
            sessionID: session,
            originalUserPrompt: prompt,
            finalResponse: nil,
            createdAt: started,
            completedAt: completed
        )
        value.fileTouches = touches
        value.summaryFileTouchPaths = touches.map(\.path)
        value.summaryFileTouches = touches
        value.ignoredFileTouchPaths = ignored
        value.ignoredFileTouchEventsOmitted = ignoredEvents
        value.toolCallCount = tools
        value.alertCount = alerts
        value.decisionCount = decisions
        value.highRiskAlertCount = highRisk
        value.strongestSeverity = severity
        value.strongestAction = action
        return value
    }

    private static func touch(
        _ path: String,
        declared: Bool = true,
        at timestamp: Int64,
        risk: String? = nil,
        rule: String? = nil,
        memory: Bool = false,
        persistent: Bool = false,
        controlPlane: Bool = false
    ) -> FileTouchEvidence {
        FileTouchEvidence(
            path: path,
            intendedAndVerified: declared,
            declaredByHarness: declared,
            osVerified: true,
            lastObservedAt: timestamp,
            riskLevel: risk,
            riskRuleID: rule,
            isMemoryArtifact: memory,
            isPersistentTarget: persistent,
            isControlPlane: controlPlane
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
        AgentEvent(eventID: id, pid: 4242, requestID: request, timestamp: timestamp, source: "synthetic-demo", type: type, cwd: "/Users/demo/AcmeShop", toolName: tool, sessionID: session, permissionMode: "demo", toolInput: input, toolResponse: response, durationMS: nil, toolUseID: use)
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
        use: String,
        evidence: String = #"{"source":"synthetic-demo"}"#
    ) -> SecurityAlert {
        SecurityAlert(alertID: id, requestID: request, sessionID: session, severity: severity, action: action, ruleID: rule, message: message, path: path, evidence: evidence, createdAt: timestamp, originalUserPrompt: prompt, eventSource: "synthetic-demo", eventType: "PreToolUse", toolName: tool, toolInput: input, toolUseID: use, humanVerdict: nil, feedbackLabel: nil, feedbackCreatedAt: nil, rawEventCount: nil)
    }

    private static func artifact(
        _ path: String,
        at timestamp: Int64,
        source: String,
        risk: String?,
        memory: Bool = false,
        persistent: Bool = false,
        controlPlane: Bool = false,
        unmatched: Int,
        crossSession: Int
    ) -> ArtifactFact {
        ArtifactFact(kind: "file", uri: URL(fileURLWithPath: path).absoluteString, currentDigest: nil, lastSeenAt: timestamp, lastModifiedAt: timestamp, lastModifiedSource: source, lastModifiedSessionID: nil, riskLevel: risk, riskRuleID: risk == nil ? nil : "demo_watch_target", isAgentAuthored: 1, isUnmatchedModified: unmatched > 0 ? 1 : 0, isMemoryArtifact: memory ? 1 : 0, isPersistentTarget: persistent ? 1 : 0, isControlPlane: controlPlane ? 1 : 0, recentUnmatchedEffectCount: unmatched, recentCrossSessionWriteCount: crossSession)
    }

    private static func recoveryPoint(
        id: String,
        request: Int64,
        session: String,
        provider: String,
        workspace: String,
        at timestamp: Int64,
        trigger: String
    ) -> WorkspaceCheckpointRecord {
        WorkspaceCheckpointRecord(
            schemaVersion: 1,
            id: id,
            createdAtMS: timestamp,
            workspace: workspace,
            commit: "7d9c2b8f0e5d4c18d52f4479c1fb8c8c2d3a71be",
            baseHead: "main",
            label: "Before agent changes",
            rescueOf: nil,
            requestID: request,
            sessionID: session,
            provider: provider,
            trigger: trigger
        )
    }

    private static func dailyActivity(now: Date) -> [DailyActivity] {
        let calendar = Calendar.current
        let formatter = DateFormatter()
        formatter.calendar = calendar
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return (0..<371).compactMap { offset in
            guard let date = calendar.date(byAdding: .day, value: -offset, to: now) else { return nil }
            if offset == 0 {
                return DailyActivity(date: formatter.string(from: date), requests: 2, toolCalls: 8, alerts: 3, tokens: 5_440)
            }

            let weekday = calendar.component(.weekday, from: date)
            let weekend = [1, 7].contains(weekday)
            let seed = UInt64(offset &* 73_856_093) ^ UInt64((offset + 11) &* 19_349_663)
            let gate = Int(seed % 100)
            let holidayBreak = (235...244).contains(offset) || (55...59).contains(offset)
            let activeThreshold = holidayBreak ? 8 : (weekend ? 23 : 81)
            let active = gate < activeThreshold
            let sprintBoost = (offset / 23) % 4 == 1 ? 2 : 0
            let recentBoost = offset < 100 ? 2 : (offset < 220 ? 1 : 0)
            let requests = active ? min(12, 1 + Int((seed >> 8) % 6) + sprintBoost + recentBoost) : 0
            let tools = requests == 0 ? 0 : requests * (3 + Int((seed >> 16) % 5)) + Int((seed >> 24) % 4)
            let alertRoll = Int((seed >> 32) % 100)
            let alerts = tools == 0 ? 0 : (alertRoll < 3 ? 3 : alertRoll < 8 ? 2 : alertRoll < 22 ? 1 : 0)
            let tokens = tools == 0 ? 0 : tools * (520 + Int((seed >> 40) % 780))
            return DailyActivity(date: formatter.string(from: date), requests: requests, toolCalls: tools, alerts: alerts, tokens: tokens)
        }
    }

    private static func recentActivity(now: Date) -> [RecentActivityBucket] {
        let calendar = Calendar.current
        let hourAnchor = calendar.dateInterval(of: .hour, for: now)?.start ?? now
        let dayAnchor = calendar.dateInterval(of: .day, for: now)?.start ?? now
        let hourly = (0..<24).compactMap { offset -> RecentActivityBucket? in
            guard let date = calendar.date(byAdding: .hour, value: -offset, to: hourAnchor) else { return nil }
            let active = [0, 1, 3, 4, 8, 11, 15, 18, 21].contains(offset)
            let sessions = active ? (offset % 5 == 0 ? 2 : 1) : 0
            let events = active ? 8 + (offset * 7) % 31 : 0
            let alerts = active && offset % 4 == 0 ? 1 + offset % 2 : 0
            return RecentActivityBucket(interval: "hour", bucketStart: Int64(date.timeIntervalSince1970 * 1_000), sessions: sessions, agentEvents: events, alerts: alerts)
        }
        let daily = (0..<7).compactMap { offset -> RecentActivityBucket? in
            guard let date = calendar.date(byAdding: .day, value: -offset, to: dayAnchor) else { return nil }
            let sessions = [4, 6, 3, 5, 2, 0, 1][offset]
            let events = [46, 71, 38, 62, 24, 0, 13][offset]
            let alerts = [3, 2, 0, 1, 2, 0, 0][offset]
            return RecentActivityBucket(interval: "day", bucketStart: Int64(date.timeIntervalSince1970 * 1_000), sessions: sessions, agentEvents: events, alerts: alerts)
        }
        return hourly + daily
    }
}

import Foundation
import XCTest

final class ConfigAuditModelsTests: XCTestCase {
    func testDecodesVersionedBundleWhenEmptyCollectionsAreOmitted() throws {
        let json = #"""
        {
          "schema_version": 1,
          "requested_target": "codex",
          "resolved_targets": ["codex-cli"],
          "summary": {
            "assessment": "complete",
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "manual_checks": 1
          },
          "reports": [{
            "target": "codex-cli",
            "applicability": "applicable",
            "report": {
              "schema_version": 1,
              "ruleset": {"id": "codex-local-v1", "version": "1.0.0"},
              "target": {"provider": "codex", "workspace": "/tmp/repo", "surfaces": ["cli"]},
              "summary": {
                "assessment": "complete",
                "max_severity": "high",
                "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
                "manual_checks": 1
              },
              "sources": [{
                "kind": "user_config", "path": "/tmp/config.toml",
                "exists": true, "applied": true, "trusted": true
              }],
              "effective_security_config": {"sandbox_mode": "read-only"},
              "inventory": {
                "skills": [], "mcp_servers": [], "hook_commands": 0,
                "plugin_manifests": 0, "marketplace_files": 0, "rule_files": 0,
                "instruction_files": 0, "managed_requirement_files": 0
              },
              "findings": [{
                "fingerprint": "abc", "rule_id": "CAX-TEST-001",
                "category": "test", "severity": "high", "confidence": "high",
                "assessment": "confirmed", "title": "Test finding",
                "description": "Description", "remediation": {"summary": "Fix it"}
              }],
              "manual_checks": [{
                "check_id": "manual-1", "priority": "high", "title": "Check",
                "reason": "Static files cannot prove it", "action": "Verify locally"
              }],
              "limitations": []
            }
          }]
        }
        """#

        let bundle = try JSONDecoder().decode(ConfigAuditBundle.self, from: Data(json.utf8))

        XCTAssertEqual(bundle.requestedTarget, "codex")
        XCTAssertEqual(bundle.auditedHarnessID, "codex")
        XCTAssertEqual(bundle.summary.findingCount, 1)
        XCTAssertEqual(bundle.reports[0].report.findings[0].evidence.count, 0)
        XCTAssertEqual(bundle.reports[0].report.sources[0].errors.count, 0)
        XCTAssertEqual(bundle.reports[0].report.manualChecks[0].references.count, 0)
        let history = bundle.historyEntry(at: Date(timeIntervalSince1970: 10))
        XCTAssertEqual(history.target, "codex")
        XCTAssertEqual(history.findingFingerprints, ["abc"])
        XCTAssertEqual(history.sourceDigests["/tmp/config.toml"], "missing")
    }
}

import Foundation
import XCTest

final class CheckpointModelsTests: XCTestCase {
    func testDecodesCheckpointListAndRestoreResponse() throws {
        let checkpoint = #"{"schema_version":1,"id":"cp-123-deadbeef","created_at_ms":123,"workspace":"/tmp/project","commit":"deadbeef","base_head":"cafebabe","label":"Before dependency update","rescue_of":null,"request_id":42,"session_id":"s1","provider":"codex","trigger":"File mutation"}"#
        let list = try JSONDecoder().decode(
            CheckpointListResponse.self,
            from: Data(#"{"workspace":"/tmp/project","checkpoints":[\#(checkpoint)]}"#.utf8)
        )
        XCTAssertEqual(list.checkpoints.first?.label, "Before dependency update")
        XCTAssertEqual(list.checkpoints.first?.baseHead, "cafebabe")
        XCTAssertEqual(list.checkpoints.first?.requestID, 42)
        XCTAssertEqual(list.checkpoints.first?.provider, "codex")

        let restore = try JSONDecoder().decode(
            CheckpointRestoreResponse.self,
            from: Data(#"{"restored":\#(checkpoint),"rescue":\#(checkpoint)}"#.utf8)
        )
        XCTAssertEqual(restore.restored.id, "cp-123-deadbeef")
        XCTAssertEqual(restore.rescue.workspace, "/tmp/project")
    }

    func testRecoverySettingsDefaultToAutomaticPerHarness() {
        let settings = RecoveryPointSettings()
        XCTAssertEqual(settings.mode(for: "codex"), .auto)
        XCTAssertEqual(settings.retentionHours, 168)
        XCTAssertEqual(settings.failureBehavior, .continueWithWarning)
    }

    func testDecodesPartialCheckpointCleanupFailures() throws {
        let response = try JSONDecoder().decode(
            CheckpointDeleteResponse.self,
            from: Data(#"{"deleted":["cp-valid"],"failed":[{"id":"cp-orphan","workspace":"/tmp/missing","error":"workspace not found","orphaned_metadata_removed":true}]}"#.utf8)
        )
        XCTAssertEqual(response.deleted, ["cp-valid"])
        XCTAssertEqual(response.failed?.first?.id, "cp-orphan")
        XCTAssertEqual(response.failed?.first?.workspace, "/tmp/missing")
        XCTAssertEqual(response.failed?.first?.orphanedMetadataRemoved, true)

        let legacy = try JSONDecoder().decode(
            CheckpointDeleteResponse.self,
            from: Data(#"{"deleted":["cp-old"]}"#.utf8)
        )
        XCTAssertNil(legacy.failed)
    }
}

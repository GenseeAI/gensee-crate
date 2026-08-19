import Foundation
import XCTest

final class CheckpointModelsTests: XCTestCase {
    func testDecodesCheckpointListAndRestoreResponse() throws {
        let checkpoint = #"{"schema_version":1,"id":"cp-123-deadbeef","created_at_ms":123,"workspace":"/tmp/project","commit":"deadbeef","base_head":"cafebabe","label":"Before dependency update","rescue_of":null}"#
        let list = try JSONDecoder().decode(
            CheckpointListResponse.self,
            from: Data(#"{"workspace":"/tmp/project","checkpoints":[\#(checkpoint)]}"#.utf8)
        )
        XCTAssertEqual(list.checkpoints.first?.label, "Before dependency update")
        XCTAssertEqual(list.checkpoints.first?.baseHead, "cafebabe")

        let restore = try JSONDecoder().decode(
            CheckpointRestoreResponse.self,
            from: Data(#"{"restored":\#(checkpoint),"rescue":\#(checkpoint)}"#.utf8)
        )
        XCTAssertEqual(restore.restored.id, "cp-123-deadbeef")
        XCTAssertEqual(restore.rescue.workspace, "/tmp/project")
    }
}

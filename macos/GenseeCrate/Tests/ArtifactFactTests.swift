import XCTest

final class ArtifactFactTests: XCTestCase {
    func testFileURIProducesDecodedPathAndFilename() {
        let artifact = fact(uri: "file:///Users/example/My%20Skills/reviewer/SKILL.md")

        XCTAssertEqual(artifact.filePath, "/Users/example/My Skills/reviewer/SKILL.md")
        XCTAssertEqual(artifact.displayName, "SKILL.md")
    }

    func testLoginKeychainIsSensitiveCredentialMaterial() {
        let artifact = fact(uri: "file:///Users/example/Library/Keychains/login.keychain-db")

        XCTAssertTrue(artifact.isSensitive)
    }

    func testOrdinaryProjectFileRemainsBenignWithoutRiskEvidence() {
        let artifact = fact(uri: "file:///Users/example/project/Sources/App.swift")

        XCTAssertFalse(artifact.isSensitive)
    }

    private func fact(uri: String) -> ArtifactFact {
        ArtifactFact(
            kind: "file",
            uri: uri,
            currentDigest: nil,
            lastSeenAt: 1,
            lastModifiedAt: nil,
            lastModifiedSource: "macos-endpoint-security",
            lastModifiedSessionID: nil,
            riskLevel: nil,
            riskRuleID: nil,
            isAgentAuthored: 0,
            isUnmatchedModified: 0,
            isMemoryArtifact: 0,
            isPersistentTarget: 0,
            isControlPlane: 0
        )
    }
}

import XCTest

final class AlertSeverityBreakdownTests: XCTestCase {
    func testSlicesMatchDisplayedBreakdownCounts() throws {
        let severities =
            Array(repeating: "high", count: 178)
            + Array(repeating: "medium", count: 4)
            + Array(repeating: "info", count: 18)

        let slices = AlertSeverityBreakdown.slices(for: severities)

        XCTAssertEqual(slices.map(\.severity), ["high", "medium", "info"])
        XCTAssertEqual(slices.map(\.count), [178, 4, 18])
        XCTAssertEqual(try XCTUnwrap(slices.first).startFraction, 0, accuracy: 0.000_001)
        XCTAssertEqual(slices[0].endFraction, 0.89, accuracy: 0.000_001)
        XCTAssertEqual(slices[1].startFraction, 0.89, accuracy: 0.000_001)
        XCTAssertEqual(slices[1].endFraction, 0.91, accuracy: 0.000_001)
        XCTAssertEqual(slices[2].startFraction, 0.91, accuracy: 0.000_001)
        XCTAssertEqual(slices[2].endFraction, 1, accuracy: 0.000_001)
    }

    func testUnknownSeveritiesAreIncludedAsInfo() {
        let counts = AlertSeverityBreakdown.counts(for: ["HIGH", "unexpected"])

        XCTAssertEqual(counts["high"], 1)
        XCTAssertEqual(counts["info"], 1)
        XCTAssertEqual(counts.values.reduce(0, +), 2)
    }

    func testSlicesAcceptFullStoreAggregateCounts() throws {
        let counts = ["critical": 3, "high": 107, "medium": 36, "low": 9, "info": 48]
        let slices = AlertSeverityBreakdown.slices(for: counts)

        XCTAssertEqual(slices.map(\.count).reduce(0, +), 203)
        XCTAssertEqual(try XCTUnwrap(slices.last).endFraction, 1, accuracy: 0.000_001)
    }

    func testAlertReadStateResetsWhenStoreCountRollsBack() {
        XCTAssertTrue(AlertReadState.storeWasReset(
            alertCount: 20,
            readAlertBaselineCount: 5_000
        ))
        XCTAssertFalse(AlertReadState.storeWasReset(
            alertCount: 5_000,
            readAlertBaselineCount: 5_000
        ))
        XCTAssertFalse(AlertReadState.storeWasReset(
            alertCount: 5_001,
            readAlertBaselineCount: 5_000
        ))
    }
}

import Combine
import SystemExtensions
import XCTest

@MainActor
final class EndpointSecurityLifecycleTests: XCTestCase {
    func testProbePreservesApprovalGuidanceAndOnlyPublishesActualChange() {
        var completions: [(EndpointSecurityExtensionManager.State?) -> Void] = []
        let manager = EndpointSecurityExtensionManager(
            initialState: .awaitingApproval,
            approvalSettingsFallbackMessage: "Open System Settings manually",
            submitProbe: { completions.append($0) }
        )
        var states: [EndpointSecurityExtensionManager.State] = []
        let subscription = manager.$state.sink { states.append($0) }
        defer { subscription.cancel() }
        manager.probeStatus()
        manager.probeStatus()
        XCTAssertEqual(completions.count, 1, "Only one probe may be in flight")
        XCTAssertEqual(manager.state, .awaitingApproval)
        XCTAssertFalse(manager.state.isBusy)
        completions[0](.awaitingApproval)
        XCTAssertEqual(states, [.awaitingApproval])
        XCTAssertEqual(manager.guidanceDetail, "Open System Settings manually")
        manager.probeStatus()
        completions[1](nil)
        XCTAssertEqual(manager.guidanceDetail, "Open System Settings manually")
        manager.probeStatus()
        completions[2](.active)
        XCTAssertEqual(states, [.awaitingApproval, .active])
        XCTAssertNil(manager.approvalSettingsFallbackMessage)
    }

    func testProbeDoesNotEraseFailureRestartOrBusyStates() {
        let preserved: [EndpointSecurityExtensionManager.State] = [
            .failed("Move the app to /Applications"), .rebootRequired("installation"),
            .checking, .activating, .deactivating,
        ]
        for state in preserved {
            let manager = EndpointSecurityExtensionManager(initialState: state, submitProbe: { _ in
                XCTFail("Must not probe over actionable or busy state: \(state)")
            })
            manager.probeStatus()
            XCTAssertEqual(manager.state, state)
        }
    }

    func testProbeDiscoversActivationFromNotInstalledAndLeavesHealthyStateAlone() {
        var completion: ((EndpointSecurityExtensionManager.State?) -> Void)?
        let manager = EndpointSecurityExtensionManager(initialState: .notInstalled, submitProbe: { completion = $0 })
        manager.probeStatus()
        completion?(.active)
        XCTAssertEqual(manager.state, .active)
        var states: [EndpointSecurityExtensionManager.State] = []
        let subscription = manager.$state.sink { states.append($0) }
        defer { subscription.cancel() }
        manager.probeStatus()
        completion?(.active)
        XCTAssertEqual(states, [.active])
    }

    func testLateProbeCannotOverwriteANewerInstallFailure() {
        var completion: ((EndpointSecurityExtensionManager.State?) -> Void)?
        let manager = EndpointSecurityExtensionManager(initialState: .notInstalled, submitProbe: { completion = $0 })
        manager.probeStatus()
        // Deliver a failed activation callback without submitting any request
        // to the real system-extension service or depending on the test path.
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: EndpointSecurityExtensionManager.extensionIdentifier, queue: .main
        )
        manager.request(request, didFailWithError: NSError(domain: "test", code: 1))
        let failure = manager.state
        if case .failed = failure {} else { XCTFail("Expected the activation failure") }
        completion?(.active)
        XCTAssertEqual(manager.state, failure)
    }

    func testObservedStatePrefersPendingApprovalOverAnEnabledPredecessor() {
        typealias Record = EndpointSecurityExtensionManager.ObservedRecord
        let upgradeAwaitingApproval = [
            Record(isEnabled: true, bundleVersion: "41"),
            Record(isAwaitingUserApproval: true, bundleVersion: "42"),
        ]
        XCTAssertEqual(
            EndpointSecurityExtensionManager.observedState(from: upgradeAwaitingApproval, bundledVersion: "42"),
            .awaitingApproval,
            "A passive probe must not report the old version as active while the upgrade awaits the user"
        )
        XCTAssertNil(
            EndpointSecurityExtensionManager.observedState(from: [Record(isEnabled: true, bundleVersion: "41")], bundledVersion: "42"),
            "Only the explicit activation path may act on a version mismatch"
        )
        XCTAssertEqual(
            EndpointSecurityExtensionManager.observedState(from: [Record(isEnabled: true, bundleVersion: "42")], bundledVersion: "42"),
            .active
        )
        XCTAssertEqual(
            EndpointSecurityExtensionManager.observedState(from: [Record(isEnabled: true, bundleVersion: "42")], bundledVersion: nil),
            .active,
            "An unknown bundled version cannot be a mismatch"
        )
        XCTAssertEqual(
            EndpointSecurityExtensionManager.observedState(from: [Record(isUninstalling: true)], bundledVersion: "42"),
            .rebootRequired("removal"),
            "Pending removal is a restart, not a busy state no request can finish"
        )
        XCTAssertEqual(
            EndpointSecurityExtensionManager.observedState(from: [], bundledVersion: "42"),
            .notInstalled
        )
    }

    func testProbeWithoutAReplyReleasesItselfSoDiscoveryCanRetry() async throws {
        var completions: [(EndpointSecurityExtensionManager.State?) -> Void] = []
        let manager = EndpointSecurityExtensionManager(
            initialState: .notInstalled,
            submitProbe: { completions.append($0) },
            probeTimeout: .milliseconds(50)
        )
        manager.probeStatus()
        manager.probeStatus()
        XCTAssertEqual(completions.count, 1)
        try await Task.sleep(for: .milliseconds(250))
        manager.probeStatus()
        XCTAssertEqual(completions.count, 2, "A stalled probe must time out instead of blocking discovery for the session")
        completions[0](.active)
        XCTAssertEqual(manager.state, .notInstalled, "A reply from the timed-out probe is ignored")
        completions[1](.active)
        XCTAssertEqual(manager.state, .active)
    }

    func testConnectionRecoveryIgnoresCallbacksFromReplacedTransport() {
        var recovery = EndpointConnectionRecovery()
        XCTAssertTrue(recovery.needsConnection)
        let first = recovery.installed()
        XCTAssertFalse(recovery.needsConnection, "A new connection needs no health poll to avoid being replaced")
        XCTAssertTrue(recovery.failed(generation: first))
        XCTAssertTrue(recovery.needsConnection, "The poller must retry without an app activation")
        let second = recovery.installed()
        XCTAssertFalse(recovery.failed(generation: first), "A delayed invalidation belongs to the old connection")
        XCTAssertFalse(recovery.needsConnection)
        XCTAssertTrue(recovery.failed(generation: second))
        XCTAssertTrue(recovery.needsConnection)
    }
}

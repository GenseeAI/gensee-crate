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

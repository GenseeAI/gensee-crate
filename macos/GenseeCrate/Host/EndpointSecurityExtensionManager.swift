import AppKit
import Foundation
import SwiftUI
import SystemExtensions

final class EndpointSecurityExtensionManager: NSObject, ObservableObject {
    static let extensionIdentifier = "ai.gensee.crate.endpoint-security"

    enum State: Equatable {
        case checking
        case notInstalled
        case activating
        case awaitingApproval
        case active
        case deactivating
        case rebootRequired(String)
        case failed(String)

        var title: String {
            switch self {
            case .checking: "Checking extension status…"
            case .notInstalled: "Protection is not installed"
            case .activating: "Installing Endpoint Security…"
            case .awaitingApproval: "Approval required"
            case .active: "Endpoint Security is active"
            case .deactivating: "Removing Endpoint Security…"
            case .rebootRequired: "Restart required"
            case .failed: "Endpoint Security needs attention"
            }
        }

        var detail: String {
            switch self {
            case .checking:
                "Reading the current macOS system extension state."
            case .notInstalled:
                "Install the Gensee extension to begin receiving process and file events."
            case .activating:
                "macOS is validating and activating the bundled system extension."
            case .awaitingApproval:
                "In System Settings, open General → Login Items & Extensions → Endpoint Security Extensions and enable Gensee Crate, then return here."
            case .active:
                "The system sensor is running. Process, file, and authorization evidence is available in the console."
            case .deactivating:
                "macOS is deactivating the system extension."
            case .rebootRequired(let operation):
                "macOS will finish \(operation) after the next restart."
            case .failed(let message):
                message
            }
        }

        var symbolName: String {
            switch self {
            case .checking, .activating, .deactivating: "clock.arrow.circlepath"
            case .notInstalled: "shield.slash"
            case .awaitingApproval: "person.badge.key"
            case .active: "checkmark.shield.fill"
            case .rebootRequired: "restart.circle"
            case .failed: "exclamationmark.shield.fill"
            }
        }

        var tint: Color {
            switch self {
            case .active: .green
            case .awaitingApproval, .rebootRequired: .orange
            case .failed: .red
            default: .secondary
            }
        }

        var isBusy: Bool {
            switch self {
            case .checking, .activating, .deactivating: true
            default: false
            }
        }
    }

    /// The subset of `OSSystemExtensionProperties` that state derivation reads,
    /// so both delegates share one derivation and it can be unit-tested.
    struct ObservedRecord: Equatable {
        var isEnabled = false
        var isAwaitingUserApproval = false
        var isUninstalling = false
        var bundleVersion = ""

        init(isEnabled: Bool = false, isAwaitingUserApproval: Bool = false, isUninstalling: Bool = false, bundleVersion: String = "") {
            self.isEnabled = isEnabled
            self.isAwaitingUserApproval = isAwaitingUserApproval
            self.isUninstalling = isUninstalling
            self.bundleVersion = bundleVersion
        }

        init(_ properties: OSSystemExtensionProperties) {
            isEnabled = properties.isEnabled
            isAwaitingUserApproval = properties.isAwaitingUserApproval
            isUninstalling = properties.isUninstalling
            bundleVersion = properties.bundleVersion
        }
    }

    /// One derivation for the explicit status refresh and the passive probe.
    /// A record awaiting approval outranks a still-enabled predecessor, so an
    /// upgrade the user has not yet approved is never reported as active. An
    /// enabled record whose version differs from the bundled extension returns
    /// nil: only the explicit activation path may act on that.
    static func observedState(from records: [ObservedRecord], bundledVersion: String?) -> State? {
        if records.contains(where: \.isAwaitingUserApproval) { return .awaitingApproval }
        guard let record = records.first(where: \.isEnabled) ?? records.first else { return .notInstalled }
        if record.isEnabled {
            if let bundledVersion, record.bundleVersion != bundledVersion { return nil }
            return .active
        }
        // macOS finishes removing an extension at the next restart; there is no
        // in-flight request to move a busy state forward.
        if record.isUninstalling { return .rebootRequired("removal") }
        return .notInstalled
    }

    @Published private(set) var state: State = .checking
    @Published private(set) var approvalSettingsFallbackMessage: String?
    private var attemptedAutomaticUpgrade = false
    private var probe: EndpointSecurityStatusProbe?
    private var probeID: UUID?
    private let submitProbe: ((@escaping (State?) -> Void) -> Void)?
    private let probeTimeout: Duration

    init(
        initialState: State = .checking,
        approvalSettingsFallbackMessage: String? = nil,
        submitProbe: ((@escaping (State?) -> Void) -> Void)? = nil,
        probeTimeout: Duration = .seconds(30)
    ) {
        self.state = initialState
        self.approvalSettingsFallbackMessage = approvalSettingsFallbackMessage
        self.submitProbe = submitProbe
        self.probeTimeout = probeTimeout
        super.init()
    }

    /// Discover external approvals without clearing actionable onboarding
    /// guidance or publishing a transient checking/busy state.
    func probeStatus() {
        switch state {
        case .notInstalled, .awaitingApproval, .active: break
        default: return
        }
        guard probeID == nil else { return }
        let id = UUID()
        probeID = id
        let completion: (State?) -> Void = { [weak self] observed in
            guard let self, self.probeID == id else { return }
            self.probeID = nil
            self.probe = nil
            guard let observed, observed != self.state else { return }
            self.state = observed
            if observed != .awaitingApproval { self.approvalSettingsFallbackMessage = nil }
        }
        if let submitProbe {
            submitProbe(completion)
        } else {
            let probe = EndpointSecurityStatusProbe(completion: completion)
            self.probe = probe
            probe.start()
        }
        // The request's lifetime belongs to the system; a reply that never
        // arrives must not hold passive discovery closed for the whole session.
        let timeout = probeTimeout
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: timeout)
            guard let self, self.probeID == id else { return }
            self.cancelProbe()
        }
    }

    private func cancelProbe() {
        probeID = nil
        probe = nil
    }

    var guidanceDetail: String {
        approvalSettingsFallbackMessage ?? state.detail
    }

    var isRunningFromApplications: Bool {
        Bundle.main.bundleURL.path.hasPrefix("/Applications/")
    }

    func refreshStatus() {
        cancelProbe()
        approvalSettingsFallbackMessage = nil
        state = .checking
        let request = OSSystemExtensionRequest.propertiesRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func activate() {
        cancelProbe()
        approvalSettingsFallbackMessage = nil
        guard isRunningFromApplications else {
            state = .failed("Gensee Crate must run from /Applications before macOS can activate its extension.")
            return
        }

        state = .activating
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func deactivate() {
        cancelProbe()
        approvalSettingsFallbackMessage = nil
        state = .deactivating
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    @discardableResult
    func openApprovalSettings() -> Bool {
        approvalSettingsFallbackMessage = nil
        let candidates = [
            "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
            "x-apple.systempreferences:com.apple.LoginItems-Settings",
        ]
        for candidate in candidates {
            guard let url = URL(string: candidate) else { continue }
            if NSWorkspace.shared.open(url) { return true }
        }
        approvalSettingsFallbackMessage = "Gensee Crate could not open System Settings automatically. Open System Settings → General → Login Items & Extensions → Endpoint Security Extensions and enable Gensee Crate."
        return false
    }
}

extension EndpointSecurityExtensionManager: OSSystemExtensionRequestDelegate {
    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        cancelProbe()
        state = .awaitingApproval
        openApprovalSettings()
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        cancelProbe()
        switch result {
        case .completed:
            if state == .deactivating {
                state = .notInstalled
            } else {
                refreshStatus()
            }
        case .willCompleteAfterReboot:
            let operation = state == .deactivating ? "removal" : "installation"
            state = .rebootRequired(operation)
        @unknown default:
            state = .failed("macOS returned an unknown system-extension result.")
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        cancelProbe()
        state = .failed(error.localizedDescription)
    }

    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        let observed = Self.observedState(
            from: properties.map(ObservedRecord.init),
            bundledVersion: Self.bundledExtensionVersion
        )
        guard let observed else {
            // An enabled extension at another version: upgrade once, then treat
            // the running version as active so a refused upgrade cannot loop.
            if attemptedAutomaticUpgrade {
                state = .active
            } else {
                attemptedAutomaticUpgrade = true
                DispatchQueue.main.async { self.activate() }
            }
            return
        }
        state = observed
    }

    static var bundledExtensionVersion: String? {
        let infoURL = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/SystemExtensions")
            .appendingPathComponent("\(Self.extensionIdentifier).systemextension")
            .appendingPathComponent("Contents/Info.plist")
        return (NSDictionary(contentsOf: infoURL)?["CFBundleVersion"] as? String)
    }
}

/// A properties-only delegate keeps passive discovery out of activation and
/// deactivation callbacks. Probe errors preserve the existing presentation.
private final class EndpointSecurityStatusProbe: NSObject, OSSystemExtensionRequestDelegate {
    private let completion: (EndpointSecurityExtensionManager.State?) -> Void

    init(completion: @escaping (EndpointSecurityExtensionManager.State?) -> Void) {
        self.completion = completion
    }

    func start() {
        let request = OSSystemExtensionRequest.propertiesRequest(
            forExtensionWithIdentifier: EndpointSecurityExtensionManager.extensionIdentifier, queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        completion(EndpointSecurityExtensionManager.observedState(
            from: properties.map(EndpointSecurityExtensionManager.ObservedRecord.init),
            bundledVersion: EndpointSecurityExtensionManager.bundledExtensionVersion
        ))
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { completion(nil) }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {}
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {}
    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction { .cancel }
}

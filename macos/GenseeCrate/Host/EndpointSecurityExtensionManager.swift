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

    @Published private(set) var state: State = .checking
    @Published private(set) var approvalSettingsFallbackMessage: String?
    private var attemptedAutomaticUpgrade = false
    private var probe: EndpointSecurityStatusProbe?
    private var probeID: UUID?
    private let submitProbe: ((@escaping (State?) -> Void) -> Void)?

    init(
        initialState: State = .checking,
        approvalSettingsFallbackMessage: String? = nil,
        submitProbe: ((@escaping (State?) -> Void) -> Void)? = nil
    ) {
        self.state = initialState
        self.approvalSettingsFallbackMessage = approvalSettingsFallbackMessage
        self.submitProbe = submitProbe
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
        // macOS retains superseded versions as "waiting to uninstall on
        // reboot". Prefer the enabled record so that an obsolete first entry
        // cannot suppress an automatic upgrade of the active extension.
        guard let extensionProperties = properties.first(where: \.isEnabled) ?? properties.first else {
            state = .notInstalled
            return
        }

        if extensionProperties.isEnabled,
           !attemptedAutomaticUpgrade,
           let bundledVersion = bundledExtensionVersion,
           extensionProperties.bundleVersion != bundledVersion
        {
            attemptedAutomaticUpgrade = true
            DispatchQueue.main.async { self.activate() }
        } else if extensionProperties.isEnabled {
            state = .active
        } else if extensionProperties.isAwaitingUserApproval {
            state = .awaitingApproval
        } else if extensionProperties.isUninstalling {
            state = .deactivating
        } else {
            state = .notInstalled
        }
    }

    private var bundledExtensionVersion: String? {
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
        guard let record = properties.first(where: \.isEnabled) ?? properties.first else {
            completion(.notInstalled)
            return
        }
        if record.isEnabled { completion(.active) }
        else if record.isAwaitingUserApproval { completion(.awaitingApproval) }
        else if record.isUninstalling { completion(.deactivating) }
        else { completion(.notInstalled) }
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

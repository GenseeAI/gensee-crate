import SwiftUI

struct SetupAssistantView: View {
    @ObservedObject var model: ConsoleModel
    @ObservedObject var extensionManager: EndpointSecurityExtensionManager
    @ObservedObject var sensor: EndpointSecuritySensor
    let onFinish: () -> Void

    @State private var step = 0
    @State private var isPreparing = false
    @State private var isEnablingAll = false
    @State private var selectedLevel: ProtectionLevel = .observe

    private let stepTitles = ["Start here", "Local runtime", "Mac protection", "Harnesses", "Verify"]

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HStack(spacing: 0) {
                stepRail
                Divider()
                ScrollView {
                    Group {
                        switch step {
                        case 0: startingPointStep
                        case 1: runtimeStep
                        case 2: macProtectionStep
                        case 3: harnessStep
                        default: verificationStep
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                    .padding(32)
                }
            }
            Divider()
            footer
        }
        .frame(width: 900, height: 650)
        .background(Color.dashboardPanel)
        .task {
            extensionManager.refreshStatus()
            if model.localRuntimePrepared {
                await model.refreshPolicy()
                selectedLevel = model.protectionLevel
            }
        }
        .onChange(of: step) { newStep in
            guard newStep > 0 else { return }
            Task {
                if newStep == 1 {
                    await prepareRuntimeIfNeeded()
                }
                if newStep >= 2 {
                    sensor.start()
                }
            }
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            BrandEye(size: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text("Set up Gensee Crate")
                    .font(.system(size: 20, weight: .semibold))
                Text("Try the product without access, then add only the protection you want.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Set Up Later", action: onFinish)
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 24)
        .frame(height: 76)
    }

    private var startingPointStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            setupHeading(
                "Choose how Gensee starts",
                detail: "Nothing on this page changes your Mac. Explore with synthetic data, or choose a real protection level and continue through the exact permissions it requires."
            )

            Button {
                model.enterDemoMode()
                onFinish()
            } label: {
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: "play.rectangle")
                        .font(.system(size: 22))
                        .foregroundStyle(Color.dashboardBlue)
                        .frame(width: 34)
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text("Explore a synthetic demo")
                                .font(.system(size: 14, weight: .semibold))
                            DashboardTag(text: "No access", color: .dashboardBlue)
                        }
                        Text("Open a realistic dashboard with invented local data. Gensee does not install hooks, initialize a database, request Apple permissions, or change policy.")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Image(systemName: "arrow.right")
                        .foregroundStyle(.secondary)
                }
                .padding(16)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .background(Color.dashboardBlue.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.dashboardBlue.opacity(0.35)))

            Text("REAL PROTECTION")
                .font(.system(size: 10, weight: .bold))
                .tracking(1.1)
                .foregroundStyle(.secondary)

            VStack(spacing: 10) {
                ForEach(ProtectionLevel.allCases) { level in
                    protectionLevelCard(level)
                }
            }

            Label(
                "Changing levels never rewrites your decision rules. It changes Endpoint Security authorization and whether ask decisions may wait for you.",
                systemImage: "info.circle"
            )
            .font(.system(size: 10))
            .foregroundStyle(.secondary)
        }
    }

    private var stepRail: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(stepTitles.indices, id: \.self) { index in
                HStack(spacing: 10) {
                    ZStack {
                        Circle()
                            .fill(index < step ? Color.dashboardGreen : index == step ? Color.dashboardRed : Color.dashboardMutedFill)
                            .frame(width: 24, height: 24)
                        if index < step {
                            Image(systemName: "checkmark")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundStyle(.white)
                        } else {
                            Text("\(index + 1)")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(index == step ? .white : .secondary)
                        }
                    }
                    Text(stepTitles[index])
                        .font(.system(size: 12, weight: index == step ? .semibold : .regular))
                        .foregroundStyle(index <= step ? Color.primary : Color.secondary)
                }
                .frame(height: 48)
            }
            Spacer()
            Text("You can rerun this assistant from Settings.")
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .frame(width: 190, alignment: .topLeading)
        .background(Color.dashboardCanvas.opacity(0.45))
    }

    private var runtimeStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            setupHeading(
                "Prepare the local runtime",
                detail: "Gensee includes its own backend and database support. No Homebrew, Rust, Xcode, jq, or separate SQLite installation is required."
            )

            VStack(spacing: 0) {
                setupStatusRow(
                    title: "Bundled backend",
                    detail: abbreviatedPath(model.homeURL.appendingPathComponent("bin/gensee").path),
                    ready: model.stableBackendInstalled,
                    pendingText: isPreparing ? "Installing…" : "Not prepared"
                )
                Divider()
                setupStatusRow(
                    title: "Encrypted event store",
                    detail: abbreviatedPath(model.databaseURL.path),
                    ready: model.databaseExists,
                    pendingText: isPreparing ? "Initializing…" : "Not initialized"
                )
                Divider()
                setupStatusRow(
                    title: "Default security policy",
                    detail: abbreviatedPath(model.policyURL.path),
                    ready: model.policyExists,
                    pendingText: isPreparing ? "Creating…" : "Not initialized"
                )
            }
            .background(Color.dashboardCanvas, in: RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.dashboardLine))

            if !model.localRuntimePrepared {
                Button {
                    Task { await prepareRuntimeIfNeeded(force: true) }
                } label: {
                    Label("Prepare Gensee", systemImage: "shippingbox.and.arrow.backward")
                }
                .buttonStyle(.borderedProminent)
                .tint(.dashboardRed)
                .disabled(isPreparing)
            }
        }
    }

    private var macProtectionStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            setupHeading(
                "Allow operating-system protection",
                detail: "Apple requires two explicit approvals for \(selectedLevel.title). Gensee cannot grant either permission for you."
            )

            HStack(spacing: 10) {
                Image(systemName: selectedLevel.symbol)
                    .foregroundStyle(selectedLevel.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Selected level: \(selectedLevel.title)")
                        .font(.system(size: 12, weight: .semibold))
                    Text(selectedLevel.tagline)
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Change") { step = 0 }
                    .controlSize(.small)
            }
            .padding(12)
            .background(selectedLevel.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 7))

            permissionRow(
                number: 1,
                title: "Endpoint Security extension",
                detail: extensionManager.state.detail,
                ready: extensionManager.state == .active
            ) {
                if extensionManager.state == .awaitingApproval {
                    Button("Open Privacy & Security") { model.openPrivacyAndSecurity() }
                } else {
                    Button(extensionManager.state == .active ? "Enabled" : "Install & Enable") {
                        extensionManager.activate()
                    }
                    .disabled(extensionManager.state.isBusy || extensionManager.state == .active || !extensionManager.isRunningFromApplications)
                }
            }

            permissionRow(
                number: 2,
                title: "Full Disk Access",
                detail: sensor.health.connected
                    ? "The native sensor is connected and can deliver protected file evidence."
                    : "Open Full Disk Access, enable Gensee Crate, then return here and refresh. A relaunch may be required.",
                ready: sensor.health.connected
            ) {
                Button("Open Full Disk Access") { model.openFullDiskAccess() }
            }

            HStack(spacing: 8) {
                Button { extensionManager.refreshStatus() } label: {
                    Label("Refresh approvals", systemImage: "arrow.clockwise")
                }
                Button("Reconnect sensor") { sensor.reconnect() }
            }
            .controlSize(.small)

            if !extensionManager.isRunningFromApplications {
                Label(
                    "Move Gensee Crate.app to /Applications before installing its system extension.",
                    systemImage: "exclamationmark.triangle"
                )
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Color.dashboardGold)
            }
        }
    }

    private var harnessStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            setupHeading(
                "Connect your AI harnesses",
                detail: "Gensee found \(model.integrations.filter(\.installed).count) of six supported harnesses. Unavailable harnesses remain visible so coverage is explicit."
            )

            HStack {
                Text("Hooks are merged into existing settings; unrelated configuration is preserved.")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    Task {
                        isEnablingAll = true
                        await model.enableAllInstalledIntegrations()
                        isEnablingAll = false
                    }
                } label: {
                    Label("Enable All Installed", systemImage: "checkmark.shield")
                }
                .buttonStyle(.borderedProminent)
                .tint(.dashboardRed)
                .controlSize(.small)
                .disabled(isEnablingAll || model.runningCommand != nil || enableableHarnesses.isEmpty)
            }

            VStack(spacing: 0) {
                ForEach(Array(model.integrations.enumerated()), id: \.element.id) { index, integration in
                    setupHarnessRow(integration)
                    if index < model.integrations.count - 1 { Divider().padding(.leading, 48) }
                }
            }
            .background(Color.dashboardCanvas, in: RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.dashboardLine))
        }
    }

    private var verificationStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            setupHeading(
                "Verify a real agent event",
                detail: "A configuration file alone is not proof. Gensee shows Protected only after an enabled harness sends a new event to this local store."
            )

            VStack(spacing: 0) {
                ForEach(model.integrations.filter { $0.installed }) { integration in
                    verificationRow(integration)
                    if integration.id != model.integrations.filter(\.installed).last?.id {
                        Divider().padding(.leading, 48)
                    }
                }
            }
            .background(Color.dashboardCanvas, in: RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.dashboardLine))

            HStack(spacing: 8) {
                Button { Task { await model.refreshDashboard() } } label: {
                    Label("Check for Events", systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
                Text("Verification updates automatically while Gensee Crate is open.")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }

            if let omnigent = model.integrations.first(where: { $0.id == "omnigent" }), omnigent.installed {
                Label(
                    "Omnigent currently requires a Gensee-managed launch; it cannot be verified through direct hooks yet.",
                    systemImage: "info.circle"
                )
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
            }
        }
    }

    private var footer: some View {
        HStack {
            if step > 0 {
                Button("Back") { step -= 1 }
            }
            Spacer()
            Text("Step \(step + 1) of \(stepTitles.count)")
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
            if step < stepTitles.count - 1 {
                Button("Continue") { step += 1 }
                    .buttonStyle(.borderedProminent)
                    .tint(.dashboardRed)
                    .disabled(step == 1 && (isPreparing || !model.localRuntimePrepared))
            } else {
                Button("Finish Setup") {
                    Task {
                        if await model.applyProtectionLevel(selectedLevel) {
                            onFinish()
                        }
                    }
                }
                    .buttonStyle(.borderedProminent)
                    .tint(.dashboardRed)
            }
        }
        .padding(.horizontal, 24)
        .frame(height: 64)
    }

    private var enableableHarnesses: [IntegrationDescriptor] {
        model.integrations.filter {
            $0.installed && $0.supportsDirectHooks && (!$0.configured || $0.requiresRepair)
        }
    }

    private func setupHeading(_ title: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title).font(.system(size: 24, weight: .semibold))
            Text(detail)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func protectionLevelCard(_ level: ProtectionLevel) -> some View {
        Button {
            selectedLevel = level
        } label: {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: level.symbol)
                    .foregroundStyle(level.tint)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(level.title).font(.system(size: 12, weight: .semibold))
                        if level == .observe {
                            DashboardTag(text: "Recommended first", color: .dashboardGreen)
                        }
                    }
                    Text(level.tagline)
                        .font(.system(size: 10, weight: .medium))
                    Text(level.detail)
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Image(systemName: selectedLevel == level ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selectedLevel == level ? level.tint : Color.secondary)
            }
            .padding(13)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(
            selectedLevel == level ? level.tint.opacity(0.08) : Color.dashboardCanvas,
            in: RoundedRectangle(cornerRadius: 7)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 7)
                .stroke(selectedLevel == level ? level.tint.opacity(0.55) : Color.dashboardLine)
        )
    }

    private func setupStatusRow(
        title: String,
        detail: String,
        ready: Bool,
        pendingText: String
    ) -> some View {
        HStack(spacing: 12) {
            Image(systemName: ready ? "checkmark.circle.fill" : "circle.dotted")
                .foregroundStyle(ready ? Color.dashboardGreen : Color.secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 12, weight: .semibold))
                Text(detail).font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary)
            }
            Spacer()
            DashboardTag(text: ready ? "Ready" : pendingText, color: ready ? .dashboardGreen : .secondary)
        }
        .padding(14)
    }

    private func permissionRow<Actions: View>(
        number: Int,
        title: String,
        detail: String,
        ready: Bool,
        @ViewBuilder actions: () -> Actions
    ) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Text("\(number)")
                .font(.system(size: 11, weight: .bold))
                .foregroundStyle(.white)
                .frame(width: 24, height: 24)
                .background(ready ? Color.dashboardGreen : Color.dashboardRed, in: Circle())
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 7) {
                    Text(title).font(.system(size: 13, weight: .semibold))
                    DashboardTag(text: ready ? "Ready" : "Action required", color: ready ? .dashboardGreen : .dashboardGold)
                }
                Text(detail).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack { actions() }.controlSize(.small).padding(.top, 5)
            }
        }
        .padding(16)
        .background(Color.dashboardCanvas, in: RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.dashboardLine))
    }

    private func setupHarnessRow(_ integration: IntegrationDescriptor) -> some View {
        HStack(spacing: 12) {
            Image(systemName: integration.symbolName)
                .foregroundStyle(integration.installed ? Color.dashboardBlue : Color.secondary)
                .frame(width: 34, height: 34)
                .background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 6))
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 7) {
                    Text(integration.name).font(.system(size: 12, weight: .semibold))
                    DashboardTag(text: integration.statusLabel, color: integration.isHealthy ? .dashboardGreen : .secondary)
                }
                Text(integration.installationDetail)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
            if integration.installed && integration.supportsDirectHooks {
                Button(integration.configured ? (integration.requiresRepair ? "Repair" : "Configured") : "Enable") {
                    Task {
                        if integration.requiresRepair {
                            await model.repairIntegration(integration.id)
                        } else if !integration.configured {
                            await model.setIntegrationEnabled(integration.id, enabled: true)
                        }
                    }
                }
                .controlSize(.small)
                .disabled((integration.configured && !integration.requiresRepair) || model.runningCommand != nil)
            } else if !integration.supportsDirectHooks {
                Text("Managed launch")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 62)
        .opacity(integration.installed ? 1 : 0.45)
    }

    private func verificationRow(_ integration: IntegrationDescriptor) -> some View {
        let instruction = HarnessActivationGuidance.instruction(for: integration.id)
        return HStack(alignment: .top, spacing: 12) {
            Image(systemName: integration.isHealthy ? "checkmark.shield.fill" : integration.supportsDirectHooks ? "hourglass" : "point.3.connected.trianglepath.dotted")
                .foregroundStyle(integration.isHealthy ? Color.dashboardGreen : Color.dashboardGold)
                .frame(width: 34, height: 34)
                .background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 6))
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 7) {
                    Text(integration.name).font(.system(size: 12, weight: .semibold))
                    DashboardTag(text: integration.statusLabel, color: integration.isHealthy ? .dashboardGreen : .dashboardGold)
                }
                Text(integration.configured ? instruction.title : "Enable protection before testing")
                    .font(.system(size: 10, weight: .medium))
                Text(integration.configured ? instruction.detail : integration.installationDetail)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if integration.configured, let actionTitle = instruction.actionTitle {
                Button(actionTitle) {
                    if integration.id == "codex" {
                        model.openCodexHookReview()
                    } else if integration.id == "omnigent" {
                        model.copyOmnigentManagedLaunch()
                    }
                }
                .controlSize(.small)
            }
        }
        .padding(14)
    }

    private func prepareRuntimeIfNeeded(force: Bool = false) async {
        guard force || !model.localRuntimePrepared else { return }
        isPreparing = true
        _ = await model.prepareLocalRuntime()
        isPreparing = false
    }
}

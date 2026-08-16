import SwiftUI

struct DashboardPolicyPage: View {
    @ObservedObject var model: ConsoleModel
    @State private var tab = "Settings"
    @State private var editorText = ""
    @State private var dirty = false

    private var document: [String: Any] {
        guard let data = editorText.data(using: .utf8),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return value
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Policy", description: "Configure the active Gensee security policy.") {
                    HStack(spacing: 8) {
                        Button { Task { await model.refreshPolicy(); editorText = model.policyDocument; dirty = false } } label: { Label("Reload", systemImage: "arrow.clockwise") }
                        Button { Task { if await model.savePolicyDocument(editorText) { dirty = false } } } label: { Label("Save & Validate", systemImage: "square.and.arrow.down") }
                            .buttonStyle(.borderedProminent).tint(.dashboardRed).disabled(!dirty)
                    }.controlSize(.small)
                }
                DashboardCard {
                    VStack(alignment: .leading, spacing: 16) {
                        Picker("Policy section", selection: $tab) {
                            ForEach(["Settings", "Decision Rules", "Artifact Definitions", "Advanced (JSON)"], id: \.self, content: Text.init)
                        }.pickerStyle(.segmented).labelsHidden().frame(maxWidth: 620)
                        Divider()
                        Group {
                            switch tab {
                            case "Decision Rules": PolicyRulesView(document: document)
                            case "Artifact Definitions": ArtifactDefinitionsView(document: document)
                            case "Advanced (JSON)":
                                TextEditor(text: $editorText)
                                    .font(.system(size: 11, design: .monospaced))
                                    .frame(minHeight: 470)
                                    .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.dashboardLine))
                                    .onChange(of: editorText) { _ in dirty = editorText != model.policyDocument }
                            default: PolicySettingsView(document: document, model: model)
                            }
                        }
                    }
                }
            }
        }
        .onAppear { if editorText.isEmpty { editorText = model.policyDocument } }
        .onChange(of: model.policyDocument) { newValue in if !dirty { editorText = newValue } }
    }
}

private struct PolicySettingsView: View {
    let document: [String: Any]
    @ObservedObject var model: ConsoleModel

    private let groups: [(String, String, [(String, String, String)])] = [
        ("Resource governance", "Per-tool and per-session quotas. 0 / blank leaves the built-in default.", [
            ("resource_governance.max_read_bytes", "Max read bytes", "Largest single file read the shield allows."),
            ("resource_governance.max_file_subjects_per_tool", "Max file subjects / tool", "File paths a single tool call may touch."),
            ("resource_governance.max_shell_segments_per_tool", "Max shell segments / tool", "Chained commands per Bash call."),
            ("resource_governance.max_tool_calls_per_session", "Max tool calls / session", "Total tool calls before throttling."),
            ("resource_governance.max_network_egress_per_session", "Max network egress / session", "Outbound network operations per session."),
            ("resource_governance.max_file_accessed_rate_per_min", "Max file access rate / min", "File operations per minute before flagging."),
            ("resource_governance.max_network_rate_per_min", "Max network rate / min", "Network operations per minute before flagging."),
        ]),
        ("Network egress", "Where the agent may reach out, and whether it must go through a proxy.", [
            ("egress.allow_hosts", "Allowed hosts", "Hosts the agent may connect to."),
            ("egress.proxy_url", "Proxy URL", "Egress proxy for outbound traffic."),
            ("egress.require_proxy", "Require proxy", "Deny direct egress that bypasses the proxy."),
        ]),
        ("Runtime", "", [("runtime.max_runtime_seconds", "Max runtime (seconds)", "Wall-clock cap for a guarded run.")]),
        ("Enforcement", "", [("enforcement.noninteractive", "Non-interactive fail-closed", "Escalate medium+ asks to deny when no human can answer.")]),
        ("Endpoint Security", "Kernel-level observation and managed-tree enforcement on macOS.", [
            ("endpoint_security.mode", "Sensor mode", "Off, observe, protect, or strict."),
            ("endpoint_security.protected_paths", "Protected paths", "Extra absolute path prefixes denied to managed agent trees."),
            ("endpoint_security.blocked_executables", "Blocked executables", "Executable paths denied before launch."),
            ("endpoint_security.max_auth_latency_ms", "Authorization latency budget", "Target maximum local decision latency."),
        ]),
        ("Allowlisted paths", "Path prefixes that are always trusted.", [("allow_path_prefixes", "Allowed path prefixes", "Absolute path prefixes exempt from sensitive checks.")]),
    ]

    var body: some View {
        VStack(spacing: 14) {
            ForEach(groups, id: \.0) { group in
                VStack(alignment: .leading, spacing: 0) {
                    HStack { Text(group.0).font(.system(size: 13, weight: .semibold)); Spacer(); Text(group.1).font(.system(size: 10)).foregroundStyle(.secondary) }
                        .padding(.bottom, 9)
                    ForEach(group.2, id: \.0) { item in
                        HStack(alignment: .top, spacing: 18) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.1).font(.system(size: 12, weight: .semibold))
                                Text(item.2).font(.system(size: 10)).foregroundStyle(.secondary)
                            }.frame(width: 260, alignment: .leading)
                            Text(displayValue(dottedValue(document, item.0)))
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                            Spacer()
                        }.padding(.vertical, 7)
                        Divider()
                    }
                }.padding(14).background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))
            }
            Text("Edit these values in Advanced (JSON), then use Save & Validate. Boolean quick controls remain available below.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            HStack {
                Picker("Endpoint Security", selection: Binding(
                    get: { model.policy.endpointSecurityMode },
                    set: { value in Task { await model.setPolicy(key: "endpoint_security.mode", value: value) } }
                )) {
                    Text("Off").tag("off")
                    Text("Observe").tag("observe")
                    Text("Protect").tag("protect")
                    Text("Strict").tag("strict")
                }
                .frame(width: 220)
                Toggle("Non-interactive fail-closed", isOn: Binding(get: { model.policy.noninteractive }, set: { value in Task { await model.setPolicy(key: "enforcement.noninteractive", value: value ? "true" : "false") } }))
                Toggle("Require proxy", isOn: Binding(get: { model.policy.requireProxy }, set: { value in Task { await model.setPolicy(key: "egress.require_proxy", value: value ? "true" : "false") } }))
                Spacer()
            }.toggleStyle(.switch)
        }
    }
}

private struct PolicyRulesView: View {
    let document: [String: Any]

    private var groups: [(String, [[String: Any]])] {
        var fileRules: [[String: Any]] = []
        if let secret = document["secret_paths"] as? [String: Any], let protected = secret["protected"] as? [String: Any] { fileRules.append(protected.merging(["_name": "Protected secrets"]) { current, _ in current }) }
        if let persistence = document["persistence_writes"] as? [String: Any] { fileRules.append(persistence.merging(["_name": "Persistence / startup writes"]) { current, _ in current }) }
        if let categories = document["categories"] as? [String: Any] {
            for (name, value) in categories { if let rule = value as? [String: Any] { fileRules.append(rule.merging(["_name": name.replacingOccurrences(of: "_", with: " ")]) { current, _ in current }) } }
        }
        return [
            ("File access rules", fileRules),
            ("Command rules", document["command_rules"] as? [[String: Any]] ?? []),
            ("Executable-content rules", document["content_rules"] as? [[String: Any]] ?? []),
            ("Network / URL rules", document["url_rules"] as? [[String: Any]] ?? []),
        ].filter { !$0.1.isEmpty }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Each rule's action — Deny blocks, Ask prompts the user, Allow/Warn lets it through.").font(.system(size: 11)).foregroundStyle(.secondary)
            if groups.isEmpty { DashboardEmpty(text: "No decision rules found in this policy.") }
            ForEach(groups, id: \.0) { group in
                VStack(alignment: .leading, spacing: 0) {
                    Text("\(group.0) (\(group.1.count))").font(.system(size: 13, weight: .semibold)).padding(.bottom, 6)
                    ForEach(Array(group.1.enumerated()), id: \.offset) { _, rule in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text((rule["_name"] ?? rule["id"] ?? rule["rule_id"] ?? "Rule") as? String ?? "Rule").font(.system(size: 12, weight: .semibold))
                                Text(rule["rule_id"] as? String ?? matcherSummary(rule)).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                            }
                            Spacer()
                            DashboardTag(text: rule["action"] as? String ?? "allow", color: actionColor(rule["action"] as? String ?? "allow"))
                        }.padding(.vertical, 7)
                        Divider()
                    }
                }.padding(14).background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))
            }
        }
    }

    private func matcherSummary(_ rule: [String: Any]) -> String {
        ["patterns", "commands", "bare_commands", "hosts", "url_substrings", "segments", "filenames", "filename_suffixes", "path_contains", "exact_paths"]
            .flatMap { rule[$0] as? [String] ?? [] }.prefix(4).joined(separator: ", ")
    }
}

private struct ArtifactDefinitionsView: View {
    let document: [String: Any]
    private let definitions = [("executable", "Executable artifacts"), ("memory", "Memory files"), ("skill", "Skill / plugin locations"), ("control_plane", "Control-plane files")]

    var body: some View {
        let registries = document["artifact_registries"] as? [String: Any] ?? [:]
        VStack(alignment: .leading, spacing: 10) {
            Text("What the shield treats as executable, memory, skill, or control-plane files.").font(.system(size: 11)).foregroundStyle(.secondary)
            ForEach(definitions, id: \.0) { definition in
                DisclosureGroup {
                    let values = registries[definition.0] as? [String: Any] ?? [:]
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(values.keys.sorted(), id: \.self) { key in
                            HStack(alignment: .top) {
                                Text(key.replacingOccurrences(of: "_", with: " ").capitalized).frame(width: 190, alignment: .leading)
                                Text(displayValue(values[key])).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                            }.font(.system(size: 11))
                        }
                    }.padding(10)
                } label: { Text(definition.1).font(.system(size: 12, weight: .semibold)) }
                    .padding(10).background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))
            }
        }
    }
}

struct DashboardSettingsPage: View {
    @ObservedObject var model: ConsoleModel
    @ObservedObject var extensionManager: EndpointSecurityExtensionManager
    @ObservedObject var sensor: EndpointSecuritySensor
    @Binding var darkMode: Bool
    @State private var confirmRemoval = false

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Settings", description: "Local-store security, appearance, and advanced configuration.")
                if model.databaseExists && !model.databaseEncrypted {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Plaintext local database detected").font(.system(size: 13, weight: .semibold))
                            Text("Telemetry is not encrypted at rest. Create or migrate to a new Gensee home with encryption enabled; automatic in-place encryption is not offered because it could corrupt the active security store.").font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                    }.padding(12).background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 5)).overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.orange.opacity(0.35)))
                }

                HStack(alignment: .top, spacing: 16) {
                    DashboardCard("Endpoint Security") { endpointSecurity }.frame(maxWidth: .infinity)
                    DashboardCard("Local Store") { localStore }.frame(maxWidth: .infinity)
                }
                HStack(alignment: .top, spacing: 16) {
                    DashboardCard("Appearance") {
                        VStack(alignment: .leading, spacing: 12) {
                            Toggle("Dark mode", isOn: $darkMode).toggleStyle(.switch)
                            Divider()
                            Text("The theme preference is saved locally and applied across the security console.").font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                    }.frame(maxWidth: .infinity)
                    DashboardCard("About") {
                        Text("Gensee Crate v0.2.4\nNative macOS security console\n\nGensee backend: \(model.backendAvailable ? "Connected" : "Unavailable")")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity)
                }
            }
        }
        .alert("Remove the Endpoint Security extension?", isPresented: $confirmRemoval) {
            Button("Cancel", role: .cancel) {}
            Button("Remove Extension", role: .destructive) { extensionManager.deactivate() }
        } message: { Text("Crate will stop receiving operating-system process and file events until the extension is installed again.") }
    }

    private var endpointSecurity: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: extensionManager.state.symbolName).foregroundStyle(extensionManager.state.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(extensionManager.state.title).font(.system(size: 12, weight: .semibold))
                    Text(extensionManager.state.detail).font(.system(size: 10)).foregroundStyle(.secondary)
                }
            }
            Divider()
            settingsLine("Sensor transport", sensor.health.connected ? "Connected" : "Disconnected")
            settingsLine("Policy mode", sensor.health.mode.capitalized)
            HStack {
                Text("Events ingested").font(.system(size: 11))
                Spacer()
                Text(sensor.health.ingestedEvents.formatted())
                    .font(.system(size: 11, design: .monospaced))
            }
            HStack {
                Text("Dropped events").font(.system(size: 11))
                Spacer()
                DashboardTag(
                    text: (sensor.health.kernelDrops + sensor.health.ringDrops).formatted(),
                    color: sensor.health.hasDataLoss ? .dashboardRed : .green
                )
            }
            HStack {
                Text("Authorization decisions").font(.system(size: 11))
                Spacer()
                Text("\(sensor.health.authorizationCount.formatted()) (\(sensor.health.deniedCount.formatted()) denied)")
                    .font(.system(size: 11, design: .monospaced))
            }
            settingsLine(
                "Max authorization latency",
                "\(sensor.health.maxAuthorizationLatencyUS) µs / \(sensor.health.configuredMaxAuthorizationLatencyUS) µs budget"
            )
            if sensor.health.exceedsAuthorizationLatencyBudget {
                Label("Authorization latency exceeded the configured budget", systemImage: "exclamationmark.triangle")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Color.dashboardGold)
            }
            settingsLine("Managed processes", sensor.health.managedProcesses.formatted())
            if let error = sensor.health.error {
                Text(error).font(.system(size: 10)).foregroundStyle(.red)
            }
            HStack {
                Button("Full Disk Access") { model.openFullDiskAccess() }
                Button("Reconnect") { sensor.reconnect() }
                Button("Remove…", role: .destructive) { confirmRemoval = true }.disabled(extensionManager.state.isBusy || extensionManager.state == .notInstalled)
                Spacer()
                Button(extensionManager.state == .active ? "Installed & Enabled" : "Install & Enable") { extensionManager.activate() }
                    .buttonStyle(.borderedProminent).tint(.dashboardRed)
                    .disabled(extensionManager.state.isBusy || extensionManager.state == .active || !extensionManager.isRunningFromApplications)
            }.controlSize(.small)
        }
    }

    private var localStore: some View {
        VStack(alignment: .leading, spacing: 12) {
            settingsLine("Local database", abbreviatedPath(model.databaseURL.path))
            Divider()
            HStack { Text("Encryption at rest").font(.system(size: 11)); Spacer(); DashboardTag(text: !model.databaseExists ? "No database" : model.databaseEncrypted ? "Encrypted" : "Plaintext — action required", color: !model.databaseExists ? .secondary : model.databaseEncrypted ? .green : .orange) }
            Divider()
            HStack { Text("Backend transport").font(.system(size: 11)); Spacer(); DashboardTag(text: "Bundled local CLI", color: .dashboardBlue) }
            HStack { Spacer(); Button("Show in Finder") { model.revealDataStore() }.controlSize(.small) }
        }
    }

    private func settingsLine(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) { Text(title).font(.system(size: 11, weight: .semibold)); Text(value).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled) }
    }
}

private func dottedValue(_ object: [String: Any], _ path: String) -> Any? {
    var current: Any = object
    for component in path.split(separator: ".").map(String.init) {
        guard let dictionary = current as? [String: Any], let next = dictionary[component] else { return nil }
        current = next
    }
    return current
}

private func displayValue(_ value: Any?) -> String {
    guard let value else { return "—" }
    if let array = value as? [Any] { return array.map { String(describing: $0) }.joined(separator: ", ") }
    if let dictionary = value as? [String: Any], let data = try? JSONSerialization.data(withJSONObject: dictionary), let string = String(data: data, encoding: .utf8) { return string }
    return String(describing: value)
}

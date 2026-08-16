import SwiftUI

struct DashboardPolicyPage: View {
    @ObservedObject var model: ConsoleModel
    @State private var tab = "Settings"
    @State private var editorText = ""
    @State private var dirty = false

    private var document: [String: Any]? {
        guard let data = editorText.data(using: .utf8),
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return value
    }

    var body: some View {
        DashboardPage {
            VStack(alignment: .leading, spacing: 16) {
                DashboardPageHeader("Policy", description: "Configure the active Gensee security policy.") {
                    HStack(spacing: 8) {
                        Button { Task { await model.refreshPolicy(); editorText = model.policyDocument; dirty = false } } label: { Label("Reload", systemImage: "arrow.clockwise") }
                        Button { Task { if await model.savePolicyDocument(editorText) { dirty = false } } } label: { Label("Save & Validate", systemImage: "square.and.arrow.down") }
                            .buttonStyle(.borderedProminent).tint(.dashboardRed).disabled(!dirty || document == nil)
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
                            case "Decision Rules":
                                PolicyRulesView(document: document ?? [:], editorText: $editorText)
                            case "Artifact Definitions":
                                ArtifactDefinitionsView(document: document ?? [:], editorText: $editorText)
                            case "Advanced (JSON)":
                                VStack(alignment: .leading, spacing: 9) {
                                    HStack {
                                        Text("Edit the complete policy document. Save & Validate checks it with the Gensee policy engine before replacing the active policy.")
                                            .font(.system(size: 11))
                                            .foregroundStyle(.secondary)
                                        Spacer()
                                        Label(
                                            document == nil ? "Invalid JSON" : "Valid JSON",
                                            systemImage: document == nil ? "xmark.circle.fill" : "checkmark.circle.fill"
                                        )
                                        .font(.system(size: 10, weight: .semibold))
                                        .foregroundStyle(document == nil ? Color.dashboardRed : Color.dashboardGreen)
                                    }
                                    TextEditor(text: $editorText)
                                        .font(.system(size: 11, design: .monospaced))
                                        .frame(minHeight: 470)
                                        .overlay(RoundedRectangle(cornerRadius: 5).stroke(document == nil ? Color.dashboardRed : Color.dashboardLine))
                                }
                            default:
                                if let document {
                                    PolicySettingsView(
                                        document: document,
                                        editorText: $editorText
                                    )
                                } else {
                                    VStack(alignment: .leading, spacing: 8) {
                                        Label("Policy JSON needs attention", systemImage: "exclamationmark.triangle.fill")
                                            .font(.system(size: 13, weight: .semibold))
                                            .foregroundStyle(Color.dashboardRed)
                                        Text("Settings controls are disabled because the policy buffer is empty or is not a valid JSON object. Fix it in Advanced (JSON), then return here.")
                                            .font(.system(size: 11))
                                            .foregroundStyle(.secondary)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(14)
                                    .background(Color.dashboardRed.opacity(0.06), in: RoundedRectangle(cornerRadius: 5))
                                }
                            }
                        }
                    }
                }
            }
        }
        .onAppear { if editorText.isEmpty { editorText = model.policyDocument } }
        .onChange(of: editorText) { newValue in dirty = newValue != model.policyDocument }
        .onChange(of: model.policyDocument) { newValue in if !dirty { editorText = newValue } }
    }
}

private struct PolicySettingsView: View {
    let document: [String: Any]
    @Binding var editorText: String

    private let groups: [PolicySettingGroup] = [
        PolicySettingGroup(
            title: "Resource governance",
            detail: "Per-tool and per-session limits.",
            settings: [
                .integer("resource_governance.max_read_bytes", "Max read bytes", "Largest single file read the shield allows.", minimum: 1),
                .integer("resource_governance.max_file_subjects_per_tool", "Max file subjects / tool", "File paths a single tool call may touch.", minimum: 1),
                .integer("resource_governance.max_shell_segments_per_tool", "Max shell segments / tool", "Chained commands per shell call.", minimum: 1),
                .integer("resource_governance.max_tool_calls_per_session", "Max tool calls / session", "Total tool calls permitted before throttling.", minimum: 1),
                .integer("resource_governance.max_network_egress_per_session", "Max network egress / session", "Outbound network operations permitted per session.", minimum: 1),
                .decimal("resource_governance.max_file_accessed_rate_per_min", "Max file access rate / min", "File operations per minute before flagging.", minimum: 0),
                .decimal("resource_governance.max_network_rate_per_min", "Max network rate / min", "Network operations per minute before flagging.", minimum: 0),
            ]
        ),
        PolicySettingGroup(
            title: "Network egress",
            detail: "Destinations and proxy requirements.",
            settings: [
                .list("egress.allow_hosts", "Allowed hosts", "Hostnames or IPs the agent may contact."),
                .text("egress.proxy_url", "Proxy URL", "Outbound proxy URL. Leave blank for none.", nullable: true),
                .boolean("egress.require_proxy", "Require proxy", "Deny direct egress that bypasses the configured proxy."),
            ]
        ),
        PolicySettingGroup(
            title: "Runtime & enforcement",
            detail: "Guarded-run lifetime and unattended decisions.",
            settings: [
                .integer("runtime.max_runtime_seconds", "Max runtime (seconds)", "Wall-clock cap. Leave blank for no cap.", minimum: 1, nullable: true),
                .boolean("enforcement.noninteractive", "Non-interactive fail-closed", "Escalate medium+ asks to deny when no human can answer."),
            ]
        ),
        PolicySettingGroup(
            title: "Endpoint Security",
            detail: "Kernel-level macOS observation and managed-tree enforcement.",
            settings: [
                .choice("endpoint_security.mode", "Sensor mode", "Choose observation or authorization enforcement.", options: ["off", "observe", "protect", "strict"]),
                .list("endpoint_security.protected_paths", "Protected paths", "Additional absolute path prefixes denied to managed agent trees."),
                .list("endpoint_security.blocked_executables", "Blocked executables", "Absolute executable paths denied before launch."),
                .integer("endpoint_security.max_auth_latency_ms", "Authorization latency budget", "Maximum local decision latency, from 1 to 100 ms.", minimum: 1, maximum: 100),
            ]
        ),
        PolicySettingGroup(
            title: "Observation & trust",
            detail: "System-event source and explicitly trusted paths.",
            settings: [
                .choice("watch.system_events", "System event source", "Choose the host-level event backend.", options: ["none", "endpoint-security", "eslogger"]),
                .list("allow_path_prefixes", "Allowed path prefixes", "Absolute prefixes exempt from sensitive-path checks."),
            ]
        ),
    ]

    var body: some View {
        VStack(spacing: 14) {
            ForEach(groups) { group in
                VStack(alignment: .leading, spacing: 0) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(group.title).font(.system(size: 13, weight: .semibold))
                        Spacer()
                        Text(group.detail).font(.system(size: 10)).foregroundStyle(.secondary)
                    }
                        .padding(.bottom, 9)
                    ForEach(group.settings) { setting in
                        PolicySettingRow(
                            setting: setting,
                            value: dottedValue(document, setting.key),
                            onChange: { updatePolicyValue(setting.key, to: $0) }
                        )
                        Divider()
                    }
                }.padding(14).background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))
            }
            HStack {
                Image(systemName: "checkmark.shield")
                    .foregroundStyle(Color.dashboardGreen)
                Text("Edits remain local until Save & Validate confirms the complete policy.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Spacer()
            }
        }
    }

    private func updatePolicyValue(_ key: String, to value: Any) {
        var root = document
        setDottedValue(&root, key, value)
        editorText = formattedPolicyDocument(root) ?? editorText
    }
}

private struct PolicySettingGroup: Identifiable {
    let title: String
    let detail: String
    let settings: [PolicySettingDefinition]
    var id: String { title }
}

private struct PolicySettingDefinition: Identifiable {
    enum Kind {
        case integer(minimum: Int?, maximum: Int?, nullable: Bool)
        case decimal(minimum: Double?, maximum: Double?)
        case boolean
        case list
        case text(nullable: Bool)
        case choice([String])
    }

    let key: String
    let label: String
    let help: String
    let kind: Kind
    var id: String { key }

    static func integer(
        _ key: String,
        _ label: String,
        _ help: String,
        minimum: Int? = nil,
        maximum: Int? = nil,
        nullable: Bool = false
    ) -> Self {
        Self(key: key, label: label, help: help, kind: .integer(minimum: minimum, maximum: maximum, nullable: nullable))
    }

    static func decimal(
        _ key: String,
        _ label: String,
        _ help: String,
        minimum: Double? = nil,
        maximum: Double? = nil
    ) -> Self {
        Self(key: key, label: label, help: help, kind: .decimal(minimum: minimum, maximum: maximum))
    }

    static func boolean(_ key: String, _ label: String, _ help: String) -> Self {
        Self(key: key, label: label, help: help, kind: .boolean)
    }

    static func list(_ key: String, _ label: String, _ help: String) -> Self {
        Self(key: key, label: label, help: help, kind: .list)
    }

    static func text(_ key: String, _ label: String, _ help: String, nullable: Bool = false) -> Self {
        Self(key: key, label: label, help: help, kind: .text(nullable: nullable))
    }

    static func choice(
        _ key: String,
        _ label: String,
        _ help: String,
        options: [String]
    ) -> Self {
        Self(key: key, label: label, help: help, kind: .choice(options))
    }
}

private struct PolicySettingRow: View {
    let setting: PolicySettingDefinition
    let value: Any?
    let onChange: (Any) -> Void

    @State private var text: String
    @State private var validationMessage: String?
    @FocusState private var textFieldFocused: Bool

    init(setting: PolicySettingDefinition, value: Any?, onChange: @escaping (Any) -> Void) {
        self.setting = setting
        self.value = value
        self.onChange = onChange
        _text = State(initialValue: Self.editableText(value, kind: setting.kind))
    }

    private var sourceText: String { Self.editableText(value, kind: setting.kind) }

    var body: some View {
        HStack(alignment: .top, spacing: 22) {
            VStack(alignment: .leading, spacing: 3) {
                Text(setting.label)
                    .font(.system(size: 12, weight: .semibold))
                Text(setting.help)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(width: 290, alignment: .leading)

            editor
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .padding(.vertical, 8)
        .onChange(of: sourceText) { newValue in
            if !textFieldFocused { text = newValue }
        }
    }

    @ViewBuilder
    private var editor: some View {
        switch setting.kind {
        case .boolean:
            HStack(spacing: 9) {
                Text(booleanValue ? "Enabled" : "Disabled")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.secondary)
                Toggle("", isOn: Binding(
                    get: { booleanValue },
                    set: { onChange($0) }
                ))
                .labelsHidden()
                .toggleStyle(.switch)
                .accessibilityLabel(setting.label)
            }

        case let .choice(options):
            Picker(setting.label, selection: Binding(
                get: { value as? String ?? options.first ?? "" },
                set: { onChange($0) }
            )) {
                ForEach(options, id: \.self) { option in
                    Text(choiceLabel(option)).tag(option)
                }
            }
            .labelsHidden()
            .frame(width: 210)

        case .integer, .decimal, .list, .text:
            VStack(alignment: .trailing, spacing: 3) {
                TextField(placeholder, text: $text)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 11, design: textFieldUsesMonospacedFont ? .monospaced : .default))
                    .multilineTextAlignment(.leading)
                    .focused($textFieldFocused)
                    .frame(width: 360)
                    .onChange(of: text) { validateAndUpdate($0) }
                    .accessibilityLabel(setting.label)
                if let validationMessage {
                    Text(validationMessage)
                        .font(.system(size: 9, weight: .medium))
                        .foregroundStyle(Color.dashboardRed)
                } else if case .list = setting.kind {
                    Text("Separate multiple values with commas.")
                        .font(.system(size: 9))
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    private var booleanValue: Bool {
        if let value = value as? Bool { return value }
        return (value as? NSNumber)?.boolValue ?? false
    }

    private var placeholder: String {
        switch setting.kind {
        case let .integer(_, _, nullable): return nullable ? "No limit" : "Enter a whole number"
        case .decimal: return "Enter a number"
        case .list: return "None"
        case let .text(nullable): return nullable ? "None" : "Enter a value"
        default: return ""
        }
    }

    private var textFieldUsesMonospacedFont: Bool {
        switch setting.kind {
        case .integer, .decimal: return true
        default: return false
        }
    }

    private func validateAndUpdate(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        switch setting.kind {
        case let .integer(minimum, maximum, nullable):
            if trimmed.isEmpty, nullable {
                validationMessage = nil
                onChange(NSNull())
                return
            }
            guard let number = Int(trimmed) else {
                validationMessage = nullable ? "Enter a whole number or leave blank." : "Enter a whole number."
                return
            }
            if let minimum, number < minimum {
                validationMessage = "Minimum: \(minimum)."
                return
            }
            if let maximum, number > maximum {
                validationMessage = "Maximum: \(maximum)."
                return
            }
            validationMessage = nil
            onChange(number)

        case let .decimal(minimum, maximum):
            guard let number = Double(trimmed), number.isFinite else {
                validationMessage = "Enter a valid number."
                return
            }
            if let minimum, number < minimum {
                validationMessage = "Minimum: \(minimum.formatted())."
                return
            }
            if let maximum, number > maximum {
                validationMessage = "Maximum: \(maximum.formatted())."
                return
            }
            validationMessage = nil
            onChange(number)

        case .list:
            validationMessage = nil
            let values = raw
                .split(whereSeparator: { $0 == "," || $0.isNewline })
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            onChange(values)

        case let .text(nullable):
            validationMessage = nil
            onChange(trimmed.isEmpty && nullable ? NSNull() : raw)

        case .boolean, .choice:
            break
        }
    }

    private static func editableText(_ value: Any?, kind: PolicySettingDefinition.Kind) -> String {
        if value == nil || value is NSNull { return "" }
        switch kind {
        case .list:
            return (value as? [Any] ?? []).map(String.init(describing:)).joined(separator: ", ")
        case .integer:
            return (value as? NSNumber)?.int64Value.description ?? String(describing: value!)
        case .decimal:
            return (value as? NSNumber).map { String($0.doubleValue) }
                ?? String(describing: value!)
        case .text:
            return value as? String ?? String(describing: value!)
        case .boolean, .choice:
            return ""
        }
    }

    private func choiceLabel(_ value: String) -> String {
        switch value {
        case "endpoint-security": return "Endpoint Security"
        case "eslogger": return "Legacy eslogger"
        case "deny-all": return "Deny all"
        default: return value.replacingOccurrences(of: "-", with: " ").capitalized
        }
    }
}

private struct PolicyRulesView: View {
    let document: [String: Any]
    @Binding var editorText: String

    private var groups: [(String, [PolicyRuleRow])] {
        var fileRules: [PolicyRuleRow] = []
        if let secret = document["secret_paths"] as? [String: Any] {
            if let protected = secret["protected"] as? [String: Any] {
                fileRules.append(PolicyRuleRow(
                    name: "Protected secrets",
                    ruleID: secret["rule_id"] as? String,
                    rule: protected,
                    target: .dotted("secret_paths.protected.action")
                ))
            }
            if let credentialHint = secret["credential_hint"] as? [String: Any] {
                fileRules.append(PolicyRuleRow(
                    name: "Credential-like paths",
                    ruleID: secret["rule_id"] as? String,
                    rule: credentialHint,
                    target: .dotted("secret_paths.credential_hint.action")
                ))
            }
        }
        if let persistence = document["persistence_writes"] as? [String: Any] {
            fileRules.append(PolicyRuleRow(
                name: "Persistence / startup writes",
                ruleID: persistence["rule_id"] as? String,
                rule: persistence,
                target: .dotted("persistence_writes.action")
            ))
        }
        if let categories = document["categories"] as? [String: Any] {
            for name in categories.keys.sorted() {
                guard let rule = categories[name] as? [String: Any] else { continue }
                fileRules.append(PolicyRuleRow(
                    name: name.replacingOccurrences(of: "_", with: " ").capitalized,
                    ruleID: rule["rule_id"] as? String,
                    rule: rule,
                    target: .dotted("categories.\(name).action")
                ))
            }
        }
        return [
            ("File access rules", fileRules),
            ("Command rules", rows(in: "command_rules")),
            ("Executable-content rules", rows(in: "content_rules")),
            ("Network / URL rules", rows(in: "url_rules")),
        ].filter { !$0.1.isEmpty }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("Choose what Gensee does when each rule matches. Deny blocks, Ask prompts, and Warn or Allow lets the operation continue.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Spacer()
                Text("ACTION")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }
            if groups.isEmpty { DashboardEmpty(text: "No decision rules found in this policy.") }
            ForEach(groups, id: \.0) { group in
                VStack(alignment: .leading, spacing: 0) {
                    Text("\(group.0) (\(group.1.count))").font(.system(size: 13, weight: .semibold)).padding(.bottom, 6)
                    ForEach(group.1) { rule in
                        HStack(spacing: 16) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(rule.name).font(.system(size: 12, weight: .semibold))
                                if let ruleID = rule.ruleID, !ruleID.isEmpty {
                                    Text(ruleID).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                                }
                                if !rule.matcherSummary.isEmpty {
                                    Text(rule.matcherSummary)
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundStyle(.tertiary)
                                        .lineLimit(1)
                                }
                            }
                            Spacer()
                            Picker("Action", selection: Binding(
                                get: { rule.action },
                                set: { updateAction(for: rule.target, action: $0) }
                            )) {
                                Text("Deny").tag("block")
                                Text("Ask").tag("ask")
                                Text("Warn").tag("warn")
                                Text("Allow").tag("allow")
                            }
                            .labelsHidden()
                            .pickerStyle(.menu)
                            .frame(width: 112)
                            .accessibilityLabel("Action for \(rule.name)")
                        }.padding(.vertical, 7)
                        Divider()
                    }
                }.padding(14).background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))
            }
            PolicyUnsavedEditsNote()
        }
    }

    private func rows(in collection: String) -> [PolicyRuleRow] {
        (document[collection] as? [[String: Any]] ?? []).enumerated().map { index, rule in
            PolicyRuleRow(
                name: (rule["id"] ?? rule["rule_id"] ?? "Rule \(index + 1)") as? String ?? "Rule \(index + 1)",
                ruleID: rule["rule_id"] as? String,
                rule: rule,
                target: .indexed(collection, index)
            )
        }
    }

    private func updateAction(for target: PolicyRuleActionTarget, action: String) {
        var root = document
        switch target {
        case let .dotted(path):
            setDottedValue(&root, path, action)
        case let .indexed(collection, index):
            guard var rules = root[collection] as? [[String: Any]], rules.indices.contains(index) else { return }
            rules[index]["action"] = action
            root[collection] = rules
        }
        editorText = formattedPolicyDocument(root) ?? editorText
    }
}

private struct ArtifactDefinitionsView: View {
    let document: [String: Any]
    @Binding var editorText: String

    private let definitions = [
        ("executable", "Executable artifacts", "Runnable scripts, skills, plugins, and hooks."),
        ("memory", "Memory files", "Agent memory tracked for poisoning across turns and sessions."),
        ("skill", "Skill / plugin locations", "Paths containing skill, rule, and plugin definitions."),
        ("control_plane", "Control-plane files", "Gensee-owned and harness-control files that require protection."),
    ]
    private let matcherFields = [
        ("segments", "Path segments", "Exact directory names."),
        ("filenames", "Exact filenames", "Case-insensitive filename matches."),
        ("filename_prefixes", "Filename prefixes", "Prefixes matched against the filename."),
        ("filename_suffixes", "Filename suffixes", "Suffixes or extensions matched against the filename."),
        ("filename_contains", "Filename contains", "Fragments matched anywhere in the filename."),
        ("path_suffixes", "Path ends with", "Suffixes matched against the complete path."),
        ("path_contains", "Path contains", "Fragments matched anywhere in the complete path."),
    ]

    var body: some View {
        let registries = document["artifact_registries"] as? [String: Any] ?? [:]
        VStack(alignment: .leading, spacing: 10) {
            Text("Define which paths Gensee treats as executable, memory, skill, or control-plane artifacts. Separate multiple matchers with commas.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            ForEach(definitions, id: \.0) { definition in
                DisclosureGroup {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(matcherFields, id: \.0) { field in
                            let path = "artifact_registries.\(definition.0).\(field.0)"
                            PolicySettingRow(
                                setting: .list(path, field.1, field.2),
                                value: dottedValue(document, path),
                                onChange: { updatePolicyValue(path, to: $0) }
                            )
                            Divider()
                        }
                    }
                    .padding(.top, 8)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(definition.1).font(.system(size: 12, weight: .semibold))
                        Text("\(definition.2) · \(matcherCount(in: registries[definition.0])) matchers")
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                    }
                }
                    .padding(10).background(Color.dashboardMutedFill, in: RoundedRectangle(cornerRadius: 5))
            }
            PolicyUnsavedEditsNote()
        }
    }

    private func matcherCount(in value: Any?) -> Int {
        guard let registry = value as? [String: Any] else { return 0 }
        return matcherFields.reduce(0) { count, field in
            count + (registry[field.0] as? [Any] ?? []).count
        }
    }

    private func updatePolicyValue(_ key: String, to value: Any) {
        var root = document
        setDottedValue(&root, key, value)
        editorText = formattedPolicyDocument(root) ?? editorText
    }
}

private enum PolicyRuleActionTarget: Hashable {
    case dotted(String)
    case indexed(String, Int)
}

private struct PolicyRuleRow: Identifiable {
    let name: String
    let ruleID: String?
    let action: String
    let matcherSummary: String
    let target: PolicyRuleActionTarget

    var id: PolicyRuleActionTarget { target }

    init(name: String, ruleID: String?, rule: [String: Any], target: PolicyRuleActionTarget) {
        self.name = name
        self.ruleID = ruleID
        action = rule["action"] as? String ?? "allow"
        matcherSummary = [
            "patterns", "all_of", "commands", "bare_commands", "arg_all", "arg_any", "raw_contains", "raw_all",
            "host_substrings", "segments", "filenames", "filename_suffixes", "path_contains", "exact_paths",
        ]
        .flatMap { rule[$0] as? [String] ?? [] }
        .prefix(4)
        .joined(separator: ", ")
        self.target = target
    }
}

private struct PolicyUnsavedEditsNote: View {
    var body: some View {
        HStack {
            Image(systemName: "checkmark.shield")
                .foregroundStyle(Color.dashboardGreen)
            Text("Edits remain local until Save & Validate confirms the complete policy.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            Spacer()
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

private func setDottedValue(_ object: inout [String: Any], _ path: String, _ value: Any) {
    setDottedValue(
        &object,
        components: ArraySlice(path.split(separator: ".").map(String.init)),
        value: value
    )
}

private func setDottedValue(
    _ object: inout [String: Any],
    components: ArraySlice<String>,
    value: Any
) {
    guard let key = components.first else { return }
    let remaining = components.dropFirst()
    guard !remaining.isEmpty else {
        object[key] = value
        return
    }
    var child = object[key] as? [String: Any] ?? [:]
    setDottedValue(&child, components: remaining, value: value)
    object[key] = child
}

private func formattedPolicyDocument(_ document: [String: Any]) -> String? {
    guard JSONSerialization.isValidJSONObject(document),
          let data = try? JSONSerialization.data(withJSONObject: document, options: [.prettyPrinted, .sortedKeys])
    else { return nil }
    return String(decoding: data, as: UTF8.self)
}

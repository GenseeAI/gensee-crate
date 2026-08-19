import AppKit
import SwiftUI

struct DashboardRecoveryPage: View {
    @ObservedObject var model: ConsoleModel
    @AppStorage("gensee.recovery.workspace") private var workspacePath = ""
    @State private var label = ""
    @State private var restoreCandidate: WorkspaceCheckpointRecord?

    var body: some View {
        DashboardPage {
            DashboardPageHeader(
                "Checkpoints",
                description: "Save a local workspace state before risky agent work, then restore it if the result goes wrong."
            ) {
                Button {
                    Task { await model.loadCheckpoints(workspace: workspacePath) }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
                .disabled(model.runningCommand != nil || workspacePath.isEmpty)
            }

            VStack(alignment: .leading, spacing: 16) {
                recoveryPromise
                checkpointControls
                checkpointList
            }
        }
        .task(id: workspacePath) {
            guard !workspacePath.isEmpty else { return }
            await model.loadCheckpoints(workspace: workspacePath, reportErrors: false)
        }
        .alert("Restore this checkpoint?", isPresented: restorePresented, presenting: restoreCandidate) { checkpoint in
            Button("Cancel", role: .cancel) { restoreCandidate = nil }
            Button("Create Rescue & Restore", role: .destructive) {
                restoreCandidate = nil
                Task { await model.restoreCheckpoint(checkpoint, workspace: workspacePath) }
            }
        } message: { checkpoint in
            Text("Gensee will first preserve the workspace as it is now, then restore \(checkpoint.label ?? checkpoint.id). Tracked and untracked non-ignored files may change or be removed. Ignored files and your Git staging index stay untouched.")
        }
    }

    private var recoveryPromise: some View {
        DashboardCard {
            HStack(alignment: .top, spacing: 14) {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color.dashboardBlue.opacity(0.11))
                    .frame(width: 42, height: 42)
                    .overlay(
                        Image(systemName: "arrow.uturn.backward.circle.fill")
                            .font(.system(size: 19))
                            .foregroundStyle(Color.dashboardBlue)
                    )
                VStack(alignment: .leading, spacing: 5) {
                    Text("An undo point before substantial agent work")
                        .font(.system(size: 15, weight: .semibold))
                    Text("Choose a Git project, create a checkpoint before starting the task, and return here to restore it if needed. Gensee stores the files in Git's local object database without committing to your branch or changing what you staged. Every restore first saves the current state as a rescue checkpoint.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                StatusPill(label: "LOCAL ONLY", color: .dashboardGreen, symbol: "lock.fill")
            }
        }
    }

    private var checkpointControls: some View {
        DashboardCard("1. Create a checkpoint") {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .bottom, spacing: 10) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Git workspace")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(.secondary)
                        HStack(spacing: 6) {
                            TextField("Choose a project folder", text: $workspacePath)
                                .textFieldStyle(.roundedBorder)
                            Button { chooseWorkspace() } label: { Image(systemName: "folder") }
                                .help("Choose Git workspace")
                        }
                    }
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Label (optional)")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(.secondary)
                        TextField("Before agent refactor", text: $label)
                            .textFieldStyle(.roundedBorder)
                    }
                    .frame(width: 260)
                    Button {
                        let currentLabel = label
                        label = ""
                        Task { await model.createCheckpoint(workspace: workspacePath, label: currentLabel) }
                    } label: {
                        Label("Create Checkpoint", systemImage: "plus.circle.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.dashboardRed)
                    .disabled(model.runningCommand != nil || workspacePath.isEmpty)
                }

                Label(
                    "Includes tracked and untracked non-ignored files. Ignored files, nested repository contents, and files outside this workspace are not captured.",
                    systemImage: "info.circle"
                )
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var checkpointList: some View {
        DashboardCard("2. Restore when needed") {
            if model.checkpoints.isEmpty {
                DashboardEmpty(
                    text: workspacePath.isEmpty
                        ? "Choose a Git workspace to see its recovery points."
                        : "No checkpoints yet. Create one before handing a substantial task to an agent.",
                    symbol: "clock.arrow.circlepath"
                )
            } else {
                VStack(spacing: 0) {
                    ForEach(model.checkpoints) { checkpoint in
                        checkpointRow(checkpoint)
                        if checkpoint.id != model.checkpoints.last?.id { Divider() }
                    }
                }
            }
        }
    }

    private func checkpointRow(_ checkpoint: WorkspaceCheckpointRecord) -> some View {
        HStack(spacing: 12) {
            Image(systemName: checkpoint.rescueOf == nil ? "clock.badge.checkmark" : "lifepreserver.fill")
                .frame(width: 24)
                .foregroundStyle(checkpoint.rescueOf == nil ? Color.dashboardBlue : Color.dashboardGold)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 7) {
                    Text(checkpoint.label ?? "Workspace checkpoint")
                        .font(.system(size: 13, weight: .semibold))
                    if checkpoint.rescueOf != nil {
                        DashboardTag(text: "Rescue", color: .dashboardGold)
                    }
                }
                Text("\(checkpoint.id) · \(checkpointDate(checkpoint.createdAtMS))")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            Button("Restore…") { restoreCandidate = checkpoint }
                .controlSize(.small)
                .disabled(model.runningCommand != nil)
        }
        .padding(.vertical, 11)
    }

    private var restorePresented: Binding<Bool> {
        Binding(
            get: { restoreCandidate != nil },
            set: { if !$0 { restoreCandidate = nil } }
        )
    }

    private func chooseWorkspace() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Choose Workspace"
        if panel.runModal() == .OK, let url = panel.url {
            workspacePath = url.resolvingSymlinksInPath().path
        }
    }

    private func checkpointDate(_ milliseconds: Int64) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: Date(timeIntervalSince1970: Double(milliseconds) / 1_000))
    }
}

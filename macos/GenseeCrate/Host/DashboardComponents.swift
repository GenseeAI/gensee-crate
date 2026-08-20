import AppKit
import SwiftUI

struct DashboardPage<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) { self.content = content() }

    var body: some View {
        ScrollView {
            content
                .padding(24)
                .frame(maxWidth: 1320, alignment: .leading)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct DashboardPageHeader<Actions: View>: View {
    let title: String
    let description: String
    let actions: Actions

    init(_ title: String, description: String, @ViewBuilder actions: () -> Actions) {
        self.title = title
        self.description = description
        self.actions = actions()
    }

    var body: some View {
        HStack(alignment: .top, spacing: 20) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 24, weight: .semibold))
                Text(description).font(.system(size: 13)).foregroundStyle(.secondary)
            }
            Spacer()
            actions
        }
        .padding(.bottom, 20)
    }
}

extension DashboardPageHeader where Actions == EmptyView {
    init(_ title: String, description: String) {
        self.init(title, description: description) { EmptyView() }
    }
}

struct DashboardStatCard: View {
    let title: String
    let value: Int
    let symbol: String
    let color: Color

    var body: some View {
        DashboardCard {
            HStack(spacing: 10) {
                DashboardSymbol(symbol, color: color, size: 15)
                    .frame(width: 22, height: 38)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: 12)).foregroundStyle(.secondary)
                    Text(value.formatted()).font(.system(size: 23, weight: .semibold))
                }
            }
            .frame(maxWidth: .infinity, minHeight: 48, alignment: .leading)
        }
    }
}

/// A restrained SF Symbol treatment shared by the native console. Keeping the
/// glyph monochrome and optically sized avoids the mixed filled/tinted tiles
/// that made otherwise-native symbols feel decorative rather than macOS-like.
struct DashboardSymbol: View {
    let name: String
    let color: Color
    let size: CGFloat
    let weight: Font.Weight

    init(
        _ name: String,
        color: Color = .secondary,
        size: CGFloat = 14,
        weight: Font.Weight = .medium
    ) {
        self.name = name
        self.color = color
        self.size = size
        self.weight = weight
    }

    var body: some View {
        Image(systemName: name)
            .symbolRenderingMode(.monochrome)
            .font(.system(size: size, weight: weight))
            .foregroundStyle(color)
    }
}

struct DashboardEmpty: View {
    let text: String
    var symbol = "tray"

    var body: some View {
        VStack(spacing: 9) {
            DashboardSymbol(symbol, color: Color.secondary.opacity(0.55), size: 18, weight: .regular)
            Text(text).font(.system(size: 12)).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 120)
    }
}

struct DashboardLoadingHint: View {
    let message: String
    var compact = false

    var body: some View {
        HStack(spacing: compact ? 7 : 10) {
            ProgressView()
                .controlSize(.small)
                .accessibilityHidden(true)
            Text(message)
                .font(.system(size: compact ? 10 : 11, weight: .medium))
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(message)
    }
}

struct DashboardTag: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 4))
    }
}

func severityColor(_ severity: String) -> Color {
    switch severity.lowercased() {
    case "critical": .purple
    case "high": .red
    case "medium": .orange
    case "low": .cyan
    default: .secondary
    }
}

func actionColor(_ action: String) -> Color {
    switch action.lowercased() {
    case "block", "deny": .red
    case "ask": .orange
    case "warn": .yellow
    case "allow": .green
    default: .secondary
    }
}

func dashboardDate(_ milliseconds: Int64) -> String {
    let formatter = DateFormatter()
    formatter.dateStyle = .short
    formatter.timeStyle = .short
    return formatter.string(from: Date(timeIntervalSince1970: Double(milliseconds) / 1_000))
}

func dashboardTime(_ milliseconds: Int64) -> String {
    let formatter = DateFormatter()
    formatter.timeStyle = .medium
    return formatter.string(from: Date(timeIntervalSince1970: Double(milliseconds) / 1_000))
}

func containsSearch(_ search: String, fields: String?...) -> Bool {
    searchTermsMatch(search, fields: fields)
}

func dashboardPathURL(_ path: String) -> URL {
    URL(fileURLWithPath: (path as NSString).expandingTildeInPath).standardizedFileURL
}

func dashboardPathExists(_ path: String) -> Bool {
    FileManager.default.fileExists(atPath: dashboardPathURL(path).path)
}

func dashboardPathIsDirectory(_ path: String) -> Bool {
    var directory: ObjCBool = false
    return FileManager.default.fileExists(atPath: dashboardPathURL(path).path, isDirectory: &directory)
        && directory.boolValue
}

func openDashboardPath(_ path: String) {
    NSWorkspace.shared.open(dashboardPathURL(path))
}

func revealDashboardPath(_ path: String) {
    let url = dashboardPathURL(path)
    if dashboardPathExists(path) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    } else {
        NSWorkspace.shared.open(url.deletingLastPathComponent())
    }
}

struct DashboardPathActions: View {
    let path: String

    private var url: URL { dashboardPathURL(path) }

    private var exists: Bool { dashboardPathExists(path) }

    private var isDirectory: Bool {
        dashboardPathIsDirectory(path)
    }

    var body: some View {
        HStack(spacing: 5) {
            Button {
                openDashboardPath(path)
            } label: {
                Label(isDirectory ? "Open Folder" : "Open File", systemImage: isDirectory ? "folder" : "doc")
            }
            .disabled(!exists)
            .help(exists ? "Open \(url.path)" : "This path no longer exists on disk")

            Button {
                revealDashboardPath(path)
            } label: {
                Label("Show in Finder", systemImage: "folder.badge.gearshape")
            }
            .help(exists ? "Reveal this item in Finder" : "Open its containing folder in Finder")
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .fixedSize()
    }

}

struct DashboardPathMenu: View {
    let path: String

    var body: some View {
        Menu {
            DashboardPathContextActions(path: path)
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .help("File actions")
    }
}

struct DashboardPathContextActions: View {
    let path: String

    var body: some View {
        let isDirectory = dashboardPathIsDirectory(path)
        Button(isDirectory ? "Open Folder" : "Open File") {
            openDashboardPath(path)
        }
        .disabled(!dashboardPathExists(path))
        Button("Show in Finder") {
            revealDashboardPath(path)
        }
    }
}

struct DashboardRefreshButton: View {
    let refreshing: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) { Label("Refresh", systemImage: "arrow.clockwise") }
            .controlSize(.small)
            .disabled(refreshing)
    }
}

struct DashboardTableHeader: View {
    let columns: [(String, CGFloat?)]

    var body: some View {
        HStack(spacing: 12) {
            ForEach(Array(columns.enumerated()), id: \.offset) { _, item in
                Text(item.0)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .frame(width: item.1, alignment: .leading)
                    .frame(maxWidth: item.1 == nil ? .infinity : nil, alignment: .leading)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(Color.dashboardMutedFill)
    }
}

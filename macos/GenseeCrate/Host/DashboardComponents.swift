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
            HStack(spacing: 12) {
                RoundedRectangle(cornerRadius: 6)
                    .fill(color.opacity(0.12))
                    .frame(width: 38, height: 38)
                    .overlay(Image(systemName: symbol).foregroundStyle(color))
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: 12)).foregroundStyle(.secondary)
                    Text(value.formatted()).font(.system(size: 23, weight: .semibold))
                }
            }
            .frame(maxWidth: .infinity, minHeight: 48, alignment: .leading)
        }
    }
}

struct DashboardEmpty: View {
    let text: String
    var symbol = "tray"

    var body: some View {
        VStack(spacing: 9) {
            Image(systemName: symbol).font(.title2).foregroundStyle(.tertiary)
            Text(text).font(.system(size: 12)).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 120)
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
    guard !search.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return true }
    return fields.compactMap { $0 }.contains { $0.localizedCaseInsensitiveContains(search) }
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

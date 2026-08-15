import AppKit
import SwiftUI

extension Color {
    static let dashboardRed = Color(red: 229 / 255, green: 57 / 255, blue: 53 / 255)
    static let dashboardBlue = Color(red: 22 / 255, green: 119 / 255, blue: 1)
    static let dashboardGold = Color(red: 250 / 255, green: 173 / 255, blue: 20 / 255)
    static let dashboardGreen = Color(red: 82 / 255, green: 196 / 255, blue: 26 / 255)
    static let crateForest = Color(red: 35 / 255, green: 46 / 255, blue: 38 / 255)
    static let crateDeep = Color(red: 18 / 255, green: 26 / 255, blue: 21 / 255)
    static let crateCream = Color(red: 240 / 255, green: 232 / 255, blue: 210 / 255)
    static let crateOrange = Color(red: 223 / 255, green: 127 / 255, blue: 47 / 255)

    static let crateCanvas = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(red: 0.055, green: 0.071, blue: 0.059, alpha: 1)
            : NSColor(red: 0.965, green: 0.957, blue: 0.925, alpha: 1)
    })

    static let cratePanel = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(red: 0.090, green: 0.112, blue: 0.095, alpha: 1)
            : NSColor(red: 0.992, green: 0.988, blue: 0.973, alpha: 1)
    })

    static let crateLine = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor.white.withAlphaComponent(0.11)
            : NSColor(red: 0.79, green: 0.77, blue: 0.70, alpha: 0.55)
    })

    static let dashboardCanvas = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(red: 13 / 255, green: 17 / 255, blue: 23 / 255, alpha: 1)
            : NSColor(red: 240 / 255, green: 242 / 255, blue: 245 / 255, alpha: 1)
    })

    static let dashboardPanel = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(red: 22 / 255, green: 27 / 255, blue: 34 / 255, alpha: 1)
            : .white
    })

    static let dashboardLine = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(red: 33 / 255, green: 38 / 255, blue: 45 / 255, alpha: 1)
            : NSColor(red: 232 / 255, green: 232 / 255, blue: 232 / 255, alpha: 1)
    })

    static let dashboardMutedFill = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor.white.withAlphaComponent(0.055)
            : NSColor.black.withAlphaComponent(0.035)
    })
}

struct BrandEye: View {
    var size: CGFloat

    var body: some View {
        Image("BrandEye")
            .resizable()
            .interpolation(.high)
            .scaledToFit()
            .frame(width: size, height: size)
            .clipShape(RoundedRectangle(cornerRadius: size * 0.23, style: .continuous))
    }
}

struct ConsolePanel<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.cratePanel)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(Color.crateLine, lineWidth: 1)
            )
    }
}

struct DashboardCard<Content: View>: View {
    var title: String?
    let content: Content

    init(_ title: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let title {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .padding(.horizontal, 14)
                    .frame(height: 38)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .overlay(alignment: .bottom) { Rectangle().fill(Color.dashboardLine).frame(height: 1) }
            }
            content
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color.dashboardPanel)
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.dashboardLine, lineWidth: 1))
    }
}

struct StatusPill: View {
    let label: String
    let color: Color
    var symbol = "circle.fill"

    var body: some View {
        Label(label, systemImage: symbol)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(color.opacity(0.12), in: Capsule())
    }
}

func relativeTimestamp(_ milliseconds: Int64) -> String {
    let date = Date(timeIntervalSince1970: Double(milliseconds) / 1_000)
    let formatter = RelativeDateTimeFormatter()
    formatter.unitsStyle = .abbreviated
    return formatter.localizedString(for: date, relativeTo: Date())
}

func abbreviatedPath(_ path: String) -> String {
    path.replacingOccurrences(
        of: FileManager.default.homeDirectoryForCurrentUser.path,
        with: "~"
    )
}

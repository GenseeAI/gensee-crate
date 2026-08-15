import SwiftUI

struct ContentView: View {
    @ObservedObject var extensionManager: EndpointSecurityExtensionManager
    @ObservedObject var model: ConsoleModel

    var body: some View {
        DashboardShell(extensionManager: extensionManager, model: model)
    }
}

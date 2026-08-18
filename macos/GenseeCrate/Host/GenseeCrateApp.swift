import SwiftUI

@main
struct GenseeCrateApp: App {
    @StateObject private var extensionManager = EndpointSecurityExtensionManager()
    @StateObject private var consoleModel = ConsoleModel()

    var body: some Scene {
        WindowGroup {
            ContentView(extensionManager: extensionManager, model: consoleModel)
                .frame(minWidth: 1180, minHeight: 720)
        }
        .windowResizability(.contentMinSize)
    }
}

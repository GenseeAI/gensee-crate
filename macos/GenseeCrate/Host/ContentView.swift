import SwiftUI

struct ContentView: View {
    @ObservedObject var extensionManager: EndpointSecurityExtensionManager
    @ObservedObject var model: ConsoleModel
    @AppStorage("gensee.setup-assistant.seen.v1") private var hasSeenSetupAssistant = false
    @State private var showsSetupAssistant = false

    var body: some View {
        DashboardShell(
            extensionManager: extensionManager,
            model: model,
            showsSetupAssistant: $showsSetupAssistant
        )
        .onAppear {
            if !hasSeenSetupAssistant {
                showsSetupAssistant = true
            }
        }
        .sheet(isPresented: $showsSetupAssistant, onDismiss: {
            hasSeenSetupAssistant = true
        }) {
            SetupAssistantView(
                model: model,
                extensionManager: extensionManager,
                sensor: model.endpointSensor
            ) {
                hasSeenSetupAssistant = true
                showsSetupAssistant = false
            }
        }
    }
}

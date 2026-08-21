import SwiftUI

struct ContentView: View {
    @ObservedObject var extensionManager: EndpointSecurityExtensionManager
    @ObservedObject var model: ConsoleModel
    @ObservedObject var notifications: CompletionNotificationCoordinator
    @AppStorage("gensee.setup-assistant.seen.v1") private var hasSeenSetupAssistant = false
    @State private var showsSetupAssistant = false

    var body: some View {
        DashboardShell(
            extensionManager: extensionManager,
            model: model,
            notifications: notifications,
            showsSetupAssistant: $showsSetupAssistant
        )
        .onAppear {
            if !hasSeenSetupAssistant {
                showsSetupAssistant = true
            }
        }
        .onChange(of: extensionManager.state) { state in
            guard state == .active else { return }
            model.endpointSensor.start()
            model.endpointSensor.reconnect()
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

import SwiftUI

@main
struct CodexOpsConsoleApp: App {
    @NSApplicationDelegateAdaptor(CodexOpsAppDelegate.self) private var appDelegate
    @StateObject private var store = OpsStore()

    var body: some Scene {
        WindowGroup {
            OpsConsoleView(store: store)
                .frame(minWidth: 1180, minHeight: 760)
                .preferredColorScheme(.dark)
                .background(WindowAccessor { window in
                    AppWindowController.shared.attach(window)
                })
                .onAppear {
                    StatusBarController.shared.install(store: store)
                }
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}

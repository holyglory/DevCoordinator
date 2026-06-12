import SwiftUI

@main
struct CodexOpsConsoleApp: App {
    var body: some Scene {
        WindowGroup {
            OpsConsoleView()
                .frame(minWidth: 1180, minHeight: 760)
                .preferredColorScheme(.dark)
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}

import AppKit
import SwiftUI

@main
struct MenuBarSnapshotMain {
    @MainActor
    static func main() async throws {
        let output = CommandLine.arguments.dropFirst().first ?? "menu-bar-qa.png"
        let mode = CommandLine.arguments.dropFirst().dropFirst().first
        let width: CGFloat = 430
        let height: CGFloat = 600
        let store = OpsStore()
        await store.loadInventory()
        if mode == "error" {
            store.lastErrorTitle = "Restart api failed"
            store.lastError = "server stop requires --agent so the coordinator can attribute the action"
            store.lastErrorDetails = """
            Restart api

            Command: python3 /Users/holyglory/.codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py server restart --agent holyglory --project /Users/holyglory/src/XFoilFOAM --name api

            Exit status: 1

            stdout:
            {"error":"server stop requires --agent so the coordinator can attribute the action"}
            """
        }

        let view = MenuBarRuntimeView(
            store: store,
            openConsole: {},
            quit: {}
        )
        .frame(width: width, height: height)
        .preferredColorScheme(.dark)

        let hostingView = NSHostingView(rootView: view)
        hostingView.frame = NSRect(x: 0, y: 0, width: width, height: height)
        hostingView.layoutSubtreeIfNeeded()
        hostingView.displayIfNeeded()

        guard let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: Int(width),
            pixelsHigh: Int(height),
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: 0,
            bitsPerPixel: 0
        ) else {
            throw MenuBarSnapshotError.renderFailed
        }
        bitmap.size = hostingView.bounds.size
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            throw MenuBarSnapshotError.renderFailed
        }

        try png.write(to: URL(fileURLWithPath: output))
    }
}

enum MenuBarSnapshotError: Error {
    case renderFailed
}

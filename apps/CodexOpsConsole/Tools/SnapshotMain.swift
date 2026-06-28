import AppKit
import SwiftUI

@main
struct SnapshotMain {
    @MainActor
    static func main() async throws {
        let output = CommandLine.arguments.dropFirst().first ?? "design-qa-implementation.png"
        let tab = CommandLine.arguments.dropFirst().dropFirst().first
        let width = CGFloat(Double(CommandLine.arguments.dropFirst(3).first ?? "1440") ?? 1440)
        let height = CGFloat(Double(CommandLine.arguments.dropFirst(4).first ?? "1024") ?? 1024)
        let store = OpsStore()
        await store.loadInventory()
        switch tab?.lowercased() {
        case "docker":
            store.activeTab = .docker
            if let container = store.visibleDockerContainers.first {
                store.selectDocker(container)
            }
        case "databases":
            store.activeTab = .databases
            if let database = store.visiblePostgres.first {
                store.selectDatabase(database)
            }
        default:
            store.activeTab = .servers
            if let server = store.filteredServers.first {
                store.selectServer(server)
            }
        }

        let layout = consoleLayout(totalWidth: width, sidebarPreference: defaultSidebarWidth, inspectorPreference: 320)
        let mainX = layout.sidebarWidth + splitHandleWidth
        let inspectorSplitX = mainX + layout.mainWidth
        let view = ZStack(alignment: .topLeading) {
            ServiceMapView(store: store)
                .frame(width: layout.sidebarWidth, height: height)
                .position(x: layout.sidebarWidth / 2, y: height / 2)
                .zIndex(1)
            if layout.showsMain {
                SplitGripPreview()
                    .frame(width: splitHandleWidth, height: height)
                    .position(x: layout.sidebarWidth + (splitHandleWidth / 2), y: height / 2)
                    .zIndex(5)
                MainBoardView(store: store)
                    .frame(width: layout.mainWidth, height: height)
                    .clipped()
                    .position(x: mainX + (layout.mainWidth / 2), y: height / 2)
                    .zIndex(0)
            }
            if layout.showsInspector {
                SplitGripPreview()
                    .frame(width: splitHandleWidth, height: height)
                    .position(x: inspectorSplitX + (splitHandleWidth / 2), y: height / 2)
                    .zIndex(5)
                DetailsRailView(store: store)
                    .frame(width: layout.inspectorWidth, height: height)
                    .position(x: inspectorSplitX + splitHandleWidth + (layout.inspectorWidth / 2), y: height / 2)
                    .zIndex(2)
            }
        }
        .frame(width: width, height: height)
        .background(Theme.background)
        .foregroundStyle(Theme.primary)
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
            throw SnapshotError.renderFailed
        }
        bitmap.size = hostingView.bounds.size
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            throw SnapshotError.renderFailed
        }

        try png.write(to: URL(fileURLWithPath: output))
    }
}

enum SnapshotError: Error {
    case renderFailed
}

struct SplitGripPreview: View {
    var body: some View {
        ZStack {
            Rectangle().fill(Color.white.opacity(0.035))
            Rectangle().fill(Color.white.opacity(0.16)).frame(width: 1)
        }
        .frame(width: splitHandleWidth)
    }
}

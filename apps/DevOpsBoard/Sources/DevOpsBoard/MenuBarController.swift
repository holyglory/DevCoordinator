import AppKit
import SwiftUI

final class DevOpsBoardAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        Task { @MainActor in
            AppWindowController.shared.showWindow()
        }
        return true
    }
}

@MainActor
final class AppWindowController: NSObject, NSWindowDelegate {
    static let shared = AppWindowController()

    private weak var window: NSWindow?
    private weak var store: OpsStore?

    func attach(_ window: NSWindow, store: OpsStore) {
        self.store = store
        guard self.window !== window else { return }
        self.window = window
        window.delegate = self
        window.isReleasedWhenClosed = false
        window.standardWindowButton(.miniaturizeButton)?.target = self
        window.standardWindowButton(.miniaturizeButton)?.action = #selector(minimizeToMenuBar(_:))
        publishWindowVisibility()
    }

    func showWindow() {
        guard let window else { return }
        NSApp.setActivationPolicy(.regular)
        if window.isMiniaturized {
            window.deminiaturize(nil)
        }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        publishWindowVisibility()
    }

    func hideWindow() {
        guard let window else { return }
        if window.isMiniaturized {
            window.deminiaturize(nil)
        }
        window.orderOut(nil)
        NSApp.setActivationPolicy(.accessory)
        publishWindowVisibility()
    }

    @objc
    private func minimizeToMenuBar(_ sender: Any?) {
        hideWindow()
    }

    func windowWillMiniaturize(_ notification: Notification) {
        hideWindow()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        hideWindow()
        return false
    }

    func windowDidChangeOcclusionState(_ notification: Notification) {
        publishWindowVisibility()
    }

    private func publishWindowVisibility() {
        guard let window, let store else { return }
        let visible = window.isVisible && window.occlusionState.contains(.visible)
        store.setSurfaceVisible(.window, visible)
    }
}

struct WindowAccessor: NSViewRepresentable {
    var onResolve: (NSWindow) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        resolveWindow(for: view)
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        resolveWindow(for: nsView)
    }

    private func resolveWindow(for view: NSView) {
        DispatchQueue.main.async {
            if let window = view.window {
                onResolve(window)
            }
        }
    }
}

@MainActor
final class StatusBarController: NSObject, NSPopoverDelegate {
    static let shared = StatusBarController()

    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private weak var store: OpsStore?

    func install(store: OpsStore) {
        self.store = store
        guard statusItem == nil else { return }

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.image = NSImage(systemSymbolName: "terminal.fill", accessibilityDescription: "DevOps Board")
            button.imagePosition = .imageLeading
            button.title = " DevOps"
            button.target = self
            button.action = #selector(togglePopover(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }

        let menuPopover = NSPopover()
        menuPopover.behavior = .transient
        menuPopover.contentSize = NSSize(width: 430, height: 600)
        menuPopover.delegate = self

        statusItem = item
        popover = menuPopover
    }

    @objc
    private func togglePopover(_ sender: Any?) {
        guard let popover else { return }
        if popover.isShown {
            closePopover()
        } else {
            showPopover()
        }
    }

    private func showPopover() {
        guard let button = statusItem?.button, let popover, let store else { return }
        popover.contentViewController = NSHostingController(
            rootView: MenuBarRuntimeView(
                store: store,
                openConsole: { [weak self] in
                    self?.closePopover()
                    AppWindowController.shared.showWindow()
                },
                quit: {
                    NSApp.terminate(nil)
                }
            )
        )
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        store.refresh()
    }

    private func closePopover() {
        popover?.performClose(nil)
    }

    func popoverWillShow(_ notification: Notification) {
        store?.setSurfaceVisible(.popover, true)
    }

    func popoverDidClose(_ notification: Notification) {
        store?.setSurfaceVisible(.popover, false)
        popover?.contentViewController = nil
    }
}

import SwiftUI

struct MenuBarRuntimeView: View {
    @ObservedObject var store: OpsStore
    let openConsole: () -> Void
    let quit: () -> Void

    private var groups: [ProjectGroup] {
        projectGroups(from: store.inventory)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "terminal.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Theme.blue)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Codex Ops")
                        .font(.system(size: 14, weight: .semibold))
                    Text(store.connected ? "Coordinator connected" : "Coordinator waiting")
                        .font(.system(size: 11))
                        .foregroundStyle(store.connected ? Theme.secondary : Theme.orange)
                }
                Spacer()
                MenuBarActionButton(
                    title: "Refresh",
                    systemImage: "arrow.clockwise",
                    tint: Theme.secondary,
                    action: store.refresh
                )
                MenuBarActionButton(
                    title: "Open console",
                    systemImage: "macwindow",
                    tint: Theme.primary,
                    action: openConsole
                )
            }
            .padding(.horizontal, 14)
            .frame(height: 54)

            Divider().overlay(Color.white.opacity(0.08))

            if groups.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "tray")
                        .font(.system(size: 24))
                        .foregroundStyle(Theme.secondary)
                    Text("No managed tasks")
                        .font(.system(size: 13, weight: .semibold))
                    Text("Run inventory from a project to register servers, containers, and databases.")
                        .font(.system(size: 11))
                        .multilineTextAlignment(.center)
                        .foregroundStyle(Theme.secondary)
                        .frame(maxWidth: 260)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView(.vertical, showsIndicators: true) {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(groups, id: \.id) { group in
                            MenuProjectRow(store: store, group: group)
                        }
                    }
                    .padding(10)
                }
                .scrollIndicators(.visible)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }

            Divider().overlay(Color.white.opacity(0.08))

            if store.lastError != nil {
                MenuBarErrorPanel(store: store)
                Divider().overlay(Color.white.opacity(0.08))
            }

            HStack(spacing: 8) {
                StatusDot(status: store.lastError == nil ? "running" : "unhealthy")
                Text(store.lastError ?? "Ready")
                    .font(.system(size: 11))
                    .foregroundStyle(store.lastError == nil ? Theme.secondary : Theme.red)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Button("Stop all") {
                    store.stopAll()
                }
                .buttonStyle(MenuBarTextButtonStyle(tint: Theme.orange))
                .disabled(!store.hasStoppableResources)
                Button("Quit") {
                    quit()
                }
                .buttonStyle(MenuBarTextButtonStyle(tint: Theme.secondary))
            }
            .padding(.horizontal, 12)
            .frame(height: 46)
        }
        .frame(width: 430, height: 600)
        .background(Theme.sidebar)
        .foregroundStyle(Theme.primary)
        .task {
            await store.loadInventory()
        }
    }
}

struct MenuBarErrorPanel: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 7) {
                StatusDot(status: "unhealthy")
                Text(store.lastErrorTitle ?? "Action failed")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.red)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Button("Copy") {
                    store.copyLastErrorDetails()
                }
                .buttonStyle(MenuBarTextButtonStyle(tint: Theme.blue))
                Button("Dismiss") {
                    store.clearLastError()
                }
                .buttonStyle(MenuBarTextButtonStyle(tint: Theme.secondary))
            }
            Text(store.lastError ?? "No details available")
                .font(.system(size: 11))
                .foregroundStyle(Theme.primary)
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)

            if let details = store.lastErrorDetails, !details.isEmpty {
                ScrollView(.vertical, showsIndicators: true) {
                    Text(details)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Theme.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(maxHeight: 96)
                .padding(8)
                .background(Color.black.opacity(0.2))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.white.opacity(0.08)))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Theme.red.opacity(0.08))
    }
}

struct MenuProjectRow: View {
    @ObservedObject var store: OpsStore
    let group: ProjectGroup

    var body: some View {
        VStack(spacing: 6) {
            HStack(spacing: 8) {
                Button {
                    store.selectProject(group.id)
                } label: {
                    HStack(spacing: 8) {
                        StatusDot(status: projectGroupStatus(group))
                        Text(group.name)
                            .font(.system(size: 13, weight: .semibold))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        CountBadge(count: group.servers.count + group.containers.count + group.databases.count)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .layoutPriority(1)

                HStack(spacing: 5) {
                    MenuBarActionButton(
                        title: canStop ? "Stop project runtime" : "Run project runtime",
                        systemImage: canStop ? "stop.fill" : "play.fill",
                        tint: canStop ? Theme.orange : Theme.green,
                        action: { canStop ? store.stopProject(group) : store.startProject(group) }
                    )
                    MenuBarActionButton(
                        title: "Restart project runtime",
                        systemImage: "arrow.clockwise",
                        tint: Theme.secondary,
                        action: { store.restartProject(group) }
                    )
                }
                .fixedSize()
                .zIndex(10)
            }
            .padding(.horizontal, 10)
            .frame(height: 34)
            .background(Theme.control.opacity(0.78))
            .clipShape(RoundedRectangle(cornerRadius: 7))

            VStack(spacing: 3) {
                ForEach(group.servers) { server in
                    MenuTaskRow(
                        kind: .server,
                        title: resourceDisplayName(server.name, inProject: group.id),
                        subtitle: menuServerSubtitle(server),
                        status: server.status,
                        canStop: canStopServer(server),
                        selectAction: { store.selectServer(server) },
                        toggleAction: { store.toggle(server) },
                        restartAction: { store.restart(server) },
                        openAction: server.url == nil ? nil : { store.openURL(server.url) }
                    )
                }

                ForEach(group.containers, id: \.stableID) { container in
                    MenuTaskRow(
                        kind: .docker,
                        title: resourceDisplayName(container.name, inProject: group.id),
                        subtitle: menuDockerSubtitle(container),
                        status: container.status,
                        canStop: container.isRunning,
                        selectAction: { store.selectDocker(container) },
                        toggleAction: { store.toggleDocker(container) },
                        restartAction: { store.restartDocker(container) },
                        openAction: nil
                    )
                }

                ForEach(group.databases, id: \.stableID) { database in
                    MenuTaskRow(
                        kind: .database,
                        title: resourceDisplayName(database.name, inProject: group.id),
                        subtitle: menuDockerSubtitle(database),
                        status: database.status,
                        canStop: database.isRunning,
                        selectAction: { store.selectDatabase(database) },
                        toggleAction: { store.toggleDocker(database) },
                        restartAction: { store.restartDocker(database) },
                        openAction: nil
                    )
                }
            }
            .padding(.leading, 8)
        }
    }

    private var canStop: Bool {
        projectGroupCanStop(group)
    }
}

struct MenuTaskRow: View {
    let kind: MapLeafKind
    let title: String
    let subtitle: String
    let status: String?
    let canStop: Bool
    let selectAction: () -> Void
    let toggleAction: () -> Void
    let restartAction: () -> Void
    let openAction: (() -> Void)?

    var body: some View {
        HStack(spacing: 7) {
            Button(action: selectAction) {
                HStack(spacing: 7) {
                    Image(systemName: kind.systemImage)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(kind.tint)
                        .frame(width: 14)
                    StatusDot(status: status)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(title)
                            .font(.system(size: 12, weight: .medium))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(subtitle)
                            .font(.system(size: 10))
                            .foregroundStyle(Theme.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .layoutPriority(1)

            HStack(spacing: 5) {
                if let openAction {
                    MenuBarActionButton(
                        title: "Open URL",
                        systemImage: "arrow.up.right.square",
                        tint: Theme.blue,
                        action: openAction
                    )
                }
                MenuBarActionButton(
                    title: canStop ? "Stop" : "Run",
                    systemImage: canStop ? "stop.fill" : "play.fill",
                    tint: canStop ? Theme.orange : Theme.green,
                    action: toggleAction
                )
                MenuBarActionButton(
                    title: "Restart",
                    systemImage: "arrow.clockwise",
                    tint: Theme.secondary,
                    action: restartAction
                )
            }
            .fixedSize()
            .zIndex(10)
        }
        .padding(.horizontal, 8)
        .frame(height: 36)
        .background(Color.white.opacity(0.035))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct MenuBarActionButton: View {
    let title: String
    let systemImage: String
    let tint: Color
    let action: () -> Void
    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 28, height: 28)
                .contentShape(RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .frame(width: 28, height: 28)
        .background(isHovering ? tint.opacity(0.18) : Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).stroke(isHovering ? tint.opacity(0.48) : Color.white.opacity(0.08)))
        .contentShape(RoundedRectangle(cornerRadius: 7))
        .onHover { hovering in
            isHovering = hovering
        }
        .help(title)
        .zIndex(20)
    }
}

struct MenuBarTextButtonStyle: ButtonStyle {
    let tint: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(tint)
            .padding(.horizontal, 10)
            .frame(height: 26)
            .background(configuration.isPressed ? Color.white.opacity(0.12) : Theme.control)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.white.opacity(0.08)))
    }
}

func menuServerSubtitle(_ server: ManagedServer) -> String {
    if let url = server.url, !url.isEmpty {
        return url
    }
    if let port = server.port {
        return "Port \(port)"
    }
    return normalizedStatus(server.status)
}

func menuDockerSubtitle(_ container: DockerContainer) -> String {
    if let ports = container.ports, !ports.isEmpty {
        return ports
    }
    if let image = container.image, !image.isEmpty {
        return image
    }
    return normalizedStatus(container.status)
}

import SwiftUI

struct MenuBarRuntimeView: View {
    @ObservedObject var store: OpsStore
    let openConsole: () -> Void
    let quit: () -> Void
    var loadsInventoryOnAppear = true

    private var groups: [ProjectGroup] {
        projectGroups(from: store.inventory)
    }

    private var latestResult: RetainedActionResult? {
        store.actionResults.values.max { $0.queuedAt < $1.queuedAt }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "terminal.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Theme.blue)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Codex Ops Console")
                        .font(.system(size: 14, weight: .semibold))
                    Text(store.presentationSnapshot.statusTitle)
                        .font(.system(size: 11))
                        .foregroundStyle(menuHealthColor(store.presentationSnapshot.level))
                        .lineLimit(1)
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
            .accessibilityIdentifier("menu-header")

            Divider().overlay(Color.white.opacity(0.08))

            MenuBarSourceSummary(store: store)

            Divider().overlay(Color.white.opacity(0.08))

            if store.isLoading && groups.isEmpty {
                VStack(spacing: 9) {
                    ProgressView().controlSize(.small)
                    Text("Refreshing coordinator sources…")
                        .font(.system(size: 12, weight: .semibold))
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .accessibilityIdentifier("menu-loading-state")
            } else if groups.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "tray")
                        .font(.system(size: 24))
                        .foregroundStyle(Theme.secondary)
                    Text("No managed tasks")
                        .font(.system(size: 13, weight: .semibold))
                    Text(store.sourceStates.isEmpty ? "No coordinator source is available." : "The loaded sources contain no managed resources.")
                        .font(.system(size: 11))
                        .multilineTextAlignment(.center)
                        .foregroundStyle(Theme.secondary)
                        .frame(maxWidth: 260)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .accessibilityIdentifier("menu-empty-state")
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

            if let issue = store.presentationSnapshot.actionIssue {
                MenuBarActionIssuePanel(store: store, issue: issue)
                Divider().overlay(Color.white.opacity(0.08))
            } else if let latestResult {
                MenuBarActionResultPanel(store: store, result: latestResult)
                Divider().overlay(Color.white.opacity(0.08))
            } else if store.lastError != nil {
                MenuBarErrorPanel(store: store)
                Divider().overlay(Color.white.opacity(0.08))
            }

            HStack(spacing: 8) {
                Image(systemName: menuHealthIcon(store.presentationSnapshot.level))
                    .foregroundStyle(menuHealthColor(store.presentationSnapshot.level))
                    .accessibilityHidden(true)
                Text(store.presentationSnapshot.statusTitle)
                    .font(.system(size: 11))
                    .foregroundStyle(menuHealthColor(store.presentationSnapshot.level))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Button("Open Console") {
                    openConsole()
                }
                .buttonStyle(MenuBarTextButtonStyle(tint: Theme.blue))
                .keyboardShortcut("o", modifiers: .command)
                .accessibilityIdentifier("menu-open-console")
                Button("Quit") {
                    quit()
                }
                .buttonStyle(MenuBarTextButtonStyle(tint: Theme.secondary))
                .accessibilityIdentifier("menu-quit")
            }
            .padding(.horizontal, 12)
            .frame(height: 46)
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("menu-footer")
        }
        .frame(width: 430, height: 600)
        .background(Theme.sidebar)
        .foregroundStyle(Theme.primary)
        .task {
            if loadsInventoryOnAppear { await store.loadInventory() }
        }
    }
}

struct MenuBarActionIssuePanel: View {
    @ObservedObject var store: OpsStore
    let issue: OpsIssue
    @State private var showingDetails = false

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 7) {
                StatusDot(status: "unhealthy")
                Text(issue.title)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.red)
                    .lineLimit(1)
                Spacer()
                Button("Copy") { store.copyIssueDetails(issue) }
                    .buttonStyle(MenuBarTextButtonStyle(tint: Theme.blue))
                Button("Dismiss") { store.dismissActionIssue() }
                    .buttonStyle(MenuBarTextButtonStyle(tint: Theme.secondary))
            }
            Text(issue.summary)
                .font(.system(size: 11))
                .fixedSize(horizontal: false, vertical: true)
            DisclosureGroup("Diagnostics", isExpanded: $showingDetails) {
                Text(issue.details)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Theme.secondary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .font(.system(size: 10, weight: .semibold))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Theme.red.opacity(0.08))
        .accessibilityIdentifier("menu-action-issue")
    }
}

struct MenuBarSourceSummary: View {
    @ObservedObject var store: OpsStore
    @State private var expanded = false

    private var loadedCount: Int { store.sourceStates.filter { $0.phase == .loaded }.count }
    private var totalCount: Int { store.sourceStates.count }
    private var title: String {
        guard totalCount > 0 else { return "Sources unavailable" }
        return "Sources \(loadedCount)/\(totalCount) · \(loadedCount == totalCount ? "Complete" : "Partial")"
    }

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 7) {
                ForEach(store.sourceStates) { source in
                    HStack(spacing: 7) {
                        StatusDot(status: source.phase.rawValue)
                        Text(source.origin.label)
                            .fontWeight(.semibold)
                            .lineLimit(1)
                        Spacer()
                        Text(source.phase.rawValue.capitalized)
                            .foregroundStyle(Theme.secondary)
                        CountBadge(count: source.resourceCount)
                    }
                }
                ForEach(store.capabilityStates.filter { $0.phase == .unavailable }) { capability in
                    Label(
                        "\(capability.capability.displayName) unavailable on \(capability.origin.label)",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(Theme.orange)
                    .fixedSize(horizontal: false, vertical: true)
                }
                if let issue = store.presentationSnapshot.inventoryIssue {
                    Text(issue.summary)
                        .foregroundStyle(Theme.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .font(.system(size: 10))
            .padding(.top, 7)
        } label: {
            HStack(spacing: 7) {
                Image(systemName: menuHealthIcon(store.presentationSnapshot.level))
                    .foregroundStyle(menuHealthColor(store.presentationSnapshot.level))
                Text(title)
                    .font(.system(size: 11, weight: .semibold))
                Spacer()
                Text(expanded ? "Hide" : "View details")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.blue)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(menuHealthColor(store.presentationSnapshot.level).opacity(0.08))
        .accessibilityIdentifier("menu-source-summary")
    }
}

struct MenuBarActionResultPanel: View {
    @ObservedObject var store: OpsStore
    let result: RetainedActionResult
    @State private var expanded = false

    private var isTerminal: Bool { result.phase != .queued && result.phase != .running }

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 8) {
                Text(store.actionResultDetails(result))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Theme.secondary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                HStack {
                    if result.outputTruncated {
                        Label("Truncated", systemImage: "scissors")
                            .foregroundStyle(Theme.orange)
                    }
                    Spacer()
                    Button("Copy details") { store.copyActionResultDetails(result) }
                        .buttonStyle(MenuBarTextButtonStyle(tint: Theme.blue))
                    Button("Dismiss") { store.dismissActionResult(result) }
                        .buttonStyle(MenuBarTextButtonStyle(tint: Theme.secondary))
                        .disabled(!isTerminal)
                }
            }
            .padding(.top, 7)
        } label: {
            HStack(spacing: 7) {
                ActionPhaseBadge(phase: result.phase)
                VStack(alignment: .leading, spacing: 2) {
                    Text(result.request.title)
                        .font(.system(size: 11, weight: .semibold))
                        .lineLimit(1)
                    Text(result.failure ?? result.request.origin?.label ?? "Coordinator action")
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Text(expanded ? "Hide" : "View")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.blue)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(actionPhaseColor(result.phase).opacity(0.08))
        .accessibilityIdentifier("menu-action-result")
    }
}

struct MenuBarErrorPanel: View {
    @ObservedObject var store: OpsStore
    @State private var showingDetails = false

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
                .accessibilityLabel("Copy issue details")
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
                DisclosureGroup("Diagnostics", isExpanded: $showingDetails) {
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
                .font(.system(size: 10, weight: .semibold))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Theme.red.opacity(0.08))
        .accessibilityIdentifier("menu-issue-panel")
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
                        if let origin = groupOrigin {
                            MenuSourceBadge(origin: origin)
                        } else if sourceCount > 1 {
                            Text("\(sourceCount) sources")
                                .font(.system(size: 9, weight: .semibold))
                                .foregroundStyle(Theme.orange)
                        }
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
                        action: { canStop ? store.stopProject(group) : store.startProject(group) },
                        disabled: !projectActionAllowed(canStop ? .projectStop : .projectStart)
                    )
                    MenuBarActionButton(
                        title: "Restart project runtime",
                        systemImage: "arrow.clockwise",
                        tint: Theme.secondary,
                        action: { store.restartProject(group) },
                        disabled: !projectActionAllowed(.projectRestart)
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
                        origin: server.origin,
                        status: server.status,
                        canStop: canStopServer(server),
                        toggleAllowed: serverActionAllowed(
                            store,
                            kind: canStopServer(server) ? .stopServer : .restartServer,
                            server: server
                        ),
                        restartAllowed: serverActionAllowed(store, kind: .restartServer, server: server),
                        selectAction: { store.selectServer(server) },
                        toggleAction: { store.toggle(server) },
                        restartAction: { store.restart(server) },
                        openAction: server.currentURL == nil ? nil : { store.openURL(server.currentURL) }
                    )
                }

                ForEach(group.containers, id: \.stableID) { container in
                    MenuTaskRow(
                        kind: .docker,
                        title: resourceDisplayName(container.name, inProject: group.id),
                        subtitle: menuDockerSubtitle(container),
                        origin: container.origin,
                        status: container.status,
                        canStop: container.isRunning,
                        toggleAllowed: dockerActionAllowed(
                            store,
                            kind: container.isRunning ? .stopDocker : .startDocker,
                            container: container
                        ),
                        restartAllowed: dockerActionAllowed(store, kind: .restartDocker, container: container),
                        selectAction: { store.selectDocker(container) },
                        toggleAction: { store.toggleDocker(container) },
                        restartAction: { store.restartDocker(container) },
                        openAction: nil
                    )
                }

                ForEach(group.databases, id: \.stableID) { database in
                    MenuTaskRow(
                        kind: .database,
                        title: database.database ?? resourceDisplayName(database.name, inProject: group.id),
                        subtitle: menuDockerSubtitle(database),
                        origin: database.origin,
                        status: database.status,
                        canStop: database.isRunning,
                        toggleAllowed: dockerActionAllowed(
                            store,
                            kind: database.isRunning ? .stopDocker : .startDocker,
                            container: database
                        ),
                        restartAllowed: dockerActionAllowed(store, kind: .restartDocker, container: database),
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

    private var groupOrigins: Set<CoordinatorOrigin> {
        Set(
            group.servers.compactMap(\.origin)
                + group.containers.compactMap(\.origin)
                + group.databases.compactMap(\.origin)
                + [group.usage?.origin].compactMap { $0 }
        )
    }

    private var sourceCount: Int { groupOrigins.count }
    private var groupOrigin: CoordinatorOrigin? { groupOrigins.count == 1 ? groupOrigins.first : nil }

    private func projectActionAllowed(_ kind: ActionKind) -> Bool {
        store.projectMutationAvailability(kind: kind, group: group).isAllowed
    }
}

struct MenuTaskRow: View {
    let kind: MapLeafKind
    let title: String
    let subtitle: String
    let origin: CoordinatorOrigin?
    let status: String?
    let canStop: Bool
    let toggleAllowed: Bool
    let restartAllowed: Bool
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
                        HStack(spacing: 5) {
                            Text(title)
                                .font(.system(size: 12, weight: .medium))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            if let origin { MenuSourceBadge(origin: origin) }
                        }
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
                    action: toggleAction,
                    disabled: !toggleAllowed
                )
                MenuBarActionButton(
                    title: "Restart",
                    systemImage: "arrow.clockwise",
                    tint: Theme.secondary,
                    action: restartAction,
                    disabled: !restartAllowed
                )
            }
            .fixedSize()
            .zIndex(10)
        }
        .padding(.horizontal, 8)
        .frame(height: 36)
        .background(Color.white.opacity(0.035))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(kindLabel), \(title), \(normalizedStatus(status)), source \(origin?.label ?? "unavailable")")
        .accessibilityIdentifier(
            "menu-resource-\(safeAccessibilityID(kindLabel))-\(safeAccessibilityID(title))-\(safeAccessibilityID(origin?.label ?? "unknown-source"))"
        )
    }

    private var kindLabel: String {
        switch kind {
        case .server: "Server"
        case .docker: "Docker container"
        case .database: "Database"
        }
    }
}

struct MenuSourceBadge: View {
    let origin: CoordinatorOrigin

    var body: some View {
        Text(origin.label)
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(Theme.blue)
            .padding(.horizontal, 5)
            .frame(height: 16)
            .background(Theme.blue.opacity(0.12))
            .clipShape(Capsule())
            .lineLimit(1)
            .accessibilityLabel("Source \(origin.label)")
    }
}

struct MenuBarActionButton: View {
    let title: String
    let systemImage: String
    let tint: Color
    let action: () -> Void
    var disabled = false
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
        .disabled(disabled)
        .opacity(disabled ? 0.45 : 1)
        .frame(width: 28, height: 28)
        .background(isHovering ? tint.opacity(0.18) : Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).stroke(isHovering ? tint.opacity(0.48) : Color.white.opacity(0.08)))
        .contentShape(RoundedRectangle(cornerRadius: 7))
        .onHover { hovering in
            isHovering = hovering
        }
        .help(title)
        .accessibilityLabel(title)
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
    if let url = server.currentURL, !url.isEmpty {
        return url
    }
    if server.urlIsCurrent == false, server.url != nil {
        return "previous URL"
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

func menuHealthColor(_ level: HealthLevel) -> Color {
    switch level {
    case .nominal: Theme.green
    case .busy: Theme.blue
    case .degraded: Theme.orange
    case .unhealthy, .unavailable: Theme.red
    }
}

func menuHealthIcon(_ level: HealthLevel) -> String {
    switch level {
    case .nominal: "checkmark.circle.fill"
    case .busy: "clock.arrow.circlepath"
    case .degraded: "exclamationmark.triangle.fill"
    case .unhealthy: "xmark.octagon.fill"
    case .unavailable: "bolt.slash.fill"
    }
}

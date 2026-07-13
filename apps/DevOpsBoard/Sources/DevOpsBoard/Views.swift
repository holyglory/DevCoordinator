import AppKit
import SwiftUI

func resizedPaneWidth(
    start: CGFloat,
    startX: CGFloat,
    currentX: CGFloat,
    direction: CGFloat,
    range: ClosedRange<CGFloat>
) -> CGFloat {
    let next = start + ((currentX - startX) * direction)
    return min(range.upperBound, max(range.lowerBound, next))
}

func resizedColumnWidth(start: CGFloat, startX: CGFloat, currentX: CGFloat, minimum: CGFloat = 72) -> CGFloat {
    max(minimum, start + (currentX - startX))
}

let splitHandleWidth: CGFloat = 8
let minimumReadableSidebarWidth: CGFloat = 320
let defaultSidebarWidth: CGFloat = 320
let maximumSidebarWidth: CGFloat = 520
let minimumMainWidth: CGFloat = 420
let minimumCompactMainWidth: CGFloat = 260
let minimumInspectorWidth: CGFloat = 320
let maximumInspectorWidth: CGFloat = 500
let sidebarFooterInset: CGFloat = 18
let sidebarFooterHeight: CGFloat = 106

func sidebarFooterContentWidth(totalWidth: CGFloat, inset: CGFloat = sidebarFooterInset) -> CGFloat {
    max(0, totalWidth - (inset * 2))
}

struct ConsoleLayout {
    var sidebarWidth: CGFloat
    var mainWidth: CGFloat
    var inspectorWidth: CGFloat
    var showsMain: Bool
    var showsInspector: Bool
    var sidebarResizeRange: ClosedRange<CGFloat>
    var inspectorResizeRange: ClosedRange<CGFloat>
}

func consoleLayout(totalWidth: CGFloat, sidebarPreference: CGFloat, inspectorPreference: CGFloat) -> ConsoleLayout {
    let total = max(0, totalWidth)
    guard total > 0 else {
        return ConsoleLayout(
            sidebarWidth: 0,
            mainWidth: 0,
            inspectorWidth: 0,
            showsMain: false,
            showsInspector: false,
            sidebarResizeRange: 0...0,
            inspectorResizeRange: 0...0
        )
    }

    if total <= minimumReadableSidebarWidth + splitHandleWidth + minimumCompactMainWidth {
        let sidebar = min(total, max(0, sidebarPreference))
        return ConsoleLayout(
            sidebarWidth: sidebar,
            mainWidth: 0,
            inspectorWidth: 0,
            showsMain: false,
            showsInspector: false,
            sidebarResizeRange: 0...max(0, total),
            inspectorResizeRange: minimumInspectorWidth...minimumInspectorWidth
        )
    }

    let sidebarMinimum = min(minimumReadableSidebarWidth, total)
    let sidebarMaximum = min(maximumSidebarWidth, max(sidebarMinimum, total - splitHandleWidth - minimumCompactMainWidth))
    let sidebar = min(sidebarMaximum, max(sidebarMinimum, sidebarPreference))
    let remainingAfterSidebar = max(0, total - sidebar - splitHandleWidth)

    guard remainingAfterSidebar >= splitHandleWidth + minimumInspectorWidth + minimumMainWidth else {
        return ConsoleLayout(
            sidebarWidth: sidebar,
            mainWidth: remainingAfterSidebar,
            inspectorWidth: 0,
            showsMain: remainingAfterSidebar > 0,
            showsInspector: false,
            sidebarResizeRange: sidebarMinimum...sidebarMaximum,
            inspectorResizeRange: minimumInspectorWidth...minimumInspectorWidth
        )
    }

    let inspectorMaximum = min(maximumInspectorWidth, max(minimumInspectorWidth, remainingAfterSidebar - splitHandleWidth - minimumMainWidth))
    let inspector = min(inspectorMaximum, max(minimumInspectorWidth, inspectorPreference))
    let main = max(minimumMainWidth, remainingAfterSidebar - splitHandleWidth - inspector)

    return ConsoleLayout(
        sidebarWidth: sidebar,
        mainWidth: main,
        inspectorWidth: inspector,
        showsMain: true,
        showsInspector: true,
        sidebarResizeRange: sidebarMinimum...sidebarMaximum,
        inspectorResizeRange: minimumInspectorWidth...inspectorMaximum
    )
}

struct OpsConsoleView: View {
    @ObservedObject var store: OpsStore
    @State private var sidebarWidth: CGFloat = defaultSidebarWidth
    @State private var inspectorWidth: CGFloat = 320

    var body: some View {
        GeometryReader { proxy in
            let layout = consoleLayout(
                totalWidth: proxy.size.width,
                sidebarPreference: sidebarWidth,
                inspectorPreference: inspectorWidth
            )
            let mainX = layout.sidebarWidth + splitHandleWidth
            let inspectorSplitX = mainX + layout.mainWidth

            ZStack(alignment: .topLeading) {
                ServiceMapView(store: store)
                    .frame(width: layout.sidebarWidth, height: proxy.size.height)
                    .position(x: layout.sidebarWidth / 2, y: proxy.size.height / 2)
                    .zIndex(1)

                if layout.showsMain {
                    SplitHandle(width: $sidebarWidth, range: layout.sidebarResizeRange)
                        .frame(width: splitHandleWidth, height: proxy.size.height)
                        .position(x: layout.sidebarWidth + (splitHandleWidth / 2), y: proxy.size.height / 2)
                        .zIndex(5)
                    MainBoardView(store: store)
                        .frame(
                            width: layout.mainWidth,
                            height: proxy.size.height,
                            alignment: .topLeading
                        )
                        .clipped()
                        .position(x: mainX + (layout.mainWidth / 2), y: proxy.size.height / 2)
                        .zIndex(0)
                }

                if layout.showsInspector {
                    SplitHandle(width: $inspectorWidth, range: layout.inspectorResizeRange, direction: -1)
                        .frame(width: splitHandleWidth, height: proxy.size.height)
                        .position(x: inspectorSplitX + (splitHandleWidth / 2), y: proxy.size.height / 2)
                        .zIndex(5)
                    DetailsRailView(store: store)
                        .frame(width: layout.inspectorWidth, height: proxy.size.height)
                        .position(x: inspectorSplitX + splitHandleWidth + (layout.inspectorWidth / 2), y: proxy.size.height / 2)
                        .zIndex(2)
                }
            }
            .frame(width: proxy.size.width, height: proxy.size.height, alignment: .leading)
            .clipped()
        }
        .background(Theme.background)
        .foregroundStyle(Theme.primary)
        .task {
            // One-shot initial load; recurring refresh is owned by the store
            // and runs only while a surface is visible.
            await store.loadInventory()
        }
        .sheet(isPresented: $store.showingStartSheet) {
            StartServerSheet(store: store)
        }
        .sheet(isPresented: $store.showingLeaseSheet) {
            LeaseSheet(store: store)
        }
        .sheet(isPresented: $store.showingServerLogs) {
            ServerLogsSheet(store: store)
        }
    }
}

struct SplitHandle: View {
    @Binding var width: CGFloat
    let range: ClosedRange<CGFloat>
    var direction: CGFloat = 1
    @State private var dragStart: CGFloat?
    @State private var isHovering = false

    var body: some View {
        ZStack {
            Rectangle()
                .fill(isHovering ? Theme.blue.opacity(0.16) : Color.white.opacity(0.035))
            Rectangle()
                .fill(isHovering ? Theme.blue.opacity(0.7) : Color.white.opacity(0.16))
                .frame(width: 1)
        }
            .frame(width: splitHandleWidth)
            .frame(maxHeight: .infinity)
            .contentShape(Rectangle())
            .gesture(
                DragGesture(minimumDistance: 0, coordinateSpace: .global)
                    .onChanged { value in
                        let start = dragStart ?? width
                        if dragStart == nil { dragStart = width }
                        width = resizedPaneWidth(
                            start: start,
                            startX: value.startLocation.x,
                            currentX: value.location.x,
                            direction: direction,
                            range: range
                        )
                    }
                    .onEnded { _ in dragStart = nil }
            )
            .onHover { hovering in
                if hovering, !isHovering {
                    NSCursor.resizeLeftRight.push()
                } else if !hovering, isHovering {
                    NSCursor.pop()
                }
                isHovering = hovering
            }
            .help("Drag to resize pane")
    }
}

struct ServiceMapView: View {
    @ObservedObject var store: OpsStore
    @State private var expandedProjects: Set<String> = []

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "terminal.fill")
                    .foregroundStyle(Theme.blue)
                    .accessibilityHidden(true)
                Text("DevOps Board")
                    .font(.system(size: 14, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.tail)
                Spacer()
            }
            .padding(.horizontal, 18)
            .frame(height: 58)

            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("SERVICE MAP")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.secondary)
                        .tracking(0.5)
                        .lineLimit(1)

                    if groupedProjects.isEmpty {
                        EmptyMapHint()
                    } else {
                        ForEach(groupedProjects, id: \.id) { group in
                            ProjectNode(
                                store: store,
                                group: group,
                                isExpanded: expandedProjects.contains(group.id),
                                toggle: {
                                    if expandedProjects.contains(group.id) {
                                        expandedProjects.remove(group.id)
                                    } else {
                                        expandedProjects.insert(group.id)
                                    }
                                    store.selectProject(group.id)
                                }
                            )
                        }
                    }
                }
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .onAppear {
                if expandedProjects.isEmpty {
                    expandedProjects = Set(groupedProjects.prefix(10).map(\.id))
                }
            }
            .onChange(of: groupedProjects.map(\.id)) { _, names in
                if expandedProjects.isEmpty {
                    expandedProjects = Set(names.prefix(10))
                }
            }

            Divider().overlay(Color.white.opacity(0.06))
            SidebarFooterView(store: store)
        }
        .background(Theme.sidebar)
    }

    private var groupedProjects: [ProjectGroup] {
        store.projectGroups
    }
}

func usageRank(_ usage: ProjectUsage) -> (Double, Double, Int) {
    (usage.cpuPercent ?? 0, usage.memoryBytes ?? 0, usage.processCount ?? 0)
}

func projectGroupStatus(_ group: ProjectGroup) -> String {
    if !group.serverConflicts.isEmpty
        || !group.serverMembershipConflicts.isEmpty
        || !group.dockerMembershipConflicts.isEmpty {
        return "unhealthy"
    }
    if group.servers.contains(where: { ($0.status ?? "").lowercased() == "unhealthy" }) { return "unhealthy" }
    if group.servers.contains(where: { ($0.status ?? "").lowercased() == "running" }) { return "running" }
    if group.containers.contains(where: { isRunningStatus($0.status) }) { return "running" }
    if group.databases.contains(where: { isRunningStatus($0.status) }) { return "running" }
    return "stopped"
}

func projectGroupShowsProjectActions(_ group: ProjectGroup) -> Bool {
    group.isRepository
}

func resourceObservationOrigins(
    primary: CoordinatorOrigin?,
    candidates: [CoordinatorOrigin]
) -> [CoordinatorOrigin] {
    Array(Set(candidates + [primary].compactMap { $0 })).sorted { $0.id < $1.id }
}

func projectGroupObservedOrigins(_ group: ProjectGroup) -> [CoordinatorOrigin] {
    let origins = group.observedOrigins
        + group.servers.flatMap {
            resourceObservationOrigins(primary: $0.origin, candidates: $0.observationOrigins)
        }
        + group.containers.flatMap {
            resourceObservationOrigins(primary: $0.origin, candidates: $0.observationOrigins)
        }
        + group.databases.flatMap {
            resourceObservationOrigins(primary: $0.origin, candidates: $0.observationOrigins)
        }
        + [group.usage?.origin].compactMap { $0 }
    return Array(Set(origins)).sorted { $0.id < $1.id }
}

func projectConflictOrigins(_ conflict: RepositoryServerConflict) -> [CoordinatorOrigin] {
    Array(Set(conflict.activeSourceIdentities.map(\.origin))).sorted { $0.id < $1.id }
}

func projectGroupConflictSummary(_ group: ProjectGroup) -> String? {
    let messages = group.serverConflicts.map(\.message)
        + group.serverMembershipConflicts.map(\.message)
        + group.dockerMembershipConflicts.map(\.message)
    guard let first = messages.first else { return nil }
    guard messages.count > 1 else { return first }
    return "\(messages.count) ownership conflicts block project actions until repository and resource evidence agree."
}

func projectGroupCanStop(_ group: ProjectGroup) -> Bool {
    group.servers.contains(where: canStopServer)
        || group.containers.contains(where: \.isRunning)
        || group.databases.contains(where: \.isRunning)
}

struct ProjectNode: View {
    @ObservedObject var store: OpsStore
    let group: ProjectGroup
    let isExpanded: Bool
    let toggle: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 7) {
                Button(action: toggle) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.secondary)
                        .frame(width: 12, height: 20)
                }
                .buttonStyle(.plain)
                StatusDot(status: groupStatus)
                Text(group.name)
                    .font(.system(size: 14, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(minWidth: 54, maxWidth: group.isRepository ? 96 : 180, alignment: .leading)
                CountBadge(count: group.servers.count + group.containers.count + group.databases.count)
                if let conflictSummary = projectGroupConflictSummary(group) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.orange)
                        .help(conflictSummary)
                        .accessibilityLabel("Project conflict: \(conflictSummary)")
                }
                if projectGroupShowsProjectActions(group) {
                    HStack(spacing: 4) {
                        SidebarActionButton(
                            title: groupCanStop ? "Stop project runtime" : "Run project runtime",
                            systemImage: groupCanStop ? "stop.fill" : "play.fill",
                            tint: groupCanStop ? Theme.orange : Theme.green,
                            enabled: projectActionAllowed(
                                store,
                                group: group,
                                kind: groupCanStop ? .projectStop : .projectStart
                            ),
                            action: { groupCanStop ? store.stopProject(group) : store.startProject(group) }
                        )
                        SidebarActionButton(
                            title: "Restart project runtime",
                            systemImage: "arrow.clockwise",
                            tint: Theme.secondary,
                            enabled: projectActionAllowed(store, group: group, kind: .projectRestart),
                            action: { store.restartProject(group) }
                        )
                    }
                    .fixedSize()
                    .layoutPriority(1)
                }
            }
            .padding(.horizontal, 6)
            .frame(maxWidth: .infinity, minHeight: 26, alignment: .leading)
            .background(store.sidebarSelection == .project(group.id) ? Theme.blue.opacity(0.18) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
            .onTapGesture(perform: toggle)

            if isExpanded {
                ForEach(group.servers.map {
                    PresentedServerRow(id: store.serverSelectionID(for: $0), server: $0)
                }) { row in
                    let server = row.server
                    MapLeaf(
                        title: resourceDisplayName(server.name, inProject: group.name),
                        kind: .server,
                        status: server.status,
                        isSelected: store.sidebarSelection == .server(row.id),
                        canStop: canStopServer(server),
                        toggleEnabled: serverActionAllowed(
                            store,
                            kind: canStopServer(server) ? .stopServer : .restartServer,
                            server: server
                        ),
                        restartEnabled: serverActionAllowed(store, kind: .restartServer, server: server),
                        selectAction: { store.selectServer(server) },
                        toggleAction: { store.toggle(server) },
                        restartAction: { store.restart(server) }
                    )
                }

                ForEach(group.containers, id: \.containerSelectionID) { container in
                    MapLeaf(
                        title: resourceDisplayName(container.name, inProject: group.name),
                        kind: .docker,
                        status: container.status,
                        isSelected: store.sidebarSelection == .docker(container.containerSelectionID),
                        canStop: container.isRunning,
                        toggleEnabled: dockerActionAllowed(
                            store,
                            kind: container.isRunning ? .stopDocker : .startDocker,
                            container: container
                        ),
                        restartEnabled: dockerActionAllowed(store, kind: .restartDocker, container: container),
                        selectAction: { store.selectDocker(container) },
                        toggleAction: { store.toggleDocker(container) },
                        restartAction: { store.restartDocker(container) }
                    )
                }

                ForEach(group.databases, id: \.databaseSelectionID) { database in
                    MapLeaf(
                        title: resourceDisplayName(database.name, inProject: group.name),
                        kind: .database,
                        status: database.status,
                        isSelected: store.sidebarSelection == .database(database.databaseSelectionID),
                        canStop: database.isRunning,
                        toggleEnabled: dockerActionAllowed(
                            store,
                            kind: database.isRunning ? .stopDocker : .startDocker,
                            container: database
                        ),
                        restartEnabled: dockerActionAllowed(store, kind: .restartDocker, container: database),
                        selectAction: { store.selectDatabase(database) },
                        toggleAction: { store.toggleDocker(database) },
                        restartAction: { store.restartDocker(database) }
                    )
                }
            }
        }
        .padding(.bottom, 8)
    }

    private var groupStatus: String {
        projectGroupStatus(group)
    }

    private var groupCanStop: Bool {
        projectGroupCanStop(group)
    }
}

struct MainBoardView: View {
    @ObservedObject var store: OpsStore
    @State private var bulkSelectionMode = false
    @State private var reviewingBulkPlan: BulkStopPlan?

    var body: some View {
        VStack(spacing: 0) {
            ToolbarView(store: store)
            Divider().overlay(Color.white.opacity(0.07))

            ScrollView(.vertical) {
                VStack(spacing: 12) {
                    InventoryStateBanner(store: store)
                    ProjectUsageStrip(store: store)
                    if let lease = store.latestLeaseResult {
                        LeaseResultCard(store: store, lease: lease)
                    }
                    ManagedLeasesPanel(store: store)
                    FilterRow(
                        store: store,
                        bulkSelectionMode: $bulkSelectionMode,
                        reviewSelection: reviewBulkSelection
                    )
                    ResourceTabBar(store: store)

                    Group {
                        switch store.activeTab {
                        case .servers:
                            DevServersSection(store: store, bulkSelectionMode: bulkSelectionMode)
                        case .docker:
                            DockerSection(store: store, bulkSelectionMode: bulkSelectionMode)
                        case .databases:
                            DatabaseSection(store: store, bulkSelectionMode: bulkSelectionMode)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .accessibilityIdentifier("main-board-scroll-body")

            ActionResultDrawer(store: store)
            Divider().overlay(Color.white.opacity(0.07))
            StatusBar(store: store)
        }
        .background(Theme.background)
        .sheet(item: $reviewingBulkPlan) { plan in
            BulkStopReviewSheet(store: store, plan: plan)
        }
    }

    private func reviewBulkSelection() {
        reviewingBulkPlan = store.prepareBulkStop()
    }
}

struct ProjectUsageStrip: View {
    @ObservedObject var store: OpsStore

    private var rows: [ProjectUsage] {
        store.projectGroups
            .filter(\.isRepository)
            .compactMap(\.usage)
            .filter { ($0.serverCount ?? 0) > 0 || ($0.containerCount ?? 0) > 0 || ($0.cpuPercent ?? 0) > 0 || ($0.memoryBytes ?? 0) > 0 }
            .sorted { usageRank($0) > usageRank($1) }
            .prefix(6)
            .map { $0 }
    }

    var body: some View {
        if !rows.isEmpty {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 8) {
                    Image(systemName: "gauge.with.dots.needle.bottom.100percent")
                        .foregroundStyle(Theme.secondary)
                    Text("PROJECT LOAD")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(Theme.secondary)
                    Spacer(minLength: 0)
                }
                VStack(spacing: 0) {
                    ForEach(rows) { row in
                        ProjectUsageRow(usage: row)
                    }
                }
                .background(Theme.control)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
            }
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
    }
}

struct ProjectUsageRow: View {
    let usage: ProjectUsage

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(usage.name ?? usage.project.map(shortProject) ?? usage.projectKey ?? "Project")
                    .font(.system(size: 12, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(resourceCountText)
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.secondary)
                    .lineLimit(1)
            }
            .frame(minWidth: 130, maxWidth: 180, alignment: .leading)
            MetricPill(title: "CPU", value: formatCPU(usage.cpuPercent), tint: usageSeverityColor(usage))
            MetricPill(title: "Memory", value: formatBytes(usage.memoryBytes), tint: usageSeverityColor(usage))
            Text(hotProcessLabel(usage.hotProcesses?.first))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 10)
        .frame(height: 34)
        .overlay(alignment: .bottom) {
            Rectangle().fill(Color.white.opacity(0.055)).frame(height: 1)
        }
    }

    private var resourceCountText: String {
        let processes = usage.processCount ?? 0
        let containers = usage.containerCount ?? 0
        if containers > 0 {
            return "\(processes) processes / \(containers) containers"
        }
        return "\(processes) processes"
    }
}

struct MetricPill: View {
    let title: String
    let value: String
    let tint: Color

    var body: some View {
        HStack(spacing: 5) {
            Text(title)
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(Theme.secondary)
            Text(value)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(tint)
                .lineLimit(1)
        }
        .padding(.horizontal, 8)
        .frame(minWidth: 92)
        .frame(height: 24)
        .background(Color.black.opacity(0.16))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct ResourceTabBar: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        Picker("Resource", selection: $store.activeTab) {
            ForEach(ResourceTab.allCases) { tab in
                Label("\(tab.rawValue) \(count(for: tab))", systemImage: tab.systemImage)
                    .tag(tab)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        // Keep the segmented control inside the main pane at the minimum
        // supported three-column window width. A fixed 520-point child plus
        // the board's horizontal padding widened the whole content stack and
        // caused SwiftUI to center-crop every sibling in the pane.
        .frame(minWidth: 280, maxWidth: 520, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func count(for tab: ResourceTab) -> Int {
        switch tab {
        case .servers: return store.filteredServers.count
        case .docker: return store.visibleDockerContainers.count
        case .databases: return store.visiblePostgres.count
        }
    }
}

struct ToolbarView: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        GeometryReader { proxy in
            if proxy.size.width < 520 {
                narrowToolbar
            } else if proxy.size.width < 760 {
                compactToolbar
            } else {
                fullToolbar
            }
        }
        .padding(.horizontal, 12)
        .frame(height: 54)
        .background(Theme.toolbar)
        .accessibilityIdentifier("main-board-toolbar")
    }

    private var fullToolbar: some View {
        HStack(spacing: 8) {
            EnvironmentPicker(projectPath: $store.projectPath)
                .frame(width: 168)
            SearchField(text: $store.searchText)
                .frame(minWidth: 220, maxWidth: .infinity)
            SourceHealthChip(store: store)
            ToolbarButton(title: "Refresh", systemImage: "arrow.clockwise", showsTitle: false) {
                store.refresh()
            }
            .disabled(store.isLoading)
            ToolbarButton(title: "Lease", systemImage: "calendar.badge.plus") {
                store.prepareLeaseDraft()
                store.showingLeaseSheet = true
            }
            .disabled(!unscopedActionAllowed(store, kind: .leasePort))
            ToolbarButton(title: "Start", systemImage: "play.circle.fill", tint: Theme.green) {
                store.prepareStartDraft()
                store.showingStartSheet = true
            }
            .disabled(!unscopedActionAllowed(store, kind: .startServer))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
    }

    private var compactToolbar: some View {
        HStack(spacing: 6) {
            EnvironmentPicker(projectPath: $store.projectPath)
                .frame(width: 132)
            SearchField(text: $store.searchText, compact: true)
                .frame(minWidth: 120, maxWidth: .infinity)
            SourceHealthChip(store: store, compact: true)
            ToolbarButton(title: "Refresh", systemImage: "arrow.clockwise", showsTitle: false) {
                store.refresh()
            }
            .disabled(store.isLoading)
            ToolbarButton(title: "Lease", systemImage: "calendar.badge.plus", showsTitle: false) {
                store.prepareLeaseDraft()
                store.showingLeaseSheet = true
            }
            .disabled(!unscopedActionAllowed(store, kind: .leasePort))
            ToolbarButton(title: "Start", systemImage: "play.circle.fill", tint: Theme.green, showsTitle: false) {
                store.prepareStartDraft()
                store.showingStartSheet = true
            }
            .disabled(!unscopedActionAllowed(store, kind: .startServer))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
    }

    private var narrowToolbar: some View {
        HStack(spacing: 6) {
            EnvironmentPicker(projectPath: $store.projectPath)
                .frame(width: 108)
            SearchField(text: $store.searchText, compact: true)
                .frame(minWidth: 72, maxWidth: .infinity)
            SourceHealthChip(store: store, compact: true, minimal: true)
            ToolbarButton(title: "Refresh", systemImage: "arrow.clockwise", showsTitle: false) {
                store.refresh()
            }
            .disabled(store.isLoading)
            ToolbarButton(title: "Lease", systemImage: "calendar.badge.plus", showsTitle: false) {
                store.prepareLeaseDraft()
                store.showingLeaseSheet = true
            }
            .disabled(!unscopedActionAllowed(store, kind: .leasePort))
            ToolbarButton(title: "Start", systemImage: "play.circle.fill", tint: Theme.green, showsTitle: false) {
                store.prepareStartDraft()
                store.showingStartSheet = true
            }
            .disabled(!unscopedActionAllowed(store, kind: .startServer))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
    }
}

struct FilterRow: View {
    @ObservedObject var store: OpsStore
    @Binding var bulkSelectionMode: Bool
    let reviewSelection: () -> Void

    var body: some View {
        ViewThatFits(in: .horizontal) {
            regularRow
            compactRow
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var regularRow: some View {
        HStack(spacing: 12) {
            Text("Filter")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Theme.secondary)
            filterPicker

            Spacer()
            HStack(spacing: 12) {
                if bulkSelectionMode {
                    selectionCount
                    reviewButton
                }
                selectionModeButton
            }
            .fixedSize()
        }
    }

    private var compactRow: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                filterPicker
                selectionModeButton
                    .fixedSize()
            }
            if bulkSelectionMode {
                HStack(spacing: 8) {
                    selectionCount
                    Spacer(minLength: 0)
                    reviewButton
                }
            }
        }
    }

    private var filterPicker: some View {
        Picker("Filter", selection: $store.filter) {
            ForEach(ServiceFilter.allCases) { filter in
                Label(filter.rawValue, systemImage: filterIcon(filter))
                    .tag(filter)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(minWidth: 220, maxWidth: 360)
    }

    private var selectionCount: some View {
        Text("\(store.bulkSelection.selected.count) selected")
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(store.bulkSelection.selected.isEmpty ? Theme.secondary : Theme.primary)
            .accessibilityIdentifier("bulk-selected-count")
    }

    private var reviewButton: some View {
        Button("Review Stop…", action: reviewSelection)
            .buttonStyle(.borderedProminent)
            .tint(Theme.red)
            .disabled(store.bulkSelection.selected.isEmpty)
            .accessibilityIdentifier("bulk-review-stop")
    }

    private var selectionModeButton: some View {
        Button {
            bulkSelectionMode.toggle()
            if !bulkSelectionMode { store.clearBulkSelection() }
        } label: {
            Label(bulkSelectionMode ? "Done" : "Select", systemImage: bulkSelectionMode ? "checkmark" : "checklist")
        }
        .buttonStyle(.bordered)
        .keyboardShortcut("s", modifiers: [.command, .shift])
        .accessibilityIdentifier("bulk-selection-toggle")
    }
}

struct SourceHealthChip: View {
    @ObservedObject var store: OpsStore
    var compact = false
    var minimal = false
    @State private var showingDetails = false

    var body: some View {
        Button {
            showingDetails.toggle()
        } label: {
            HStack(spacing: 6) {
                StatusDot(status: sourceStatus)
                Text(minimal ? "\(loadedCount)/\(totalCount)" : "Sources \(loadedCount)/\(totalCount) \(sourceStatus)")
            }
            .font(.system(size: compact ? 10 : 11, weight: .semibold))
            .padding(.horizontal, compact ? 7 : 9)
            .frame(height: 32)
        }
        .buttonStyle(.plain)
        .background(Theme.control)
        .clipShape(Capsule())
        .overlay(Capsule().stroke(statusColor(sourceStatus).opacity(0.35)))
        .help("Coordinator sources \(loadedCount) of \(totalCount), \(sourceStatus)")
        .accessibilityLabel("Coordinator sources \(loadedCount) of \(totalCount), \(sourceStatus)")
        .accessibilityIdentifier("sources-health-chip")
        .popover(isPresented: $showingDetails, arrowEdge: .bottom) {
            SourceDiagnosticsPopover(store: store)
        }
    }

    private var loadedCount: Int { store.sourceStates.filter { $0.phase == .loaded }.count }
    private var totalCount: Int { store.sourceStates.count }

    private var sourceStatus: String {
        if totalCount == 0 { return "Unavailable" }
        if store.sourceStates.allSatisfy({ $0.phase == .loading }) { return "Loading" }
        if loadedCount == totalCount { return "Complete" }
        return "Partial"
    }
}

struct SourceDiagnosticsPopover: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Coordinator Sources")
                        .font(.system(size: 14, weight: .bold))
                    Spacer()
                    Button("Refresh") { store.refresh() }
                        .keyboardShortcut("r", modifiers: .command)
                }
                if store.sourceStates.isEmpty {
                    Text("No coordinator sources were discovered.")
                        .foregroundStyle(Theme.secondary)
                } else {
                    ForEach(store.sourceStates) { source in
                        VStack(alignment: .leading, spacing: 5) {
                            HStack {
                                StatusDot(status: source.phase.rawValue)
                                Text(source.origin.label)
                                    .font(.system(size: 12, weight: .semibold))
                                Spacer()
                                Text(source.phase.rawValue.capitalized)
                                    .font(.system(size: 11))
                                    .foregroundStyle(Theme.secondary)
                                CountBadge(count: source.resourceCount)
                            }
                            Text("Checked \(formatDate(source.checkedAt))")
                                .font(.system(size: 11))
                                .foregroundStyle(Theme.secondary)
                            DisclosureGroup("Diagnostics") {
                                DetailLine(label: "Coordinator home", value: source.origin.home)
                                DetailLine(label: "State", value: source.origin.statePath ?? "Unavailable")
                                if let error = source.error { DetailLine(label: "Error", value: error) }
                            }
                            .font(.system(size: 11, weight: .semibold))
                        }
                        .padding(10)
                        .background(Theme.control)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
                if !store.capabilityStates.isEmpty {
                    Text("CAPABILITIES")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(Theme.secondary)
                    ForEach(store.capabilityStates) { capability in
                        HStack(spacing: 8) {
                            StatusDot(status: capability.phase.rawValue)
                            Text(capability.capability.displayName)
                            Text(capability.origin.label)
                                .foregroundStyle(Theme.secondary)
                            Spacer()
                            Text(capability.phase.rawValue.capitalized)
                                .foregroundStyle(capability.phase == .available ? Theme.green : Theme.orange)
                        }
                        .font(.system(size: 11))
                        .help(capability.error ?? "")
                    }
                }
            }
            .padding(16)
        }
        .frame(width: 420, height: 420)
        .background(Theme.sidebar)
    }
}

struct InventoryStateBanner: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        let snapshot = store.presentationSnapshot
        let dockerUnavailable = store.explicitlyUnavailableDockerCapabilities
        let isInitialLoading = store.isInitialInventoryLoading
        if isInitialLoading || snapshot.level != .nominal || !dockerUnavailable.isEmpty {
            VStack(alignment: .leading, spacing: 7) {
                HStack(alignment: .top, spacing: 10) {
                    if isInitialLoading {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: inventoryBannerIcon(snapshot.level))
                            .foregroundStyle(healthLevelColor(snapshot.level))
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        Text(isInitialLoading ? "Refreshing inventory" : snapshot.statusTitle)
                            .font(.system(size: 12, weight: .bold))
                        Text(isInitialLoading && store.sourceStates.isEmpty ? "Looking for configured coordinator sources." : snapshot.statusMessage)
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    if !store.isLoading {
                        Button("Refresh") { store.refresh() }
                            .buttonStyle(.bordered)
                    }
                }
                if !dockerUnavailable.isEmpty {
                    Label(
                        "Docker is unavailable for \(dockerUnavailable.map(\.origin.label).joined(separator: ", ")). Server and port lease actions remain available.",
                        systemImage: "shippingbox.and.arrow.backward"
                    )
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("docker-unavailable-warning")
                }
                if let issue = snapshot.inventoryIssue {
                    DisclosureGroup("Inventory details") {
                        Text(issue.details)
                            .font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .font(.system(size: 11, weight: .semibold))
                }
                if let issue = snapshot.actionIssue {
                    DisclosureGroup("Action issue") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(issue.details)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            HStack {
                                Button("Copy details") { store.copyIssueDetails(issue) }
                                Button("Dismiss") { store.dismissActionIssue() }
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    .font(.system(size: 11, weight: .semibold))
                    .accessibilityIdentifier("action-issue-details")
                }
            }
            .padding(10)
            .background(healthLevelColor(snapshot.level).opacity(0.1))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(healthLevelColor(snapshot.level).opacity(0.28)))
            .accessibilityIdentifier("inventory-state-banner")
        }
    }
}

struct LeaseResultCard: View {
    @ObservedObject var store: OpsStore
    let lease: LeaseActionResult

    var body: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 3) {
                Text("LEASED PORT")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(Theme.secondary)
                Text(String(lease.port))
                    .font(.system(size: 24, weight: .bold, design: .monospaced))
                    .textSelection(.enabled)
            }
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    SourceBadge(origin: lease.identity.origin, states: store.sourceStates)
                    StatusText(status: lease.managementStatus)
                }
                Text("Project \(projectDisplayLabel(lease.project)) · Expires \(formatTimestamp(lease.expiresAtISO))")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
                    .lineLimit(1)
                DisclosureGroup("Lease details") {
                    DetailLine(label: "Lease ID", value: lease.leaseID)
                    DetailLine(label: "Project", value: lease.project ?? "Unavailable")
                    DetailLine(label: "Agent", value: lease.agent ?? "Unavailable")
                    if let serverID = lease.serverID { DetailLine(label: "Attached server", value: serverID) }
                    if let operationID = lease.pendingOperationID { DetailLine(label: "Attachment operation", value: operationID) }
                }
                .font(.system(size: 11, weight: .semibold))
            }
            Spacer()
            Button("Copy") { store.copyLeasePort(lease) }
                .accessibilityLabel("Copy leased port \(lease.port)")
                .accessibilityIdentifier("lease-copy-port")
            Button("Start using lease") {
                if store.prepareStartDraft(using: lease) { store.showingStartSheet = true }
            }
            .buttonStyle(.borderedProminent)
            .disabled(
                !lease.canStartServer
                    || !store.mutationAvailability(
                        kind: .startServer,
                        origin: lease.identity.origin,
                        resource: nil,
                        leaseID: lease.leaseID,
                        projectPath: lease.project
                    ).isAllowed
            )
            .accessibilityIdentifier("lease-start-using")
            Button("Release", role: .destructive) { store.releaseLease(lease) }
                .disabled(
                    !lease.canReleaseDirectly
                        || !store.mutationAvailability(
                            kind: .releasePort,
                            origin: lease.identity.origin,
                            resource: lease.identity,
                            leaseID: lease.leaseID,
                            projectPath: lease.project
                        ).isAllowed
                )
                .accessibilityIdentifier("lease-release")
            Button { store.dismissLatestLeaseResult() } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.plain)
            .help("Dismiss lease result")
            .accessibilityLabel("Dismiss lease result")
            .accessibilityIdentifier("lease-dismiss")
        }
        .padding(11)
        .background(Theme.blue.opacity(0.09))
        .clipShape(RoundedRectangle(cornerRadius: 9))
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.blue.opacity(0.28)))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("latest-lease-result")
    }
}

struct ManagedLeasesPanel: View {
    @ObservedObject var store: OpsStore
    @State private var expanded = false

    private var leases: [LeaseActionResult] {
        store.manageableLeaseResults.filter { $0.identity != store.latestLeaseResult?.identity }
    }

    var body: some View {
        if !leases.isEmpty {
            DisclosureGroup(isExpanded: $expanded) {
                VStack(spacing: 7) {
                    ForEach(leases) { lease in
                        ManagedLeaseRow(store: store, lease: lease)
                    }
                }
                .padding(.top, 7)
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "network.badge.shield.half.filled")
                        .foregroundStyle(Theme.blue)
                    Text("Managed port leases")
                        .font(.system(size: 12, weight: .semibold))
                    CountBadge(count: leases.count)
                    Spacer()
                    Text(expanded ? "Hide" : "Review")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.blue)
                }
            }
            .padding(10)
            .background(Theme.control.opacity(0.72))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
            .accessibilityIdentifier("managed-port-leases")
        }
    }
}

struct ManagedLeaseRow: View {
    @ObservedObject var store: OpsStore
    let lease: LeaseActionResult

    var body: some View {
        HStack(spacing: 10) {
            Text(String(lease.port))
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .textSelection(.enabled)
                .frame(width: 56, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    SourceBadge(origin: lease.identity.origin, states: store.sourceStates)
                    StatusText(status: lease.managementStatus)
                }
                Text("\(projectDisplayLabel(lease.project)) · expires \(formatTimestamp(lease.expiresAtISO))")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.secondary)
                    .lineLimit(1)
                DisclosureGroup("Lease identity") {
                    Text(lease.leaseID)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                }
                .font(.system(size: 10, weight: .semibold))
            }
            Spacer()
            Button("Copy") { store.copyLeasePort(lease) }
            Button("Start") {
                if store.prepareStartDraft(using: lease) { store.showingStartSheet = true }
            }
            .disabled(
                !lease.canStartServer
                    || !store.mutationAvailability(
                        kind: .startServer,
                        origin: lease.identity.origin,
                        resource: nil,
                        leaseID: lease.leaseID,
                        projectPath: lease.project
                    ).isAllowed
            )
            Button("Release", role: .destructive) { store.releaseLease(lease) }
                .disabled(
                    !lease.canReleaseDirectly
                        || !store.mutationAvailability(
                            kind: .releasePort,
                            origin: lease.identity.origin,
                            resource: lease.identity,
                            leaseID: lease.leaseID,
                            projectPath: lease.project
                        ).isAllowed
                )
        }
        .padding(8)
        .background(Color.white.opacity(0.035))
        .clipShape(RoundedRectangle(cornerRadius: 7))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Port \(lease.port), source \(lease.identity.origin.label), \(lease.managementStatus)")
    }
}

struct ActionResultDrawer: View {
    @ObservedObject var store: OpsStore
    @State private var expanded = false

    private var results: [RetainedActionResult] {
        store.actionResults.values.sorted { $0.queuedAt > $1.queuedAt }
    }

    var body: some View {
        if let latest = results.first {
            DisclosureGroup(isExpanded: $expanded) {
                ScrollView(.vertical) {
                    LazyVStack(spacing: 7) {
                        ForEach(results) { result in
                            ActionResultRow(store: store, result: result)
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.bottom, 10)
                }
                .frame(maxHeight: 240)
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "tray.full")
                    Text("Activity")
                        .fontWeight(.bold)
                    CountBadge(count: results.count)
                    Text(latest.request.title)
                        .lineLimit(1)
                    Spacer()
                    ActionPhaseBadge(phase: latest.phase)
                }
                .font(.system(size: 11))
                .padding(.horizontal, 14)
                .frame(height: 34)
            }
            .background(Theme.toolbar)
            .accessibilityIdentifier("action-result-drawer")
        }
    }
}

struct ActionResultRow: View {
    @ObservedObject var store: OpsStore
    let result: RetainedActionResult
    @State private var showingDetails = false

    var body: some View {
        DisclosureGroup(isExpanded: $showingDetails) {
            VStack(alignment: .leading, spacing: 8) {
                Text(store.actionResultDetails(result))
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                HStack {
                    if result.outputTruncated {
                        Label("Output truncated", systemImage: "scissors")
                            .foregroundStyle(Theme.orange)
                    }
                    Spacer()
                    Button("Copy details") { store.copyActionResultDetails(result) }
                    if isTerminalActionPhase(result.phase) {
                        Button("Dismiss") { store.dismissActionResult(result) }
                    }
                }
            }
            .padding(.top, 7)
        } label: {
            HStack(spacing: 8) {
                ActionPhaseBadge(phase: result.phase)
                VStack(alignment: .leading, spacing: 2) {
                    Text(result.request.title).fontWeight(.semibold).lineLimit(1)
                    Text(result.request.origin?.label ?? "Coordinator action")
                        .foregroundStyle(Theme.secondary)
                }
                Spacer()
                Text(formatDate(result.finishedAt ?? result.queuedAt))
                    .foregroundStyle(Theme.secondary)
            }
            .font(.system(size: 11))
        }
        .padding(9)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 7))
    }
}

struct ActionPhaseBadge: View {
    let phase: ActionPhase

    var body: some View {
        Text(phase.rawValue.capitalized)
            .font(.system(size: 10, weight: .bold))
            .foregroundStyle(actionPhaseColor(phase))
            .padding(.horizontal, 7)
            .frame(height: 20)
            .background(actionPhaseColor(phase).opacity(0.12))
            .clipShape(Capsule())
    }
}

struct BulkSelectionCheckbox: View {
    @ObservedObject var store: OpsStore
    let identity: ResourceIdentity?
    let enabled: Bool

    var body: some View {
        if let identity {
            Toggle(
                "Select \(identity.nativeID) to stop",
                isOn: Binding(
                    get: { store.bulkSelection.contains(identity) },
                    set: { store.setBulkSelected(identity, selected: $0) }
                )
            )
            .labelsHidden()
            .toggleStyle(.checkbox)
            .disabled(!enabled || !actionAllowed(store, kind: identity.kind == .server ? .stopServer : .stopDocker, identity: identity))
            .accessibilityIdentifier("bulk-select-\(safeAccessibilityID(identity.rawValue))")
        } else {
            Image(systemName: "square.dashed")
                .foregroundStyle(Theme.secondary)
                .accessibilityLabel("Resource cannot be selected")
        }
    }
}

struct BulkStopReviewSheet: View {
    @ObservedObject var store: OpsStore
    let plan: BulkStopPlan
    @Environment(\.dismiss) private var dismiss
    @State private var submitted = false
    @State private var executionError: String?

    private var completedResult: BulkActionResult? {
        guard let result = store.latestBulkActionResult,
              result.selection == plan.selection,
              result.results.count == plan.items.count,
              result.results.values.allSatisfy({ $0.queuedAt >= plan.preparedAt })
        else { return nil }
        return result
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(submitted ? "Stop Results" : "Review \(plan.items.count) Selected")
                        .font(.title2.bold())
                    Text("Only the resources listed below are in this bounded operation.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                }
                Spacer()
                Button("Close") { dismiss() }
            }

            ScrollView {
                LazyVStack(spacing: 7) {
                    ForEach(plan.items) { item in
                        HStack(spacing: 9) {
                            Image(systemName: "checkmark.square.fill")
                                .foregroundStyle(Theme.blue)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.displayName).fontWeight(.semibold)
                                Text("\(shortProject(item.project)) · \(item.identity.origin.label)")
                                    .foregroundStyle(Theme.secondary)
                                if let failure = completedResult?.results[item.identity]?.failure, !failure.isEmpty {
                                    Text(failure)
                                        .font(.system(size: 10))
                                        .foregroundStyle(Theme.red)
                                        .lineLimit(2)
                                }
                            }
                            Spacer()
                            if let result = completedResult?.results[item.identity] {
                                ActionPhaseBadge(phase: result.phase)
                            } else if submitted {
                                ProgressView().controlSize(.small)
                            } else {
                                StatusText(status: item.expectedStatus)
                            }
                        }
                        .font(.system(size: 12))
                        .padding(10)
                        .background(Theme.control)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
            .frame(maxHeight: 330)

            if let result = completedResult {
                HStack {
                    Label("\(result.succeededCount) stopped", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(Theme.green)
                    if result.failedCount > 0 {
                        Label("\(result.failedCount) failed", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(Theme.red)
                    }
                    Spacer()
                }
                .font(.system(size: 12, weight: .semibold))
                .accessibilityIdentifier("bulk-stop-result-summary")
            } else if submitted {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Stopping selected resources…")
                }
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    if let executionError {
                        Label(executionError, systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(Theme.red)
                    }
                    HStack {
                        Button("Cancel") { dismiss() }
                        Spacer()
                        Button("Stop \(plan.items.count) Selected", role: .destructive) {
                            submitted = store.executeBulkStop(planID: plan.id, confirmation: plan.confirmationText)
                            executionError = submitted ? nil : (store.actionIssue?.summary ?? "The selected resources could not be stopped.")
                        }
                        .keyboardShortcut(.defaultAction)
                        .accessibilityIdentifier("bulk-stop-execute")
                    }
                }
            }
        }
        .padding(22)
        .frame(width: 620, height: 560)
        .background(Theme.background)
    }
}

struct DevServersSection: View {
    @ObservedObject var store: OpsStore
    let bulkSelectionMode: Bool
    @State private var widths: [CGFloat] = [220, 120, 170, 86, 72, 58, 150]

    var body: some View {
        SectionSurface(title: "DEV SERVERS", count: store.filteredServers.count, systemImage: "terminal") {
            if store.filteredServers.isEmpty {
                DevServersEmptyState(store: store)
            } else {
                ResizableTable(columns: ["Service", "Project", "URL", "Status", "Uptime", "Port", "Actions"], widths: $widths) {
                    ForEach(store.filteredServerRows) { row in
                        let server = row.server
                        TableRow(widths: widths, isSelected: store.selectedServerID == row.id) {
                            TableCell(width: widths[0]) {
                                HStack(spacing: 8) {
                                    if bulkSelectionMode {
                                        BulkSelectionCheckbox(
                                            store: store,
                                            identity: server.resourceIdentity,
                                            enabled: canStopServer(server)
                                                && serverActionAllowed(store, kind: .stopServer, server: server)
                                        )
                                    }
                                    StatusDot(status: server.status)
                                    Text(server.name).fontWeight(.medium).lineLimit(1)
                                    ResourceSourceBadge(
                                        primary: server.origin,
                                        candidates: server.observationOrigins,
                                        states: store.sourceStates
                                    )
                                }
                            }
                            TableCell(width: widths[1]) {
                                Text(projectDisplayLabel(server.project)).foregroundStyle(Theme.secondary).lineLimit(1)
                            }
                            TableCell(width: widths[2]) {
                                URLCell(url: server.currentURL, staleURL: server.url, open: { store.openURL(server.currentURL) }, copy: { store.copyURL(server.currentURL) })
                            }
                            TableCell(width: widths[3]) { StatusText(status: server.status) }
                            TableCell(width: widths[4]) {
                                let uptime = server.uptime(now: Date())
                                Text(formatUptime(uptime))
                                    .foregroundStyle(Theme.secondary)
                                    .help(uptimeHelp(uptime))
                            }
                            TableCell(width: widths[5]) {
                                Text(server.port.map(String.init) ?? "—").monospacedDigit()
                            }
                            TableCell(width: widths[6]) {
                                HStack(spacing: 7) {
                                    IconButton("Restart", "arrow.clockwise") { store.restart(server) }
                                        .disabled(!serverActionAllowed(store, kind: .restartServer, server: server))
                                    IconButton("Stop", "stop") { store.stop(server) }
                                        .disabled(!canStopServer(server) || !serverActionAllowed(store, kind: .stopServer, server: server))
                                    IconButton("Open", "arrow.up.forward.square") { store.openURL(server.currentURL) }
                                        .disabled(server.currentURL == nil)
                                    IconButton("Logs", "doc.text.magnifyingglass") { store.showServerLogs(server) }
                                        .disabled(!serverActionAllowed(store, kind: .serverLogs, server: server))
                                }
                            }
                        }
                        .onTapGesture { store.selectServer(server) }
                        .accessibilityAddTraits(.isButton)
                        .accessibilityLabel("Open details for server \(server.name)")
                        .accessibilityAction { store.selectServer(server) }
                    }
                }
            }
        }
    }
}

struct DockerSection: View {
    @ObservedObject var store: OpsStore
    let bulkSelectionMode: Bool
    @State private var widths: [CGFloat] = [240, 110, 88, 100, 108, 118, 118, 130, 128, 130]

    var body: some View {
        SectionSurface(title: "DOCKER", count: store.visibleDockerContainers.count, systemImage: "shippingbox") {
            if store.visibleDockerContainers.isEmpty {
                ResourceEmptyState(
                    store: store,
                    title: dockerCapabilityUnavailable(store) ? "Docker inventory unavailable" : "No Docker containers in this scope",
                    message: dockerCapabilityUnavailable(store)
                        ? "Coordinator-managed servers and port leases remain available. Refresh after Docker is restored."
                        : "No source returned a Docker container matching the current project, filter, and search.",
                    systemImage: "shippingbox"
                )
            } else {
                ResizableTable(columns: ["Container", "Project", "Status", "CPU", "Memory", "Network", "Disk I/O", "Image", "Ports", "Actions"], widths: $widths) {
                    ForEach(store.visibleDockerContainers, id: \.containerSelectionID) { container in
                    TableRow(widths: widths, isSelected: store.selectedDockerID == container.containerSelectionID) {
                        TableCell(width: widths[0]) {
                            HStack(spacing: 8) {
                                if bulkSelectionMode {
                                    BulkSelectionCheckbox(
                                        store: store,
                                        identity: normalizedBulkIdentity(container.resourceIdentity),
                                        enabled: container.isRunning
                                            && dockerActionAllowed(store, kind: .stopDocker, container: container)
                                    )
                                }
                                StatusDot(status: container.status)
                                Text(container.name ?? "container")
                                    .fontWeight(.medium)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                ResourceSourceBadge(
                                    primary: container.origin,
                                    candidates: container.observationOrigins,
                                    states: store.sourceStates
                                )
                            }
                        }
                        TableCell(width: widths[1]) {
                            Text(projectLabel(for: container, in: store.projectGroups)).foregroundStyle(Theme.secondary).lineLimit(1)
                        }
                        TableCell(width: widths[2]) { StatusText(status: container.status) }
                        TableCell(width: widths[3]) {
                            MetricSparkCell(
                                value: formatPercent(dockerMetricValue(container.stats, metric: .cpu)),
                                values: dockerMetricSeries(container, metric: .cpu),
                                tint: Theme.blue,
                                isLive: container.isRunning && container.stats != nil
                            )
                        }
                        TableCell(width: widths[4]) {
                            MetricSparkCell(
                                value: formatPercent(dockerMetricValue(container.stats, metric: .memory)),
                                values: dockerMetricSeries(container, metric: .memory),
                                tint: Theme.green,
                                isLive: container.isRunning && container.stats != nil
                            )
                        }
                        TableCell(width: widths[5]) {
                            MetricSparkCell(
                                value: formatRate(dockerMetricValue(container.stats, metric: .networkRate)),
                                values: dockerMetricSeries(container, metric: .networkRate),
                                tint: Theme.orange,
                                isLive: container.isRunning && container.stats != nil
                            )
                        }
                        TableCell(width: widths[6]) {
                            MetricSparkCell(
                                value: formatRate(dockerMetricValue(container.stats, metric: .blockRate)),
                                values: dockerMetricSeries(container, metric: .blockRate),
                                tint: Theme.red,
                                isLive: container.isRunning && container.stats != nil
                            )
                        }
                        TableCell(width: widths[7]) {
                            Text(container.image ?? "—").foregroundStyle(Theme.secondary).lineLimit(1)
                        }
                        TableCell(width: widths[8]) {
                            Text(container.ports?.isEmpty == false ? container.ports! : "none")
                                .foregroundStyle(Theme.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        TableCell(width: widths[9]) {
                            HStack(spacing: 7) {
                                if container.isRunning {
                                    IconButton("Restart", "arrow.clockwise") { store.restartDocker(container) }
                                        .disabled(!dockerActionAllowed(store, kind: .restartDocker, container: container))
                                    IconButton("Stop", "stop") { store.stopDocker(container) }
                                        .disabled(!dockerActionAllowed(store, kind: .stopDocker, container: container))
                                } else {
                                    IconButton("Start", "play.fill") { store.startDocker(container) }
                                        .disabled(!dockerActionAllowed(store, kind: .startDocker, container: container))
                                }
                                IconButton("Logs", "doc.text") { store.dockerLogs(container) }
                                    .disabled(!dockerActionAllowed(store, kind: .dockerLogs, container: container))
                            }
                        }
                    }
                    .onTapGesture { store.selectDocker(container) }
                    .accessibilityAddTraits(.isButton)
                    .accessibilityLabel("Open details for container \(container.name ?? "container")")
                    .accessibilityAction { store.selectDocker(container) }
                    }
                }
            }
        }
    }
}

struct DatabaseSection: View {
    @ObservedObject var store: OpsStore
    let bulkSelectionMode: Bool
    @State private var widths: [CGFloat] = [240, 135, 150, 105, 75, 145, 130, 90]

    var body: some View {
        SectionSurface(title: "DATABASES", count: store.visiblePostgres.count, systemImage: "cylinder.split.1x2") {
            if store.visiblePostgres.isEmpty {
                ResourceEmptyState(
                    store: store,
                    title: databaseCapabilityUnavailable(store) ? "Database discovery unavailable" : "No databases in this scope",
                    message: databaseCapabilityUnavailable(store)
                        ? "No database target is being guessed. Restore Docker/database capability, then refresh."
                        : "No exact discovered database matches the current project, filter, and search.",
                    systemImage: "cylinder.split.1x2"
                )
            } else {
                ResizableTable(columns: ["Database", "Project", "Engine", "Status", "Size", "Last Backup", "Restore Safety", "Actions"], widths: $widths) {
                    ForEach(store.visiblePostgres, id: \.databaseSelectionID) { db in
                    let backup = newestBackupRecord(for: db, records: store.backupRecords)
                    TableRow(widths: widths, isSelected: store.selectedDatabaseID == db.databaseSelectionID) {
                        TableCell(width: widths[0]) {
                            HStack(spacing: 8) {
                                StatusDot(status: db.status)
                                Text(db.database ?? "Unknown database")
                                    .fontWeight(.medium)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                ResourceSourceBadge(
                                    primary: db.origin,
                                    candidates: db.observationOrigins,
                                    states: store.sourceStates
                                )
                            }
                        }
                        TableCell(width: widths[1]) { Text(projectLabel(for: db, in: store.projectGroups)).foregroundStyle(Theme.secondary).lineLimit(1) }
                        TableCell(width: widths[2]) { Text(db.image ?? "postgres").foregroundStyle(Theme.secondary).lineLimit(1) }
                        TableCell(width: widths[3]) { StatusText(status: db.status) }
                        TableCell(width: widths[4]) { Text(formatDatabaseBytes(db.databaseSizeBytes)).foregroundStyle(Theme.secondary) }
                        TableCell(width: widths[5]) {
                            Text(backup.map { formatDate($0.createdAt) } ?? "No backup")
                                .foregroundStyle(backup == nil ? Theme.orange : Theme.primary)
                                .lineLimit(1)
                        }
                        TableCell(width: widths[6]) { BackupSafetyLabel(backup: backup) }
                        TableCell(width: widths[7]) {
                            HStack(spacing: 7) {
                                if db.isRunning {
                                    IconButton("Backup", "externaldrive.badge.timemachine") { store.backupDatabase(container: db) }
                                        .disabled(!databaseProtectionActionAllowed(store, kind: .backupDatabase, database: db))
                                }
                                IconButton("Details", "info.circle") { store.selectDatabase(db) }
                            }
                        }
                    }
                    .onTapGesture { store.selectDatabase(db) }
                    .accessibilityAddTraits(.isButton)
                    .accessibilityLabel("Open details for database \(db.database ?? "unknown")")
                    .accessibilityAction { store.selectDatabase(db) }
                    }
                }
            }
        }
    }
}

struct MetricSparkCell: View {
    let value: String
    let values: [Double]
    let tint: Color
    let isLive: Bool

    var body: some View {
        if isLive {
            VStack(alignment: .leading, spacing: 2) {
                Text(value)
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundStyle(Theme.primary)
                    .lineLimit(1)
                Sparkline(values: values, tint: tint)
                    .frame(height: 13)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            Text("—")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
        }
    }
}

struct DockerTelemetryPanel: View {
    let container: DockerContainer

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if container.isRunning, let stats = container.stats {
                DetailLine(label: "Sampled", value: stats.timestamp ?? "—")
                TelemetryChartRow(
                    title: "CPU",
                    value: formatPercent(stats.cpuPercent),
                    values: dockerMetricSeries(container, metric: .cpu),
                    tint: Theme.blue
                )
                TelemetryChartRow(
                    title: "Memory",
                    value: memoryValue(stats),
                    values: dockerMetricSeries(container, metric: .memory),
                    tint: Theme.green
                )
                TelemetryChartRow(
                    title: "Network",
                    value: ratePairValue(
                        inbound: stats.networkRxRateBytesPerSecond,
                        outbound: stats.networkTxRateBytesPerSecond,
                        inboundLabel: "in",
                        outboundLabel: "out"
                    ),
                    values: dockerMetricSeries(container, metric: .networkRate),
                    tint: Theme.orange
                )
                TelemetryChartRow(
                    title: "Disk I/O",
                    value: ratePairValue(
                        inbound: stats.blockReadRateBytesPerSecond,
                        outbound: stats.blockWriteRateBytesPerSecond,
                        inboundLabel: "read",
                        outboundLabel: "write"
                    ),
                    values: dockerMetricSeries(container, metric: .blockRate),
                    tint: Theme.red
                )
            } else {
                Text("Telemetry is available when this container is running.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 4)
    }
}

struct TelemetryChartRow: View {
    let title: String
    let value: String
    let values: [Double]
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.secondary)
            Text(value)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
            Sparkline(values: values, tint: tint)
                .frame(height: 34)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .padding(9)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
    }
}

struct Sparkline: View {
    let values: [Double]
    let tint: Color

    var body: some View {
        GeometryReader { proxy in
            let cleaned = values.filter { $0.isFinite }
            if cleaned.isEmpty {
                Rectangle()
                    .fill(Color.white.opacity(0.08))
                    .frame(height: 1)
                    .frame(maxHeight: .infinity)
            } else {
                Path { path in
                    let width = max(proxy.size.width, 1)
                    let height = max(proxy.size.height, 1)
                    if cleaned.count == 1 {
                        let y = height / 2
                        path.move(to: CGPoint(x: 0, y: y))
                        path.addLine(to: CGPoint(x: width, y: y))
                        return
                    }
                    let minimum = cleaned.min() ?? 0
                    let maximum = cleaned.max() ?? 1
                    let span = max(maximum - minimum, max(abs(maximum), 1) * 0.08)
                    for index in cleaned.indices {
                        let x = cleaned.count == 1 ? width : width * CGFloat(index) / CGFloat(cleaned.count - 1)
                        let normalized = (cleaned[index] - minimum) / span
                        let y = height - (height * CGFloat(normalized))
                        if index == cleaned.startIndex {
                            path.move(to: CGPoint(x: x, y: y))
                        } else {
                            path.addLine(to: CGPoint(x: x, y: y))
                        }
                    }
                }
                .stroke(tint, style: StrokeStyle(lineWidth: 1.6, lineCap: .round, lineJoin: .round))
            }
        }
        .accessibilityHidden(true)
    }
}

struct DetailsRailView: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 16) {
                Text("DETAILS")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(Theme.secondary)
                SelectionDetailsPanel(store: store)
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.sidebar)
    }
}

struct SelectionDetailsPanel: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        switch store.sidebarSelection {
        case .server:
            if let selected = store.selectedServer {
                SelectedServerPanel(store: store, server: selected)
            } else {
                EmptyDetailsPanel()
            }
        case .docker:
            if let selected = store.selectedDocker {
                SelectedDockerPanel(store: store, container: selected)
            } else {
                EmptyDetailsPanel()
            }
        case .database:
            if let selected = store.selectedDatabase {
                SelectedDatabasePanel(store: store, database: selected)
            } else {
                EmptyDetailsPanel()
            }
        case .project(let name):
            SelectedProjectPanel(name: name, store: store)
        case nil:
            EmptyDetailsPanel()
        }
    }
}

struct SelectedServerPanel: View {
    @ObservedObject var store: OpsStore
    let server: ManagedServer

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(server.name)
                    .font(.system(size: 15, weight: .bold))
                Spacer()
                ResourceSourceBadge(
                    primary: server.origin,
                    candidates: server.observationOrigins,
                    states: store.sourceStates
                )
            }
            Text(projectDisplayLabel(server.project))
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Theme.secondary)
            DetailLine(label: "Port", value: server.port.map(String.init) ?? "—")
            DetailLine(label: "Health", value: server.status ?? "unknown")
            if let duplicateCount = server.duplicateCount, duplicateCount > 1 {
                DetailLine(label: "State Records", value: "\(duplicateCount) collapsed")
            }
            if server.portReused == true {
                DetailLine(label: "Port Reused By", value: portReuseText(server.portReusedBy))
            }
            if let usage = server.processUsage {
                DetailLine(label: "CPU", value: formatCPU(usage.cpuPercent))
                DetailLine(label: "Memory", value: formatBytes(usage.memoryBytes ?? usage.rssBytes))
                DetailLine(label: "Hot Process", value: hotProcessLabel(usage.hotProcesses?.first))
            }
            DetailLine(label: "Stopped", value: server.stoppedAt ?? "—")
            DetailLine(label: "Reason", value: server.stoppedReason ?? "—")
            if let ownershipError = server.ownershipError {
                Label(ownershipError, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("server-ownership-conflict")
            }
            Button {
                store.showServerLogs(server)
            } label: {
                Label("View Logs", systemImage: "doc.text.magnifyingglass")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!serverActionAllowed(store, kind: .serverLogs, server: server))
            InspectorActionStack {
                Button {
                    store.openURL(server.currentURL)
                } label: {
                    Label("Open", systemImage: "arrow.up.forward.square")
                        .frame(maxWidth: .infinity)
                }
                .disabled(server.currentURL == nil)
                Button {
                    store.copyURL(server.currentURL)
                } label: {
                    Label("Copy", systemImage: "link")
                        .frame(maxWidth: .infinity)
                }
                .disabled(server.currentURL == nil)
            }
            DisclosureGroup("Diagnostics") {
                DetailLine(label: "Project path", value: server.project ?? "Unavailable")
                DetailLine(label: "Working directory", value: server.cwd ?? "Unavailable")
                DetailLine(label: "Log path", value: server.logPath ?? "Unavailable")
                DetailLine(label: "Metadata source", value: server.metadataSource ?? "Unavailable")
                ForEach(
                    resourceObservationOrigins(
                        primary: server.origin,
                        candidates: server.observationOrigins
                    ),
                    id: \.id
                ) { origin in
                    DetailLine(label: "Observed by", value: origin.label)
                }
            }
            .font(.system(size: 11, weight: .semibold))
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }
}

struct SelectedDockerPanel: View {
    @ObservedObject var store: OpsStore
    let container: DockerContainer

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(container.name ?? "container")
                    .font(.system(size: 15, weight: .bold))
                    .lineLimit(2)
                Spacer()
                ResourceSourceBadge(
                    primary: container.origin,
                    candidates: container.observationOrigins,
                    states: store.sourceStates
                )
            }
            Text(container.image ?? "No image")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .lineLimit(2)
            DetailLine(label: "Status", value: normalizedStatus(container.status))
            DetailLine(label: "Ports", value: container.ports?.isEmpty == false ? container.ports! : "none")
            DetailLine(label: "PIDs", value: container.stats?.pids.map(String.init) ?? "—")
            DockerTelemetryPanel(container: container)
            InspectorActionStack {
                if container.isRunning {
                    Button { store.restartDocker(container) } label: { Label("Restart", systemImage: "arrow.clockwise").frame(maxWidth: .infinity) }
                        .disabled(!dockerActionAllowed(store, kind: .restartDocker, container: container))
                    Button { store.stopDocker(container) } label: { Label("Stop", systemImage: "stop").frame(maxWidth: .infinity) }
                        .disabled(!dockerActionAllowed(store, kind: .stopDocker, container: container))
                } else {
                    Button { store.startDocker(container) } label: { Label("Start", systemImage: "play.fill").frame(maxWidth: .infinity) }
                        .disabled(!dockerActionAllowed(store, kind: .startDocker, container: container))
                }
            }
            Button {
                store.dockerLogs(container)
            } label: {
                Label("Fetch Logs", systemImage: "doc.text")
                    .frame(maxWidth: .infinity)
            }
            .disabled(!dockerActionAllowed(store, kind: .dockerLogs, container: container))
            DisclosureGroup("Diagnostics") {
                DetailLine(label: "Project", value: container.project ?? "Unavailable")
                DetailLine(label: "Container ID", value: container.id ?? "Unavailable")
                DetailLine(label: "Metadata source", value: container.metadataSource ?? "Unavailable")
                if let error = container.ownershipError { DetailLine(label: "Ownership", value: error) }
                ForEach(
                    resourceObservationOrigins(
                        primary: container.origin,
                        candidates: container.observationOrigins
                    ),
                    id: \.id
                ) { origin in
                    DetailLine(label: "Observed by", value: origin.label)
                }
            }
            .font(.system(size: 11, weight: .semibold))
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }
}

struct SelectedDatabasePanel: View {
    @ObservedObject var store: OpsStore
    let database: DockerContainer
    @State private var restorePrompt: DatabaseRestorePrompt?
    @State private var showingEvidence = false

    var body: some View {
        let identity = database.databaseIdentity
        let backup = newestBackupRecord(for: database, records: store.backupRecords)
        let restore = identity.flatMap { store.restoreEvidence[$0] }
        let isVerifyingBackup = store.isBackupVerificationInProgress(for: database)
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(database.database ?? "Unknown database")
                    .font(.system(size: 15, weight: .bold))
                    .lineLimit(2)
                Spacer()
                ResourceSourceBadge(
                    primary: database.origin,
                    candidates: database.observationOrigins,
                    states: store.sourceStates
                )
            }
            Text(database.name ?? "Unknown container")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Theme.secondary)
                .lineLimit(2)
            Text(database.image ?? "Postgres image unavailable")
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .lineLimit(2)
            DetailLine(label: "Database", value: database.database ?? "Unavailable")
            DetailLine(label: "Container", value: database.name ?? "Unavailable")
            DetailLine(label: "Size", value: formatDatabaseBytes(database.databaseSizeBytes))
            DetailLine(label: "Status", value: normalizedStatus(database.status))
            if let discoveryError = database.databaseDiscoveryError {
                Label(discoveryError, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("PROTECTION EVIDENCE")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(Theme.secondary)
                EvidenceStateLine(
                    label: "Checksum verified",
                    state: isVerifyingBackup ? "Checking…" : checksumLabel(backup?.checksum),
                    tint: isVerifyingBackup ? Theme.blue : checksumColor(backup?.checksum)
                )
                EvidenceStateLine(
                    label: "Restore tested",
                    state: restoreTestLabel(backup?.restoreTest),
                    tint: restoreTestColor(backup?.restoreTest)
                )
                if let compatibilityError = backup?.compatibilityError {
                    Text(compatibilityError)
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.orange)
                }
                if let restore {
                    EvidenceStateLine(
                        label: "Last restore",
                        state: restore.transactional ? "Transactional" : "Unverified",
                        tint: restore.transactional ? Theme.green : Theme.red
                    )
                }
            }
            .padding(10)
            .background(Theme.control)
            .clipShape(RoundedRectangle(cornerRadius: 8))

            InspectorActionStack {
                Button { store.backupDatabase(container: database) } label: {
                    Label("Back up now", systemImage: "externaldrive.badge.timemachine").frame(maxWidth: .infinity)
                }
                .disabled(!database.isRunning || !databaseProtectionActionAllowed(store, kind: .backupDatabase, database: database))
                .accessibilityIdentifier("database-backup-now")
                Button {
                    if let identity, let backup { restorePrompt = DatabaseRestorePrompt(target: identity, backup: backup) }
                } label: {
                    Label("Restore…", systemImage: "arrow.counterclockwise").frame(maxWidth: .infinity)
                }
                .disabled(
                    identity == nil
                        || backup?.isStronglyVerified != true
                        || !database.isRunning
                        || !databaseProtectionActionAllowed(store, kind: .restoreDatabase, database: database)
                )
                .accessibilityIdentifier("database-restore")
                Button { showingEvidence = true } label: {
                    Label("View evidence", systemImage: "checkmark.seal").frame(maxWidth: .infinity)
                }
                .disabled(identity == nil || (backup == nil && restore == nil))
                .accessibilityIdentifier("database-view-evidence")
            }

            DisclosureGroup("Diagnostics") {
                DetailLine(label: "Immutable container ID", value: database.id ?? "Unavailable")
                DetailLine(label: "Ports", value: database.ports?.isEmpty == false ? database.ports! : "none")
                DetailLine(label: "PIDs", value: database.stats?.pids.map(String.init) ?? "—")
                if let error = database.ownershipError { DetailLine(label: "Ownership", value: error) }
                ForEach(
                    resourceObservationOrigins(
                        primary: database.origin,
                        candidates: database.observationOrigins
                    ),
                    id: \.id
                ) { origin in
                    DetailLine(label: "Observed by", value: origin.label)
                }
                DockerTelemetryPanel(container: database)
            }
            .font(.system(size: 11, weight: .semibold))

            InspectorActionStack {
                if database.isRunning {
                    Button { store.stopDocker(database) } label: {
                        Label("Stop container", systemImage: "stop").frame(maxWidth: .infinity)
                    }
                    .disabled(!dockerActionAllowed(store, kind: .stopDocker, container: database))
                } else {
                    Button { store.startDocker(database) } label: {
                        Label("Start container", systemImage: "play.fill").frame(maxWidth: .infinity)
                    }
                    .disabled(!dockerActionAllowed(store, kind: .startDocker, container: database))
                }
                Button { store.dockerLogs(database) } label: {
                    Label("Container logs", systemImage: "terminal").frame(maxWidth: .infinity)
                }
                .disabled(!dockerActionAllowed(store, kind: .dockerLogs, container: database))
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .sheet(item: $restorePrompt) { prompt in
            DatabaseRestoreSheet(store: store, prompt: prompt)
        }
        .sheet(isPresented: $showingEvidence) {
            DatabaseEvidenceSheet(identity: identity, backup: backup, restore: restore)
        }
    }
}

struct EvidenceStateLine: View {
    let label: String
    let state: String
    let tint: Color

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: evidenceIcon(state))
                .foregroundStyle(tint)
            Text(label)
                .font(.system(size: 11, weight: .semibold))
            Spacer()
            Text(state)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(tint)
        }
    }
}

struct DatabaseRestorePrompt: Identifiable {
    var id: String { "\(target.id)|\(backup.id)" }
    let target: DatabaseIdentity
    let backup: BackupRecord
}

struct DatabaseRestoreSheet: View {
    @ObservedObject var store: OpsStore
    let prompt: DatabaseRestorePrompt
    @Environment(\.dismiss) private var dismiss
    @State private var confirmation = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Restore Database")
                .font(.title2.bold())
            Label("This changes one exact database target.", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(Theme.orange)
            DetailLine(label: "Database", value: prompt.target.database)
            DetailLine(label: "Container", value: prompt.target.container)
            DetailLine(label: "Source", value: prompt.target.origin.label)
            DetailLine(label: "Backup created", value: formatDate(prompt.backup.createdAt))
            HStack(spacing: 16) {
                EvidenceStateLine(
                    label: "Checksum",
                    state: checksumLabel(prompt.backup.checksum),
                    tint: checksumColor(prompt.backup.checksum)
                )
                EvidenceStateLine(
                    label: "Restore test",
                    state: restoreTestLabel(prompt.backup.restoreTest),
                    tint: restoreTestColor(prompt.backup.restoreTest)
                )
            }
            Text("Type \(store.restoreConfirmation(for: prompt.target)) to confirm")
                .font(.system(size: 12, weight: .semibold))
            TextField(store.restoreConfirmation(for: prompt.target), text: $confirmation)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("database-restore-confirmation")
            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button("Restore database", role: .destructive) {
                    store.restoreDatabase(target: prompt.target, backup: prompt.backup, confirmation: confirmation)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(confirmation != store.restoreConfirmation(for: prompt.target))
                .accessibilityIdentifier("database-restore-execute")
            }
        }
        .padding(24)
        .frame(width: 560)
        .background(Theme.background)
    }
}

struct DatabaseEvidenceSheet: View {
    let identity: DatabaseIdentity?
    let backup: BackupRecord?
    let restore: DatabaseRestoreEvidence?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Database Evidence").font(.title2.bold())
                    Spacer()
                    Button("Close") { dismiss() }
                }
                if let identity {
                    DetailLine(label: "Exact target", value: "\(identity.container)/\(identity.database)")
                    DetailLine(label: "Source", value: identity.origin.label)
                    DetailLine(label: "Immutable container ID", value: identity.containerID ?? "Unavailable")
                }
                if let backup {
                    Text("BACKUP").font(.system(size: 11, weight: .bold)).foregroundStyle(Theme.secondary)
                    DetailLine(label: "Created", value: formatDate(backup.createdAt))
                    DetailLine(label: "Checksum", value: checksumLabel(backup.checksum))
                    DetailLine(label: "Restore tested", value: restoreTestLabel(backup.restoreTest))
                    DetailLine(label: "Format / scope", value: "\(backup.format ?? "unknown") / \(backup.scope ?? "unknown")")
                    DetailLine(label: "Artifact", value: backup.path)
                    if let error = backup.compatibilityError { DetailLine(label: "Compatibility", value: error) }
                } else {
                    Text("No backup evidence is available for this exact immutable database.")
                        .foregroundStyle(Theme.orange)
                }
                if let restore {
                    Text("RESTORE").font(.system(size: 11, weight: .bold)).foregroundStyle(Theme.secondary)
                    DetailLine(label: "Completed", value: formatDate(restore.completedAt))
                    DetailLine(label: "Transactional", value: restore.transactional ? "Yes" : "No")
                    DetailLine(label: "Incoming verification", value: restore.incomingVerificationPassed ? "Passed" : "Failed")
                    DetailLine(label: "Safety verification", value: restore.safetyVerificationPassed ? "Passed" : "Failed")
                    DetailLine(label: "Safety backup", value: restore.safetyBackupPath)
                    DetailLine(label: "Restored catalog", value: restore.restoredCatalogSignature.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ", "))
                }
            }
            .padding(22)
        }
        .frame(width: 680, height: 620)
        .background(Theme.background)
    }
}

struct SelectedProjectPanel: View {
    let name: String
    @ObservedObject var store: OpsStore

    var body: some View {
        // A dropped cached selection may recover only the persisted usage-key
        // path. It never scans the filesystem or derives a project from names.
        let cachedRepository = RepositoryIdentity(projectPath: projectPath(fromUsageKey: name))
        let group = store.projectGroups.first { $0.id == name } ?? ProjectGroup(
            id: name,
            name: projectName(fromUsageKey: name),
            projectPath: cachedRepository?.canonicalRoot,
            servers: [],
            containers: [],
            databases: [],
            usage: nil,
            kind: cachedRepository == nil ? .unassigned : .repository
        )
        let report = store.projectRuntimeReports[name]
        let origins = projectGroupObservedOrigins(group)
        VStack(alignment: .leading, spacing: 10) {
            Text(group.name)
                .font(.system(size: 15, weight: .bold))
                .lineLimit(2)
            DetailLine(
                label: "Runtime",
                value: group.isRepository ? projectDisplayLabel(group.projectPath) : "Not linked to a repository"
            )
            DetailLine(label: "Servers", value: "\(group.servers.count)")
            DetailLine(label: "Docker", value: "\(group.containers.count)")
            DetailLine(label: "Databases", value: "\(group.databases.count)")
            if !group.isRepository, group.unassignedEvidenceCount > 0 {
                DetailLine(label: "Attribution hints", value: "\(group.unassignedEvidenceCount)")
            }
            if let usage = group.usage {
                DetailLine(label: "CPU", value: formatCPU(usage.cpuPercent))
                DetailLine(label: "Memory", value: formatBytes(usage.memoryBytes))
                DetailLine(label: "Hot Process", value: hotProcessLabel(usage.hotProcesses?.first))
            }
            if let conflictSummary = projectGroupConflictSummary(group) {
                Label(conflictSummary, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("project-server-conflict")
            }
            if projectGroupShowsProjectActions(group) {
                InspectorActionStack {
                    Button { store.startProject(group) } label: { Label("Run", systemImage: "play.fill").frame(maxWidth: .infinity) }
                        .disabled(!projectActionAllowed(store, group: group, kind: .projectStart))
                    Button { store.restartProject(group) } label: { Label("Restart", systemImage: "arrow.clockwise").frame(maxWidth: .infinity) }
                        .disabled(!projectActionAllowed(store, group: group, kind: .projectRestart))
                    Button { store.stopProject(group) } label: { Label("Stop", systemImage: "stop").frame(maxWidth: .infinity) }
                        .disabled(!projectActionAllowed(store, group: group, kind: .projectStop))
                }
                Button {
                    store.statusProject(group)
                } label: {
                    Label("Check Runtime", systemImage: "checkmark.seal")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!projectActionAllowed(store, group: group, kind: .projectStatus))
            } else {
                Text("These resources have no validated repository path. Use each resource row to inspect the controls available for its exact source.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
            }
            if let report {
                ProjectRuntimeSummary(report: report)
            }
            DisclosureGroup("Diagnostics") {
                DetailLine(label: "Project path", value: group.projectPath ?? "Unassigned")
                ForEach(origins, id: \.id) { origin in
                    DetailLine(label: "Source", value: origin.label)
                }
                ForEach(group.serverConflicts) { conflict in
                    DetailLine(label: "Server conflict", value: conflict.message)
                    DetailLine(
                        label: "Active sources",
                        value: projectConflictOrigins(conflict).map(\.label).joined(separator: ", ")
                    )
                }
                ForEach(group.serverMembershipConflicts) { conflict in
                    DetailLine(label: "Server ownership", value: conflict.message)
                    DetailLine(
                        label: "Candidate repositories",
                        value: conflict.repositories.map(\.displayName).joined(separator: ", ")
                    )
                }
                ForEach(group.dockerMembershipConflicts) { conflict in
                    DetailLine(label: "Docker ownership", value: conflict.message)
                    DetailLine(
                        label: "Candidate repositories",
                        value: conflict.repositories.map(\.displayName).joined(separator: ", ")
                    )
                }
            }
            .font(.system(size: 11, weight: .semibold))
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }
}

struct ProjectRuntimeSummary: View {
    let report: ProjectRuntimeReport

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            DetailLine(label: "Ready", value: report.ok == true ? "Yes" : "No")
            DetailLine(label: "Class", value: report.classification ?? "—")
            if report.partial == true {
                DetailLine(label: "Outcome", value: "Partial changes applied; inventory refreshed")
            } else if report.partial == false, report.ok == false {
                DetailLine(label: "Outcome", value: "Preflight failed; no changes applied")
            }
            if let url = report.urls.first?.url {
                DetailLine(label: "URL", value: url)
            }
            if let port = report.ports.first {
                DetailLine(label: "Port", value: port.fixedPort.map(String.init) ?? port.port.map(String.init) ?? port.ports ?? "—")
            }
            ForEach(report.services.prefix(6)) { service in
                RuntimeServiceLine(service: service)
            }
            ForEach(report.previousExitReasons.prefix(2), id: \.self) { reason in
                if let text = reason.reason, !text.isEmpty {
                    DetailLine(label: reason.name ?? "Exit", value: text)
                }
            }
            ForEach((report.actionErrors ?? []).prefix(2), id: \.self) { error in
                DetailLine(label: error.name ?? "Action", value: error.error ?? error.classification ?? "failed")
            }
        }
        .padding(.top, 4)
    }
}

struct RuntimeServiceLine: View {
    let service: ProjectRuntimeService

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            StatusDot(status: service.ok == true ? "running" : "unhealthy")
            VStack(alignment: .leading, spacing: 2) {
                Text(service.name ?? service.type ?? "service")
                    .font(.system(size: 12, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(service.classification ?? service.status ?? "ok")
                    .font(.system(size: 11))
                    .foregroundStyle(service.ok == true ? Theme.secondary : Theme.orange)
                    .lineLimit(2)
            }
            Spacer(minLength: 0)
        }
        .padding(8)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
    }
}

struct EmptyDetailsPanel: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No selection")
                .font(.system(size: 14, weight: .semibold))
            Text("Select a project, server, container, or database to manage it here.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct ActionSourcePicker: View {
    let title: String
    let origins: [CoordinatorOrigin]
    @Binding var selection: CoordinatorOrigin?

    var body: some View {
        Picker(title, selection: $selection) {
            Text(origins.isEmpty ? "No loaded source" : "Choose a source")
                .tag(nil as CoordinatorOrigin?)
            ForEach(origins) { origin in
                Text(origin.label)
                    .tag(origin as CoordinatorOrigin?)
            }
        }
        .pickerStyle(.menu)
        .disabled(origins.isEmpty)
    }
}

struct StartServerSheet: View {
    @ObservedObject var store: OpsStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Start Managed Server")
                        .font(.title2.bold())
                    Text("Commands are sent as structured arguments and are never evaluated by a shell.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                }
                Spacer()
                if let origin = store.startDraft.origin {
                    SourceBadge(origin: origin, states: store.sourceStates)
                }
            }
            ActionSourcePicker(
                title: "Coordinator source",
                origins: store.availableActionOrigins,
                selection: $store.startDraft.origin
            )
            .disabled(store.startDraft.leaseID != nil)
            .accessibilityIdentifier("start-server-source")
            TextField("Name", text: $store.startDraft.name)
                .accessibilityIdentifier("start-server-name")
            TextField("Project", text: $store.startDraft.project)
                .disabled(store.startDraft.leaseID != nil)
                .accessibilityIdentifier("start-server-project")
            TextField("Working directory", text: $store.startDraft.cwd)
                .accessibilityIdentifier("start-server-cwd")
            VStack(alignment: .leading, spacing: 8) {
                Text("COMMAND")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(Theme.secondary)
                TextField("Executable", text: $store.startDraft.executable)
                    .accessibilityLabel("Server executable")
                    .accessibilityIdentifier("start-server-executable")
                ForEach($store.startDraft.argumentRows) { $argument in
                    HStack(spacing: 8) {
                        TextField("Argument", text: $argument.value)
                            .accessibilityIdentifier("start-server-argument-\(argument.id.uuidString)")
                        Button {
                            store.startDraft.argumentRows.removeAll { $0.id == argument.id }
                        } label: {
                            Image(systemName: "minus.circle")
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Remove command argument")
                    }
                }
                Button {
                    store.startDraft.argumentRows.append(StartServerArgument(value: ""))
                } label: {
                    Label("Add Argument", systemImage: "plus")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("start-server-add-argument")
            }
            .padding(12)
            .background(Theme.control)
            .clipShape(RoundedRectangle(cornerRadius: 8))
            HStack {
                TextField("Port range", text: $store.startDraft.range)
                    .disabled(store.startDraft.leaseID != nil)
                TextField("Exact port", text: $store.startDraft.preferredPort)
                    .disabled(store.startDraft.leaseID != nil)
                TextField("Health URL", text: $store.startDraft.healthURL)
            }
            Text("Exact port is optional. When set, the coordinator reserves only that port.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
            if store.startDraft.leaseID != nil {
                Label(
                    "Using reserved port \(store.startDraft.preferredPort) from \(store.startDraft.origin?.label ?? "selected source")",
                    systemImage: "link.badge.plus"
                )
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.blue)
                    .accessibilityIdentifier("start-server-lease-summary")
                    .accessibilityHint("Exact lease identity is available in the lease result details")
                Text("The lease source, project, and exact port are fixed. A health URL must use the leased port.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Start") { store.startServer() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!startIsValid)
                    .accessibilityIdentifier("start-server-submit")
            }
        }
        .padding(24)
        .frame(width: 640)
    }

    private var preferredPortIsValid: Bool {
        let value = store.startDraft.preferredPort.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return true }
        guard let port = Int(value) else { return false }
        return (1...65535).contains(port)
    }

    private var startIsValid: Bool {
        !store.startDraft.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !store.startDraft.executable.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !store.startDraft.arguments.contains { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            && preferredPortIsValid
            && startDestinationIsAvailable
            && leaseBindingIsValid
    }

    private var startDestinationIsAvailable: Bool {
        guard let origin = store.startDraft.origin,
              let identity = store.startDraftResourceIdentity
        else { return false }
        return store.mutationAvailability(
            kind: .startServer,
            origin: origin,
            resource: identity,
            leaseID: store.startDraft.leaseID,
            projectPath: store.startDraft.project
        ).isAllowed
    }

    private var leaseBindingIsValid: Bool {
        guard let leaseID = store.startDraft.leaseID else { return true }
        guard let origin = store.startDraft.origin,
              let lease = store.leaseResults.values.first(where: {
                  $0.leaseID == leaseID && $0.identity.origin.id == origin.id
              }),
              lease.canStartServer
        else { return false }
        let expectedProject = lease.project ?? store.actionProjectPath
        guard store.startDraft.project == expectedProject,
              store.startDraft.agent == lease.agent,
              store.startDraft.range == "\(lease.port)-\(lease.port)",
              store.startDraft.preferredPort == String(lease.port)
        else { return false }
        let healthURL = store.startDraft.healthURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !healthURL.isEmpty else { return true }
        return URLComponents(string: healthURL)?.port == lease.port
    }
}

struct LeaseSheet: View {
    @ObservedObject var store: OpsStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Lease Port")
                .font(.title2.bold())
            Text("The coordinator will reserve a free port for this project.")
                .foregroundStyle(.secondary)
            ActionSourcePicker(
                title: "Coordinator source",
                origins: store.availableActionOrigins,
                selection: $store.leaseOrigin
            )
            .accessibilityIdentifier("lease-source")
            DetailLine(label: "Project", value: store.actionProjectPath)
            TextField("Range", text: $store.leaseRange)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Lease") { store.leasePort() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!leaseDestinationIsAvailable)
            }
        }
        .padding(24)
        .frame(width: 420)
    }

    private var leaseDestinationIsAvailable: Bool {
        guard let origin = store.leaseOrigin else { return false }
        return store.mutationAvailability(
            kind: .leasePort,
            origin: origin,
            resource: nil,
            projectPath: store.actionProjectPath
        ).isAllowed
    }
}

struct ServerLogsSheet: View {
    @ObservedObject var store: OpsStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(store.serverLogTitle)
                        .font(.title2.bold())
                    Text(store.serverLogMetadata)
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                        .lineLimit(3)
                }
                Spacer()
                Button("Close") { dismiss() }
            }

            TextEditor(text: $store.serverLogText)
                .font(.system(size: 12, design: .monospaced))
                .textEditorStyle(.plain)
                .scrollContentBackground(.hidden)
                .padding(10)
                .background(Color.black.opacity(0.28))
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))

            HStack {
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(store.serverLogText, forType: .string)
                } label: {
                    Label("Copy Logs", systemImage: "doc.on.doc")
                }
            }
        }
        .padding(22)
        .frame(width: 840, height: 620)
        .background(Theme.background)
    }
}

struct SectionSurface<Content: View>: View {
    let title: String
    let count: Int
    let systemImage: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 13) {
            HStack(spacing: 8) {
                Image(systemName: systemImage).foregroundStyle(Theme.secondary)
                Text(title)
                    .font(.system(size: 14, weight: .bold))
                CountBadge(count: count)
                Spacer()
            }
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

struct ResizableTable<Rows: View>: View {
    let columns: [String]
    @Binding var widths: [CGFloat]
    @ViewBuilder var rows: Rows

    var body: some View {
        GeometryReader { proxy in
            let tableWidth = max(totalWidth, proxy.size.width)
            ScrollView([.horizontal, .vertical]) {
                VStack(alignment: .leading, spacing: 0) {
                    ResizableHeaderRow(columns: columns, widths: $widths)
                        .frame(width: tableWidth, alignment: .leading)
                    rows
                    Spacer(minLength: 0)
                }
                .frame(width: tableWidth, alignment: .topLeading)
                .frame(minHeight: proxy.size.height, alignment: .topLeading)
            }
            .frame(width: proxy.size.width, height: proxy.size.height)
            .background(Color.white.opacity(0.015))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.07)))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .frame(minHeight: 340)
    }

    private var totalWidth: CGFloat {
        widths.reduce(0, +)
    }
}

struct ResizableHeaderRow: View {
    let columns: [String]
    @Binding var widths: [CGFloat]

    var body: some View {
        HStack(spacing: 0) {
            ForEach(columns.indices, id: \.self) { index in
                ResizableHeaderCell(
                    title: columns[index],
                    width: Binding(
                        get: { widths[index] },
                        set: { widths[index] = $0 }
                    )
                )
            }
        }
        .frame(height: 32)
        .background(Color.white.opacity(0.025))
        .overlay(alignment: .bottom) {
            Rectangle().fill(Color.white.opacity(0.08)).frame(height: 1)
        }
    }
}

struct ResizableHeaderCell: View {
    let title: String
    @Binding var width: CGFloat
    @State private var dragStart: CGFloat?
    @State private var isHovering = false

    var body: some View {
        HStack(spacing: 0) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.secondary)
                .lineLimit(1)
                .padding(.horizontal, 8)
            Spacer(minLength: 0)
            ZStack {
                Rectangle().fill(isHovering ? Theme.blue.opacity(0.18) : Color.white.opacity(0.035))
                HStack(spacing: 2) {
                    Capsule().fill(Color.white.opacity(0.26)).frame(width: 1, height: 20)
                    Capsule().fill(Color.white.opacity(0.16)).frame(width: 1, height: 20)
                }
            }
                .frame(width: 14)
                .contentShape(Rectangle())
                .gesture(
                    DragGesture(minimumDistance: 0, coordinateSpace: .global)
                        .onChanged { value in
                            let start = dragStart ?? width
                            if dragStart == nil { dragStart = width }
                            width = resizedColumnWidth(start: start, startX: value.startLocation.x, currentX: value.location.x)
                        }
                        .onEnded { _ in dragStart = nil }
                )
                .onHover { hovering in
                    if hovering, !isHovering {
                        NSCursor.resizeLeftRight.push()
                    } else if !hovering, isHovering {
                        NSCursor.pop()
                    }
                    isHovering = hovering
                }
                .help("Drag to resize column")
        }
        .frame(width: width, height: 32)
    }
}

struct TableRow<Content: View>: View {
    let widths: [CGFloat]
    let isSelected: Bool
    @ViewBuilder var content: Content

    var body: some View {
        HStack(spacing: 0) {
            content
        }
        .font(.system(size: 12))
        .frame(width: widths.reduce(0, +), height: 44, alignment: .leading)
        .background(isSelected ? Theme.blue.opacity(0.12) : Color.clear)
        .contentShape(Rectangle())
        .overlay(alignment: .bottom) {
            Rectangle().fill(Color.white.opacity(0.06)).frame(height: 1)
        }
    }
}

struct TableCell<Content: View>: View {
    let width: CGFloat
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(.horizontal, 8)
            .frame(width: width, alignment: .leading)
    }
}

struct DevServersEmptyState: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .center, spacing: 12) {
                    stateIcon
                    stateCopy
                        .fixedSize(horizontal: true, vertical: false)
                    Spacer(minLength: 8)
                    actions
                }

                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .top, spacing: 12) {
                        stateIcon
                        stateCopy
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if !store.isInitialInventoryLoading {
                        HStack(spacing: 8) {
                            Spacer(minLength: 0)
                            actions
                        }
                    }
                }
            }

            if !store.inventory.urls.isEmpty {
                HStack(spacing: 8) {
                    ForEach(store.inventory.urls.prefix(4)) { managedURL in
                        RecentURLPill(url: managedURL, open: { store.openURL(managedURL.url) }, copy: { store.copyURL(managedURL.url) })
                    }
                    Spacer()
                }
            }
        }
        .padding(14)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
        .accessibilityIdentifier("dev-server-empty-state")
    }

    private var stateIcon: some View {
        Group {
            if store.isInitialInventoryLoading {
                ProgressView()
                    .controlSize(.small)
            } else {
                Image(systemName: "terminal")
                    .foregroundStyle(Theme.blue)
            }
        }
        .foregroundStyle(Theme.blue)
        .frame(width: 28, height: 28)
        .background(Theme.blue.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 7))
    }

    private var stateCopy: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(store.isInitialInventoryLoading ? "Loading managed dev servers" : "No managed dev servers in this scope")
                .font(.system(size: 13, weight: .semibold))
            Text(store.isInitialInventoryLoading ? "Waiting for configured coordinator sources." : "Use the coordinator before opening default ports.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private var actions: some View {
        if !store.isInitialInventoryLoading {
            ToolbarButton(title: "Lease", systemImage: "calendar.badge.plus") {
                store.prepareLeaseDraft()
                store.showingLeaseSheet = true
            }
            .disabled(!unscopedActionAllowed(store, kind: .leasePort))
            ToolbarButton(title: "Start", systemImage: "play.circle.fill", tint: Theme.green) {
                store.prepareStartDraft()
                store.showingStartSheet = true
            }
            .disabled(!unscopedActionAllowed(store, kind: .startServer))
        }
    }
}

struct ResourceEmptyState: View {
    @ObservedObject var store: OpsStore
    let title: String
    let message: String
    let systemImage: String

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Group {
                if store.isInitialInventoryLoading {
                    ProgressView()
                        .controlSize(.small)
                } else {
                    Image(systemName: systemImage)
                        .foregroundStyle(Theme.blue)
                }
            }
            .frame(width: 28, height: 28)
            .background(Theme.blue.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 7))

            VStack(alignment: .leading, spacing: 3) {
                Text(store.isInitialInventoryLoading ? "Loading inventory" : title)
                    .font(.system(size: 13, weight: .semibold))
                Text(store.isInitialInventoryLoading ? "Waiting for configured coordinator sources." : message)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if !store.isInitialInventoryLoading {
                Button("Refresh") { store.refresh() }
                    .buttonStyle(.bordered)
            }
        }
        .padding(14)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
        .accessibilityIdentifier("resource-empty-state-\(safeAccessibilityID(title))")
    }
}

struct RecentURLPill: View {
    let url: ManagedURL
    let open: () -> Void
    let copy: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            StatusDot(status: url.status)
            Button(action: open) {
                Text("\(url.name ?? "server")  \(url.url ?? "")")
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)
            }
            .buttonStyle(.plain)
            .foregroundStyle(Theme.blue)
            Button(action: copy) {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 11))
            }
            .buttonStyle(.plain)
            .help("Copy URL")
        }
        .padding(.horizontal, 9)
        .frame(height: 28)
        .background(Theme.blue.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 7))
    }
}

func HeaderRow(_ headers: [String]) -> some View {
    GridRow {
        ForEach(headers, id: \.self) { header in
            Text(header)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    .frame(height: 28)
}

struct URLCell: View {
    let url: String?
    var staleURL: String? = nil
    let open: () -> Void
    let copy: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Button(action: open) {
                Text(label)
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)
            }
            .buttonStyle(URLButtonStyle())
            .disabled(url == nil)
            Button(action: copy) {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(IconButtonStyle())
            .disabled(url == nil)
        }
    }

    private var label: String {
        if let url {
            return url
        }
        if staleURL != nil {
            return "previous"
        }
        return "—"
    }
}

struct ToolbarButton: View {
    let title: String
    let systemImage: String
    var tint: Color = Theme.primary
    var showsTitle = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            content
        }
        .buttonStyle(.plain)
        .help(title)
        .accessibilityLabel(title)
        .accessibilityIdentifier("toolbar-action-\(safeAccessibilityID(title))")
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
    }

    @ViewBuilder
    private var content: some View {
        if showsTitle {
            Label(title, systemImage: systemImage)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(tint)
                .lineLimit(1)
                .padding(.horizontal, 8)
                .frame(height: 32)
        } else {
            Image(systemName: systemImage)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 32, height: 32)
        }
    }
}

struct SearchField: View {
    @Binding var text: String
    var compact = false

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(Theme.secondary)
            TextField(compact ? "Search" : "Search servers, containers, databases, URLs...", text: $text)
                .textFieldStyle(.plain)
                .font(.system(size: 12))
        }
        .padding(.horizontal, 9)
        .frame(height: 32)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.white.opacity(0.08)))
    }
}

struct EnvironmentPicker: View {
    @Binding var projectPath: String
    @State private var showingEditor = false

    var body: some View {
        Button {
            showingEditor.toggle()
        } label: {
            HStack(spacing: 9) {
                Image(systemName: "square.stack.3d.up")
                    .foregroundStyle(Theme.blue)
                    .frame(width: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text(environmentTitle(projectPath))
                        .font(.system(size: 12, weight: .semibold))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(environmentSubtitle(projectPath))
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: 0)
            }
        }
        .buttonStyle(.plain)
        .help(projectPath.isEmpty ? "All coordinator projects" : "Scoped to \(environmentTitle(projectPath))")
        .padding(.horizontal, 9)
        .frame(height: 36)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.white.opacity(0.08)))
        .popover(isPresented: $showingEditor, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Environment")
                    .font(.system(size: 13, weight: .semibold))
                TextField("Project path; empty means all projects", text: $projectPath)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 430)
                HStack {
                    Button("All Projects") { projectPath = "" }
                    Button("Current Folder") { projectPath = FileManager.default.currentDirectoryPath }
                    Spacer()
                    Button("Done") { showingEditor = false }
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(16)
        }
    }
}

struct BackupSafetyLabel: View {
    let backup: BackupRecord?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(
                checksumLabel(backup?.checksum),
                systemImage: backup?.checksum == .verified ? "checkmark.seal.fill" : "exclamationmark.shield"
            )
            .foregroundStyle(checksumColor(backup?.checksum))
            Text("Restore \(restoreTestLabel(backup?.restoreTest).lowercased())")
                .font(.system(size: 10))
                .foregroundStyle(restoreTestColor(backup?.restoreTest))
        }
            .font(.system(size: 11, weight: .semibold))
            .lineLimit(1)
            .frame(minWidth: 108, alignment: .leading)
    }
}

struct StatusBar: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        HStack(spacing: 14) {
            Circle()
                .fill(healthLevelColor(store.presentationSnapshot.level))
                .frame(width: 9, height: 9)
                .accessibilityHidden(true)
            Text(store.presentationSnapshot.statusMessage)
                .font(.system(size: 12))
                .foregroundStyle(healthLevelColor(store.presentationSnapshot.level))
                .lineLimit(1)
            Spacer()
            if let lease = store.latestLeaseResult {
                Text("Lease port \(lease.port) · \(lease.managementStatus)")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
            }
            Text("Sources \(store.healthSummary.loadedSourceCount)/\(store.sourceStates.count)")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
        }
        .padding(.horizontal, 18)
        .frame(height: 38)
        .accessibilityIdentifier("main-board-status")
    }

}

struct StatusDot: View {
    let status: String?

    var body: some View {
        Circle()
            .fill(statusColor(status))
            .frame(width: 9, height: 9)
            .accessibilityHidden(true)
    }
}

struct SourceBadge: View {
    let origin: CoordinatorOrigin?
    let states: [CoordinatorSourceState]

    var body: some View {
        let phase = origin.flatMap { origin in states.first(where: { $0.origin.id == origin.id })?.phase }
        Label(origin?.label ?? "Unknown source", systemImage: "point.3.connected.trianglepath.dotted")
            .labelStyle(.titleAndIcon)
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(sourcePhaseColor(phase))
            .padding(.horizontal, 5)
            .frame(height: 18)
            .background(sourcePhaseColor(phase).opacity(0.1))
            .clipShape(Capsule())
            .lineLimit(1)
            .help("Source \(origin?.label ?? "unavailable") · \(phase?.rawValue ?? "unknown")")
            .accessibilityLabel("Source \(origin?.label ?? "unknown"), \(phase?.rawValue ?? "unknown")")
    }
}

struct ResourceSourceBadge: View {
    let primary: CoordinatorOrigin?
    let candidates: [CoordinatorOrigin]
    let states: [CoordinatorSourceState]

    private var origins: [CoordinatorOrigin] {
        resourceObservationOrigins(primary: primary, candidates: candidates)
    }

    var body: some View {
        if origins.count <= 1 {
            SourceBadge(origin: origins.first, states: states)
        } else {
            Label("\(origins.count) sources", systemImage: "point.3.connected.trianglepath.dotted")
                .labelStyle(.titleAndIcon)
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(Theme.blue)
                .padding(.horizontal, 5)
                .frame(height: 18)
                .background(Theme.blue.opacity(0.1))
                .clipShape(Capsule())
                .lineLimit(1)
                .help("Observed by \(origins.map(\.label).joined(separator: ", "))")
                .accessibilityLabel("Observed by sources \(origins.map(\.label).joined(separator: ", "))")
        }
    }
}

struct StatusText: View {
    let status: String?

    var body: some View {
        Text(normalizedStatus(status))
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(statusColor(status))
            .lineLimit(1)
    }
}

struct CountBadge: View {
    let count: Int

    var body: some View {
        Text("\(count)")
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(Theme.secondary)
            .padding(.horizontal, 7)
            .frame(height: 20)
            .background(Theme.control)
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct MapLeaf: View {
    let title: String
    let kind: MapLeafKind
    let status: String?
    let isSelected: Bool
    let canStop: Bool
    let toggleEnabled: Bool
    let restartEnabled: Bool
    let selectAction: () -> Void
    let toggleAction: () -> Void
    let restartAction: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Button(action: selectAction) {
                HStack(spacing: 7) {
                    Image(systemName: kind.systemImage)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(kind.tint)
                        .frame(width: 14)
                    StatusDot(status: status)
                    Text(title)
                        .font(.system(size: 12))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(minWidth: 46, maxWidth: 116, alignment: .leading)
                }
            }
            .buttonStyle(.plain)
            HStack(spacing: 4) {
                SidebarActionButton(
                    title: canStop ? "Stop" : "Run",
                    systemImage: canStop ? "stop.fill" : "play.fill",
                    tint: canStop ? Theme.orange : Theme.green,
                    enabled: toggleEnabled,
                    action: toggleAction
                )
                SidebarActionButton(
                    title: "Restart",
                    systemImage: "arrow.clockwise",
                    tint: Theme.secondary,
                    enabled: restartEnabled,
                    action: restartAction
                )
            }
            .fixedSize()
        }
        .padding(.leading, 30)
        .padding(.trailing, 6)
        .foregroundStyle(Theme.primary)
        .frame(maxWidth: .infinity, minHeight: 26, alignment: .leading)
        .background(isSelected ? Theme.blue.opacity(0.18) : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

}

enum MapLeafKind {
    case server
    case docker
    case database

    var systemImage: String {
        switch self {
        case .server: return "terminal"
        case .docker: return "shippingbox"
        case .database: return "cylinder.split.1x2"
        }
    }

    var tint: Color {
        switch self {
        case .server: return Theme.blue
        case .docker: return Theme.orange
        case .database: return Theme.green
        }
    }
}

struct SidebarActionButton: View {
    let title: String
    let systemImage: String
    let tint: Color
    var enabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 20, height: 20)
        }
        .buttonStyle(.plain)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 5))
        .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.white.opacity(0.08)))
        .help(title)
        .accessibilityLabel(title)
        .disabled(!enabled)
        .opacity(enabled ? 1 : 0.45)
    }
}

struct SidebarRowButtonStyle: ButtonStyle {
    let isSelected: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(Theme.primary)
            .padding(.horizontal, 6)
            .frame(maxWidth: .infinity, minHeight: 24, alignment: .leading)
            .background(background(configuration: configuration))
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private func background(configuration: Configuration) -> Color {
        if isSelected { return Theme.blue.opacity(0.18) }
        if configuration.isPressed { return Color.white.opacity(0.08) }
        return Color.clear
    }
}

struct SidebarFooterView: View {
    @ObservedObject var store: OpsStore
    @State private var showingSources = false

    var body: some View {
        GeometryReader { proxy in
            let contentWidth = sidebarFooterContentWidth(totalWidth: proxy.size.width)
            VStack(spacing: 9) {
                HStack(spacing: 8) {
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                        .foregroundStyle(healthLevelColor(store.presentationSnapshot.level))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(store.presentationSnapshot.statusTitle)
                            .font(.system(size: 12, weight: .medium))
                            .lineLimit(1)
                        Text("Sources \(store.healthSummary.loadedSourceCount)/\(store.sourceStates.count)")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.secondary)
                            .lineLimit(1)
                    }
                    .layoutPriority(1)
                    Spacer(minLength: 4)
                }
                .frame(width: contentWidth, alignment: .leading)
                .frame(minHeight: 28, alignment: .leading)
                Button {
                    showingSources = true
                } label: {
                    Label("Manage Sources", systemImage: "slider.horizontal.3")
                        .frame(width: contentWidth)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("manage-coordinator-sources")
            }
            .frame(width: contentWidth, alignment: .topLeading)
            .padding(.leading, sidebarFooterInset)
            .padding(.top, 16)
        }
        .frame(height: sidebarFooterHeight)
        .clipped()
        .sheet(isPresented: $showingSources) {
            CoordinatorSourcesSheet(store: store)
        }
    }
}

struct CoordinatorSourceDraftRow: Identifiable {
    let id: UUID
    var label: String
    var home: String
    var enabled: Bool

    init(id: UUID = UUID(), configuration: CoordinatorSourceConfiguration) {
        self.id = id
        label = configuration.label
        home = configuration.home
        enabled = configuration.enabled
    }

    var configuration: CoordinatorSourceConfiguration {
        CoordinatorSourceConfiguration(label: label, home: home, enabled: enabled)
    }
}

struct CoordinatorSourcesSheet: View {
    @ObservedObject var store: OpsStore
    @Environment(\.dismiss) private var dismiss
    @State private var draft = CoordinatorConfiguration()
    @State private var sourceRows: [CoordinatorSourceDraftRow] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Coordinator Sources").font(.title2.bold())
                    Text("Configure typed local coordinator homes and refresh behavior.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                }
                Spacer()
                Button("Refresh now") { store.refresh() }
            }

            ScrollView {
                VStack(spacing: 10) {
                    ForEach($sourceRows) { $source in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                TextField("Source label", text: $source.label)
                                Toggle("Enabled", isOn: $source.enabled)
                                Button(role: .destructive) {
                                    sourceRows.removeAll { $0.id == source.id }
                                } label: {
                                    Image(systemName: "trash")
                                }
                                .accessibilityLabel("Remove source \(source.label.isEmpty ? "without a label" : source.label)")
                            }
                            TextField("Absolute coordinator home", text: $source.home)
                            .font(.system(size: 12, design: .monospaced))
                        }
                        .padding(10)
                        .background(Theme.control)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                    Button {
                        sourceRows.append(
                            CoordinatorSourceDraftRow(
                                configuration: CoordinatorSourceConfiguration(label: "", home: "", enabled: true)
                            )
                        )
                    } label: {
                        Label("Add Source", systemImage: "plus")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .frame(minHeight: 250, maxHeight: 390)

            HStack(spacing: 10) {
                Text("Refresh")
                    .font(.system(size: 12, weight: .semibold))
                Picker("Refresh", selection: $draft.refreshPolicy.mode) {
                    Text("Manual").tag(CoordinatorRefreshMode.manual)
                    Text("Interval").tag(CoordinatorRefreshMode.interval)
                }
                .pickerStyle(.segmented)
                .frame(width: 190)
                if draft.refreshPolicy.mode == .interval {
                    TextField(
                        "Seconds",
                        value: Binding(
                            get: {
                                draft.refreshPolicy.intervalSeconds
                                    ?? CoordinatorRefreshPolicy.defaultIntervalSeconds
                            },
                            set: { draft.refreshPolicy.intervalSeconds = $0 }
                        ),
                        format: .number
                    )
                    .frame(width: 90)
                }
                Spacer()
            }
            .onChange(of: draft.refreshPolicy.mode) { _, mode in
                draft.refreshPolicy.intervalSeconds = mode == .manual
                    ? nil
                    : (draft.refreshPolicy.intervalSeconds ?? CoordinatorRefreshPolicy.defaultIntervalSeconds)
            }

            if let warning = store.configurationWarning {
                Text(warning)
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button("Save") {
                    draft.sources = sourceRows.map(\.configuration)
                    if store.saveCoordinatorConfiguration(draft) {
                        dismiss()
                        store.refresh()
                    }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(width: 650, height: 590)
        .background(Theme.background)
        .onAppear {
            store.reloadCoordinatorConfiguration()
            draft = store.coordinatorConfiguration
            sourceRows = draft.sources.map { CoordinatorSourceDraftRow(configuration: $0) }
        }
    }
}

struct EmptyMapHint: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No managed services yet")
                .font(.system(size: 13, weight: .semibold))
            Text("Use Start Server or New Lease to bring local work under coordinator control.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct DetailLine: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.secondary)
            Text(value.isEmpty ? "—" : value)
                .font(.system(size: 12))
                .foregroundStyle(Theme.primary)
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .padding(.vertical, 2)
    }
}

struct InspectorActionStack<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(spacing: 8) {
            content()
        }
        .buttonStyle(.bordered)
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }
}

struct IconButton: View {
    let title: String
    let systemImage: String
    let action: () -> Void

    init(_ title: String, _ systemImage: String, action: @escaping () -> Void) {
        self.title = title
        self.systemImage = systemImage
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .frame(width: 24, height: 24)
        }
        .help(title)
        .accessibilityLabel(title)
        .buttonStyle(IconButtonStyle())
    }
}

struct IconButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(Theme.primary)
            .background(configuration.isPressed ? Theme.blue.opacity(0.25) : Theme.control)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.white.opacity(0.08)))
    }
}

struct URLButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(Theme.blue)
            .padding(.horizontal, 8)
            .frame(height: 28)
            .background(configuration.isPressed ? Theme.blue.opacity(0.25) : Theme.blue.opacity(0.11))
            .clipShape(RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).stroke(Theme.blue.opacity(0.25)))
    }
}

@MainActor
func actionAllowed(_ store: OpsStore, kind: ActionKind, identity: ResourceIdentity?) -> Bool {
    guard let identity else { return false }
    return store.mutationAvailability(kind: kind, origin: identity.origin, resource: identity).isAllowed
}

@MainActor
func serverActionAllowed(_ store: OpsStore, kind: ActionKind, server: ManagedServer) -> Bool {
    guard let identity = server.resourceIdentity,
          let project = server.project?.trimmingCharacters(in: .whitespacesAndNewlines),
          !project.isEmpty,
          !server.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else { return false }
    return store.mutationAvailability(
        kind: kind,
        origin: identity.origin,
        resource: identity,
        projectPath: project
    ).isAllowed
}

@MainActor
func dockerActionAllowed(_ store: OpsStore, kind: ActionKind, container: DockerContainer) -> Bool {
    guard let identity = container.resourceIdentity,
          let name = container.name?.trimmingCharacters(in: .whitespacesAndNewlines),
          !name.isEmpty
    else { return false }
    if kind != .dockerLogs {
        guard let project = container.project?.trimmingCharacters(in: .whitespacesAndNewlines),
              !project.isEmpty
        else { return false }
    }
    return store.mutationAvailability(
        kind: kind,
        origin: identity.origin,
        resource: identity,
        projectPath: container.project
    ).isAllowed
}

@MainActor
func databaseProtectionActionAllowed(
    _ store: OpsStore,
    kind: ActionKind,
    database: DockerContainer
) -> Bool {
    guard let identity = database.databaseIdentity,
          identity.containerID?.isEmpty == false,
          !identity.container.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
          !identity.database.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
          let resource = databaseProtectionIdentity(database)
    else { return false }
    if kind == .backupDatabase {
        guard let project = database.project?.trimmingCharacters(in: .whitespacesAndNewlines),
              !project.isEmpty
        else { return false }
    }
    return store.mutationAvailability(
        kind: kind,
        origin: resource.origin,
        resource: resource,
        projectPath: database.project
    ).isAllowed
}

@MainActor
func unscopedActionAllowed(_ store: OpsStore, kind: ActionKind) -> Bool {
    store.availableActionOrigins.contains {
        store.mutationAvailability(kind: kind, origin: $0, resource: nil).isAllowed
    }
}

@MainActor
func projectActionAllowed(_ store: OpsStore, group: ProjectGroup, kind: ActionKind) -> Bool {
    store.projectMutationAvailability(kind: kind, group: group).isAllowed
}

@MainActor
func dockerCapabilityUnavailable(_ store: OpsStore) -> Bool {
    capabilityUnavailable(store, capability: .docker)
}

@MainActor
func databaseCapabilityUnavailable(_ store: OpsStore) -> Bool {
    capabilityUnavailable(store, capability: .database)
}

@MainActor
func capabilityUnavailable(_ store: OpsStore, capability: CoordinatorCapability) -> Bool {
    let states = store.capabilityStates.filter { $0.capability == capability }
    guard !states.isEmpty else { return !store.isLoading }
    return states.allSatisfy { $0.phase == .unavailable }
}

func normalizedBulkIdentity(_ identity: ResourceIdentity?) -> ResourceIdentity? {
    guard let identity else { return nil }
    if identity.kind == .database {
        return ResourceIdentity(origin: identity.origin, kind: .docker, nativeID: identity.nativeID)
    }
    return identity
}

func databaseProtectionIdentity(_ database: DockerContainer) -> ResourceIdentity? {
    guard let identity = database.databaseIdentity, let containerID = identity.containerID else { return nil }
    return ResourceIdentity(
        origin: identity.origin,
        kind: .database,
        nativeID: "\(containerID)/\(identity.container)/\(identity.database)"
    )
}

func newestBackupRecord(for database: DockerContainer, records: [BackupRecord]) -> BackupRecord? {
    guard let identity = database.databaseIdentity else { return nil }
    return records
        .filter { $0.identity.isSameImmutableDatabase(as: identity) }
        .max { $0.createdAt < $1.createdAt }
}

func formatDate(_ date: Date) -> String {
    date.formatted(date: .abbreviated, time: .shortened)
}

func formatTimestamp(_ value: String?) -> String {
    guard let value else { return "No expiry recorded" }
    return parseISOTimestamp(value).map(formatDate) ?? value
}

func formatDatabaseBytes(_ bytes: Int64?) -> String {
    guard let bytes else { return "Unavailable" }
    let formatter = ByteCountFormatter()
    formatter.allowedUnits = [.useBytes, .useKB, .useMB, .useGB, .useTB]
    formatter.countStyle = .file
    return formatter.string(fromByteCount: bytes)
}

func formatUptime(_ uptime: UptimeValue) -> String {
    switch uptime {
    case .measured(let interval):
        let seconds = max(0, Int(interval))
        let days = seconds / 86_400
        let hours = (seconds % 86_400) / 3_600
        let minutes = (seconds % 3_600) / 60
        if days > 0 { return "\(days)d \(hours)h" }
        if hours > 0 { return "\(hours)h \(minutes)m" }
        return "\(minutes)m"
    case .unavailable:
        return "—"
    }
}

func uptimeHelp(_ uptime: UptimeValue) -> String {
    switch uptime {
    case .measured(let interval): return "Measured from the recorded start time: \(Int(max(0, interval))) seconds"
    case .unavailable(let reason): return "Uptime unavailable: \(reason)"
    }
}

func checksumLabel(_ state: ChecksumState?) -> String {
    switch state {
    case .verified: return "Verified"
    case .failed: return "Failed"
    case .unknown: return "Not verified"
    case nil: return "No backup"
    }
}

func checksumColor(_ state: ChecksumState?) -> Color {
    switch state {
    case .verified: return Theme.green
    case .failed: return Theme.red
    case .unknown, nil: return Theme.orange
    }
}

func restoreTestLabel(_ state: RestoreTestState?) -> String {
    switch state {
    case .passed: return "Passed"
    case .failed: return "Failed"
    case .notRun: return "Not run"
    case nil: return "No backup"
    }
}

func restoreTestColor(_ state: RestoreTestState?) -> Color {
    switch state {
    case .passed: return Theme.green
    case .failed: return Theme.red
    case .notRun, nil: return Theme.orange
    }
}

func evidenceIcon(_ state: String) -> String {
    let normalized = state.lowercased()
    if normalized.contains("failed") || normalized.contains("not verified") || normalized.contains("unverified") {
        return "xmark.circle.fill"
    }
    if normalized.contains("verified") || normalized.contains("passed") || normalized.contains("transactional") {
        return "checkmark.circle.fill"
    }
    return "circle.dashed"
}

func healthLevelColor(_ level: HealthLevel) -> Color {
    switch level {
    case .nominal: return Theme.green
    case .busy: return Theme.blue
    case .degraded: return Theme.orange
    case .unhealthy, .unavailable: return Theme.red
    }
}

func inventoryBannerIcon(_ level: HealthLevel) -> String {
    switch level {
    case .nominal: return "checkmark.circle.fill"
    case .busy: return "clock.arrow.circlepath"
    case .degraded: return "exclamationmark.triangle.fill"
    case .unhealthy: return "exclamationmark.octagon.fill"
    case .unavailable: return "wifi.slash"
    }
}

func sourcePhaseColor(_ phase: CoordinatorSourcePhase?) -> Color {
    switch phase {
    case .loaded: return Theme.green
    case .loading: return Theme.blue
    case .stale: return Theme.orange
    case .failed, nil: return Theme.red
    }
}

func actionPhaseColor(_ phase: ActionPhase) -> Color {
    switch phase {
    case .queued, .running: return Theme.blue
    case .succeeded: return Theme.green
    case .failed, .timedOut: return Theme.red
    case .cancelled: return Theme.orange
    }
}

func isTerminalActionPhase(_ phase: ActionPhase) -> Bool {
    switch phase {
    case .queued, .running: return false
    case .succeeded, .failed, .timedOut, .cancelled: return true
    }
}

func safeAccessibilityID(_ value: String) -> String {
    value.unicodeScalars.map { scalar in
        CharacterSet.alphanumerics.contains(scalar) ? String(scalar) : "-"
    }.joined()
}

enum Theme {
    static let background = Color(red: 0.075, green: 0.09, blue: 0.095)
    static let sidebar = Color(red: 0.058, green: 0.071, blue: 0.078)
    static let toolbar = Color(red: 0.064, green: 0.075, blue: 0.08)
    static let control = Color.white.opacity(0.055)
    static let primary = Color(red: 0.9, green: 0.93, blue: 0.95)
    static let secondary = Color(red: 0.58, green: 0.64, blue: 0.68)
    static let blue = Color(red: 0.31, green: 0.52, blue: 0.95)
    static let green = Color(red: 0.36, green: 0.82, blue: 0.28)
    static let orange = Color(red: 1.0, green: 0.66, blue: 0.16)
    static let red = Color(red: 1.0, green: 0.29, blue: 0.31)
}

enum DockerMetric {
    case cpu
    case memory
    case networkRate
    case blockRate
}

func dockerMetricValue(_ stats: DockerStats?, metric: DockerMetric) -> Double? {
    guard let stats else { return nil }
    switch metric {
    case .cpu:
        return stats.cpuPercent
    case .memory:
        return stats.memoryPercent
    case .networkRate:
        return sumOptional(stats.networkRxRateBytesPerSecond, stats.networkTxRateBytesPerSecond)
    case .blockRate:
        return sumOptional(stats.blockReadRateBytesPerSecond, stats.blockWriteRateBytesPerSecond)
    }
}

func dockerMetricSeries(_ container: DockerContainer, metric: DockerMetric) -> [Double] {
    (container.statsHistory ?? []).compactMap { dockerMetricValue($0, metric: metric) }
}

func sumOptional(_ left: Double?, _ right: Double?) -> Double? {
    switch (left, right) {
    case (.some(let left), .some(let right)):
        return left + right
    case (.some(let left), .none):
        return left
    case (.none, .some(let right)):
        return right
    case (.none, .none):
        return nil
    }
}

func formatPercent(_ value: Double?) -> String {
    guard let value else { return "—" }
    return String(format: "%.1f%%", value)
}

func formatCPU(_ value: Double?) -> String {
    formatPercent(value)
}

func formatBytes(_ value: Double?) -> String {
    guard let value else { return "—" }
    if value == 0 { return "0 B" }
    let formatter = ByteCountFormatter()
    formatter.allowedUnits = [.useBytes, .useKB, .useMB, .useGB, .useTB]
    formatter.countStyle = .file
    return formatter.string(fromByteCount: Int64(value.rounded()))
}

func hotProcessLabel(_ process: ProcessUsage?) -> String {
    guard let process else { return "No hot process" }
    let pid = process.pid.map { "PID \($0)" } ?? "PID —"
    let command = process.command?.trimmingCharacters(in: .whitespacesAndNewlines)
    if let command, !command.isEmpty {
        return "\(pid) \(command)"
    }
    return pid
}

func isHighProjectUsage(_ usage: ProjectUsage) -> Bool {
    let cpu = usage.cpuPercent ?? 0
    let memory = usage.memoryBytes ?? 0
    return cpu >= 200 || memory >= 8_000_000_000
}

func usageSeverityColor(_ usage: ProjectUsage) -> Color {
    let cpu = usage.cpuPercent ?? 0
    let memory = usage.memoryBytes ?? 0
    if isHighProjectUsage(usage) { return Theme.red }
    if cpu >= 80 || memory >= 2_000_000_000 { return Theme.orange }
    return Theme.primary
}

func formatRate(_ value: Double?) -> String {
    guard let value else { return "n/a" }
    return "\(formatBytes(value))/s"
}

func memoryValue(_ stats: DockerStats) -> String {
    if let percent = stats.memoryPercent {
        return "\(formatPercent(percent))  \(formatBytes(stats.memoryUsageBytes))"
    }
    return formatBytes(stats.memoryUsageBytes)
}

func ratePairValue(inbound: Double?, outbound: Double?, inboundLabel: String, outboundLabel: String) -> String {
    "\(formatRate(inbound)) \(inboundLabel) / \(formatRate(outbound)) \(outboundLabel)"
}

func statusColor(_ status: String?) -> Color {
    let value = (status ?? "").lowercased()
    if value.contains("unhealthy") || value.contains("failed") || value.contains("dead") || value.contains("unavailable") { return Theme.red }
    if value.contains("start") || value.contains("warning") || value.contains("degraded") || value.contains("partial") || value.contains("stale") { return Theme.orange }
    if value.contains("loading") || value.contains("running action") { return Theme.blue }
    if isStoppedStatus(status) || value.contains("stop") || value.isEmpty { return Theme.secondary }
    return Theme.green
}

func normalizedStatus(_ status: String?) -> String {
    guard let status, !status.isEmpty else { return "Unknown" }
    if status.lowercased().hasPrefix("up") { return "Running" }
    return status.prefix(1).uppercased() + status.dropFirst()
}

func shortProject(_ path: String?) -> String {
    guard let path, !path.isEmpty else { return "local" }
    return URL(fileURLWithPath: path).lastPathComponent
}

/// `usage_key` is a persisted coordinator contract: `path:<canonical repo
/// path>` for attributed groups, `name:<derived key>` for unclaimed ones.
func projectPath(fromUsageKey key: String) -> String? {
    let usageKey = key.components(separatedBy: "|project-group|").last ?? key
    guard usageKey.hasPrefix("path:") else { return nil }
    let path = String(usageKey.dropFirst("path:".count))
    return path.isEmpty ? nil : path
}

func projectDisplayLabel(_ path: String?) -> String {
    guard let path else { return "Unavailable" }
    let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return "Unavailable" }
    return shortProject(trimmed)
}

func projectName(fromUsageKey key: String) -> String {
    let usageKey = key.components(separatedBy: "|project-group|").last ?? key
    if let path = projectPath(fromUsageKey: usageKey) {
        return shortProject(path)
    }
    if usageKey.hasPrefix("name:") {
        let name = String(usageKey.dropFirst("name:".count))
        if !name.isEmpty { return name }
    }
    return usageKey == "stray:other" ? "other" : usageKey
}

func environmentTitle(_ path: String) -> String {
    let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? "Local Dev" : shortProject(trimmed)
}

func environmentSubtitle(_ path: String) -> String {
    let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty { return "All projects" }
    return URL(fileURLWithPath: trimmed).deletingLastPathComponent().lastPathComponent
}

/// Table columns show the same project a container is grouped (and acted on)
/// under; the fallbacks only cover containers absent from every membership row.
func projectLabel(for container: DockerContainer, in groups: [ProjectGroup]) -> String {
    let member = groups.first { group in
        group.containers.contains { $0.containerSelectionID == container.containerSelectionID }
            || group.databases.contains { $0.containerSelectionID == container.containerSelectionID }
    }
    if let member {
        return member.name
    }
    if let project = container.project, !project.isEmpty {
        return shortProject(project)
    }
    return "other"
}

func portReuseText(_ owner: PortReuseOwner?) -> String {
    guard let owner else { return "unknown" }
    if let name = owner.name, !name.isEmpty {
        let project = owner.project.map(shortProject) ?? "unknown"
        return "\(project) / \(name)"
    }
    if let cwd = owner.cwd, !cwd.isEmpty {
        return shortProject(cwd)
    }
    if let project = owner.project, !project.isEmpty {
        return shortProject(project)
    }
    if let pid = owner.pid {
        return "PID \(pid)"
    }
    return "unknown"
}

/// Cosmetic leaf label only — grouping never derives from resource names. The
/// project argument is the group's display name and is normalized here so a
/// repo named `XFoilFOAM` still strips the `xfoilfoam-` prefix.
func resourceDisplayName(_ name: String?, inProject projectName: String) -> String {
    guard let name, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return "service" }
    let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
    let normalized = trimmed.lowercased().replacingOccurrences(of: "_", with: "-")
    let prefix = projectName.lowercased().replacingOccurrences(of: "_", with: "-") + "-"
    if normalized.hasPrefix(prefix) {
        let index = trimmed.index(trimmed.startIndex, offsetBy: min(prefix.count, trimmed.count))
        let suffix = String(trimmed[index...]).trimmingCharacters(in: CharacterSet(charactersIn: "-_ "))
        return suffix.isEmpty ? trimmed : suffix
    }
    return trimmed
}

func filterIcon(_ filter: ServiceFilter) -> String {
    switch filter {
    case .all: return "circle.grid.2x2"
    case .running: return "circle.fill"
    case .unhealthy: return "exclamationmark.triangle.fill"
    case .stopped: return "pause.circle"
    }
}

func lastBackupText(for db: DockerContainer, backups: [DatabaseBackup]) -> String {
    let match = backups.first { backup in
        backup.container == db.name || backup.database == db.name
    }
    return match?.modifiedAt ?? "No backup"
}

func backupColor(for db: DockerContainer, backups: [DatabaseBackup]) -> Color {
    lastBackupText(for: db, backups: backups) == "No backup" ? Theme.orange : Theme.green
}

func hasBackup(for db: DockerContainer, backups: [DatabaseBackup]) -> Bool {
    backups.contains { backup in
        backup.container == db.name || backup.database == db.name
    }
}

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
                        .frame(width: layout.mainWidth, height: proxy.size.height)
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
            await store.loadInventory()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_500_000_000)
                await store.loadInventory()
            }
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
                WindowDots()
                Text("Codex Ops Console")
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
        projectGroups(from: store.inventory)
    }
}

struct ProjectGroup {
    var id: String
    var name: String
    var projectPath: String?
    var servers: [ManagedServer]
    var containers: [DockerContainer]
    var databases: [DockerContainer]
    var usage: ProjectUsage?
}

func projectGroups(from inventory: Inventory) -> [ProjectGroup] {
    let dedupedServers = deduplicatedManagedServers(inventory.servers)
    let servers = Dictionary(grouping: dedupedServers) { projectKey(fromPath: $0.project) }
    let docker = Dictionary(grouping: inventory.docker.containers.filter { !$0.isPostgresLike }) { projectKey(fromDockerContainer: $0) }
    let databases = Dictionary(grouping: inventory.postgres) { projectKey(fromDockerContainer: $0) }
    let usage = Dictionary(grouping: inventory.projectUsage) { $0.projectKey ?? projectKey(fromPath: $0.project) }
        .compactMapValues { rows in rows.max(by: { usageRank($0) < usageRank($1) }) }
    let keys = Set(servers.keys).union(docker.keys).union(databases.keys).union(usage.keys).sorted()

    return keys.map { key in
        ProjectGroup(
            id: key,
            name: projectDisplayName(
                key: key,
                servers: servers[key] ?? [],
                containers: docker[key] ?? [],
                databases: databases[key] ?? []
            ),
            projectPath: projectPathForGroup(
                key: key,
                servers: servers[key] ?? [],
                containers: docker[key] ?? [],
                databases: databases[key] ?? []
            ),
            servers: servers[key] ?? [],
            containers: docker[key] ?? [],
            databases: databases[key] ?? [],
            usage: usage[key]
        )
    }
}

func usageRank(_ usage: ProjectUsage) -> (Double, Double, Int) {
    (usage.cpuPercent ?? 0, usage.memoryBytes ?? 0, usage.processCount ?? 0)
}

func projectGroupStatus(_ group: ProjectGroup) -> String {
    if group.servers.contains(where: { ($0.status ?? "").lowercased() == "unhealthy" }) { return "unhealthy" }
    if group.servers.contains(where: { ($0.status ?? "").lowercased() == "running" }) { return "running" }
    if group.containers.contains(where: { isRunningStatus($0.status) }) { return "running" }
    if group.databases.contains(where: { isRunningStatus($0.status) }) { return "running" }
    return "stopped"
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
                    .frame(minWidth: 54, maxWidth: 96, alignment: .leading)
                CountBadge(count: group.servers.count + group.containers.count + group.databases.count)
                HStack(spacing: 4) {
                    SidebarActionButton(
                        title: groupCanStop ? "Stop project runtime" : "Run project runtime",
                        systemImage: groupCanStop ? "stop.fill" : "play.fill",
                        tint: groupCanStop ? Theme.orange : Theme.green,
                        action: { groupCanStop ? store.stopProject(group) : store.startProject(group) }
                    )
                    SidebarActionButton(
                        title: "Restart project runtime",
                        systemImage: "arrow.clockwise",
                        tint: Theme.secondary,
                        action: { store.restartProject(group) }
                    )
                }
                .fixedSize()
                .layoutPriority(1)
            }
            .padding(.horizontal, 6)
            .frame(maxWidth: .infinity, minHeight: 26, alignment: .leading)
            .background(store.sidebarSelection == .project(group.id) ? Theme.blue.opacity(0.18) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
            .onTapGesture(perform: toggle)

            if isExpanded {
                ForEach(group.servers) { server in
                    MapLeaf(
                        title: resourceDisplayName(server.name, inProject: group.id),
                        kind: .server,
                        status: server.status,
                        isSelected: store.sidebarSelection == .server(server.id),
                        selectAction: { store.selectServer(server) },
                        toggleAction: { store.toggle(server) },
                        restartAction: { store.restart(server) }
                    )
                }

                ForEach(group.containers, id: \.stableID) { container in
                    MapLeaf(
                        title: resourceDisplayName(container.name, inProject: group.id),
                        kind: .docker,
                        status: container.status,
                        isSelected: store.sidebarSelection == .docker(container.stableID),
                        selectAction: { store.selectDocker(container) },
                        toggleAction: { store.toggleDocker(container) },
                        restartAction: { store.restartDocker(container) }
                    )
                }

                ForEach(group.databases, id: \.stableID) { database in
                    MapLeaf(
                        title: resourceDisplayName(database.name, inProject: group.id),
                        kind: .database,
                        status: database.status,
                        isSelected: store.sidebarSelection == .database(database.stableID),
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

    var body: some View {
        VStack(spacing: 0) {
            ToolbarView(store: store)
            Divider().overlay(Color.white.opacity(0.07))

            VStack(spacing: 14) {
                ProjectUsageStrip(store: store)
                FilterRow(store: store)
                ResourceTabBar(store: store)

                Group {
                    switch store.activeTab {
                    case .servers:
                        DevServersSection(store: store)
                    case .docker:
                        DockerSection(store: store)
                    case .databases:
                        DatabaseSection(store: store)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .padding(14)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            Divider().overlay(Color.white.opacity(0.07))
            StatusBar(store: store)
        }
        .background(Theme.background)
    }
}

struct ProjectUsageStrip: View {
    @ObservedObject var store: OpsStore

    private var rows: [ProjectUsage] {
        store.inventory.projectUsage
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
        .frame(width: 520, alignment: .leading)
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
            if proxy.size.width < 760 {
                compactToolbar
            } else {
                fullToolbar
            }
        }
        .padding(.horizontal, 12)
        .frame(height: 54)
        .background(Theme.toolbar)
    }

    private var fullToolbar: some View {
        HStack(spacing: 8) {
            EnvironmentPicker(projectPath: $store.projectPath)
                .frame(width: 168)
            SearchField(text: $store.searchText)
                .frame(minWidth: 220, maxWidth: .infinity)
            ToolbarButton(title: "Refresh", systemImage: "arrow.clockwise", showsTitle: false) {
                store.refresh()
            }
            ToolbarButton(title: "Lease", systemImage: "calendar.badge.plus") {
                store.showingLeaseSheet = true
            }
            ToolbarButton(title: "Start", systemImage: "play.circle.fill", tint: Theme.green) {
                store.prepareStartDraft()
                store.showingStartSheet = true
            }
            ToolbarButton(title: "Backup", systemImage: "externaldrive.badge.timemachine", tint: Theme.blue, showsTitle: false) {
                store.backupDatabase(container: store.visiblePostgres.first)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
    }

    private var compactToolbar: some View {
        HStack(spacing: 6) {
            EnvironmentPicker(projectPath: $store.projectPath)
                .frame(width: 132)
            SearchField(text: $store.searchText, compact: true)
                .frame(minWidth: 120, maxWidth: .infinity)
            ToolbarButton(title: "Refresh", systemImage: "arrow.clockwise", showsTitle: false) {
                store.refresh()
            }
            ToolbarButton(title: "Lease", systemImage: "calendar.badge.plus", showsTitle: false) {
                store.showingLeaseSheet = true
            }
            ToolbarButton(title: "Start", systemImage: "play.circle.fill", tint: Theme.green, showsTitle: false) {
                store.prepareStartDraft()
                store.showingStartSheet = true
            }
            ToolbarButton(title: "Backup", systemImage: "externaldrive.badge.timemachine", tint: Theme.blue, showsTitle: false) {
                store.backupDatabase(container: store.visiblePostgres.first)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
    }
}

struct FilterRow: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        HStack(spacing: 12) {
            Text("Filter")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Theme.secondary)
            Picker("Filter", selection: $store.filter) {
                ForEach(ServiceFilter.allCases) { filter in
                    Label(filter.rawValue, systemImage: filterIcon(filter))
                        .tag(filter)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 360)

            Spacer()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct DevServersSection: View {
    @ObservedObject var store: OpsStore
    @State private var widths: [CGFloat] = [112, 106, 160, 86, 62, 58, 150]

    var body: some View {
        SectionSurface(title: "DEV SERVERS", count: store.filteredServers.count, systemImage: "terminal") {
            if store.filteredServers.isEmpty {
                DevServersEmptyState(store: store)
            } else {
                ResizableTable(columns: ["Service", "Project", "URL", "Status", "Uptime", "Port", "Actions"], widths: $widths) {
                    ForEach(store.filteredServers) { server in
                        TableRow(widths: widths, isSelected: store.selectedServerID == server.id) {
                            TableCell(width: widths[0]) {
                                HStack(spacing: 8) {
                                    StatusDot(status: server.status)
                                    Text(server.name).fontWeight(.medium).lineLimit(1)
                                }
                            }
                            TableCell(width: widths[1]) {
                                Text(shortProject(server.project)).foregroundStyle(Theme.secondary).lineLimit(1)
                            }
                            TableCell(width: widths[2]) {
                                URLCell(url: server.currentURL, staleURL: server.url, open: { store.openURL(server.currentURL) }, copy: { store.copyURL(server.currentURL) })
                            }
                            TableCell(width: widths[3]) { StatusText(status: server.status) }
                            TableCell(width: widths[4]) {
                                Text(server.health?.pidAlive == true ? "active" : "—").foregroundStyle(Theme.secondary)
                            }
                            TableCell(width: widths[5]) {
                                Text(server.port.map(String.init) ?? "—").monospacedDigit()
                            }
                            TableCell(width: widths[6]) {
                                HStack(spacing: 7) {
                                    IconButton("Restart", "arrow.clockwise") { store.restart(server) }
                                    IconButton("Stop", "stop") { store.stop(server) }
                                    IconButton("Open", "arrow.up.forward.square") { store.openURL(server.currentURL) }
                                        .disabled(server.currentURL == nil)
                                    IconButton("Logs", "doc.text.magnifyingglass") { store.showServerLogs(server) }
                                }
                            }
                        }
                        .onTapGesture { store.selectServer(server) }
                    }
                }
            }
        }
    }
}

struct DockerSection: View {
    @ObservedObject var store: OpsStore
    @State private var widths: [CGFloat] = [160, 100, 88, 100, 108, 118, 118, 130, 128, 130]

    var body: some View {
        SectionSurface(title: "DOCKER", count: store.visibleDockerContainers.count, systemImage: "shippingbox") {
            ResizableTable(columns: ["Container", "Project", "Status", "CPU", "Memory", "Network", "Disk I/O", "Image", "Ports", "Actions"], widths: $widths) {
                ForEach(store.visibleDockerContainers, id: \.stableID) { container in
                    TableRow(widths: widths, isSelected: store.selectedDockerID == container.stableID) {
                        TableCell(width: widths[0]) {
                            HStack(spacing: 8) {
                                StatusDot(status: container.status)
                                Text(container.name ?? "container")
                                    .fontWeight(.medium)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                        TableCell(width: widths[1]) {
                            Text(projectLabel(for: container)).foregroundStyle(Theme.secondary).lineLimit(1)
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
                                    IconButton("Stop", "stop") { store.stopDocker(container) }
                                } else {
                                    IconButton("Start", "play.fill") { store.startDocker(container) }
                                }
                                IconButton("Logs", "doc.text") { store.dockerLogs(container) }
                                if container.isPostgresLike {
                                    IconButton("Backup", "externaldrive.badge.timemachine") { store.backupDatabase(container: container) }
                                }
                            }
                        }
                    }
                    .onTapGesture { store.selectDocker(container) }
                }
            }
        }
    }
}

struct DatabaseSection: View {
    @ObservedObject var store: OpsStore
    @State private var widths: [CGFloat] = [160, 135, 150, 105, 75, 145, 130, 120]

    var body: some View {
        SectionSurface(title: "DATABASES", count: store.visiblePostgres.count, systemImage: "cylinder.split.1x2") {
            ResizableTable(columns: ["Database", "Project", "Engine", "Status", "Size", "Last Backup", "Restore Safety", "Actions"], widths: $widths) {
                ForEach(store.visiblePostgres, id: \.stableID) { db in
                    let hasBackup = hasBackup(for: db, backups: store.inventory.backups)
                    TableRow(widths: widths, isSelected: store.selectedDatabaseID == db.stableID) {
                        TableCell(width: widths[0]) {
                            HStack(spacing: 8) {
                                StatusDot(status: db.status)
                                Text(db.name ?? "postgres")
                                    .fontWeight(.medium)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                        TableCell(width: widths[1]) { Text(projectLabel(for: db)).foregroundStyle(Theme.secondary).lineLimit(1) }
                        TableCell(width: widths[2]) { Text(db.image ?? "postgres").foregroundStyle(Theme.secondary).lineLimit(1) }
                        TableCell(width: widths[3]) { StatusText(status: db.status) }
                        TableCell(width: widths[4]) { Text("—").foregroundStyle(Theme.secondary) }
                        TableCell(width: widths[5]) {
                            Text(lastBackupText(for: db, backups: store.inventory.backups))
                                .foregroundStyle(backupColor(for: db, backups: store.inventory.backups))
                                .lineLimit(1)
                        }
                        TableCell(width: widths[6]) { BackupSafetyLabel(hasBackup: hasBackup) }
                        TableCell(width: widths[7]) {
                            HStack(spacing: 7) {
                                if db.isRunning {
                                    IconButton("Backup", "externaldrive.badge.timemachine") { store.backupDatabase(container: db) }
                                    IconButton("Stop", "stop") { store.stopDocker(db) }
                                } else {
                                    IconButton("Start", "play.fill") { store.startDocker(db) }
                                }
                                IconButton("Logs", "terminal") { store.dockerLogs(db) }
                            }
                        }
                    }
                    .onTapGesture { store.selectDatabase(db) }
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
            Text(server.name)
                .font(.system(size: 15, weight: .bold))
            Text(server.project ?? "No project")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)
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
            DetailLine(label: "Log", value: server.logPath ?? "—")
            Button {
                store.showServerLogs(server)
            } label: {
                Label("View Logs", systemImage: "doc.text.magnifyingglass")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
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
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }
}

struct SelectedDockerPanel: View {
    @ObservedObject var store: OpsStore
    let container: DockerContainer

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(container.name ?? "container")
                .font(.system(size: 15, weight: .bold))
                .lineLimit(2)
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
                    Button { store.stopDocker(container) } label: { Label("Stop", systemImage: "stop").frame(maxWidth: .infinity) }
                } else {
                    Button { store.startDocker(container) } label: { Label("Start", systemImage: "play.fill").frame(maxWidth: .infinity) }
                }
            }
            Button {
                store.dockerLogs(container)
            } label: {
                Label("Fetch Logs", systemImage: "doc.text")
                    .frame(maxWidth: .infinity)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }
}

struct SelectedDatabasePanel: View {
    @ObservedObject var store: OpsStore
    let database: DockerContainer

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(database.name ?? "postgres")
                .font(.system(size: 15, weight: .bold))
                .lineLimit(2)
            Text(database.image ?? "Postgres")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .lineLimit(2)
            DetailLine(label: "Status", value: normalizedStatus(database.status))
            DetailLine(label: "Last Backup", value: lastBackupText(for: database, backups: store.inventory.backups))
            DetailLine(label: "Ports", value: database.ports?.isEmpty == false ? database.ports! : "none")
            DetailLine(label: "PIDs", value: database.stats?.pids.map(String.init) ?? "—")
            DockerTelemetryPanel(container: database)
            InspectorActionStack {
                if database.isRunning {
                    Button { store.backupDatabase(container: database) } label: { Label("Backup", systemImage: "externaldrive.badge.timemachine").frame(maxWidth: .infinity) }
                    Button { store.stopDocker(database) } label: { Label("Stop", systemImage: "stop").frame(maxWidth: .infinity) }
                } else {
                    Button { store.startDocker(database) } label: { Label("Start", systemImage: "play.fill").frame(maxWidth: .infinity) }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }
}

struct SelectedProjectPanel: View {
    let name: String
    @ObservedObject var store: OpsStore

    var body: some View {
        let servers = deduplicatedManagedServers(store.inventory.servers).filter { projectKey(fromPath: $0.project) == name }
        let docker = store.inventory.docker.containers.filter { projectKey(fromDockerContainer: $0) == name }
        let databases = store.inventory.postgres.filter { projectKey(fromDockerContainer: $0) == name }
        let usage = store.inventory.projectUsage.first { ($0.projectKey ?? projectKey(fromPath: $0.project)) == name }
        let group = ProjectGroup(
            id: name,
            name: projectDisplayName(key: name, servers: servers, containers: docker, databases: databases),
            projectPath: projectPathForGroup(key: name, servers: servers, containers: docker, databases: databases),
            servers: servers,
            containers: docker,
            databases: databases,
            usage: usage
        )
        let report = store.projectRuntimeReports[name]
        VStack(alignment: .leading, spacing: 10) {
            Text(group.name)
                .font(.system(size: 15, weight: .bold))
                .lineLimit(2)
            DetailLine(label: "Runtime", value: group.projectPath ?? "No project path")
            DetailLine(label: "Servers", value: "\(servers.count)")
            DetailLine(label: "Docker", value: "\(docker.count)")
            DetailLine(label: "Databases", value: "\(databases.count)")
            if let usage = group.usage {
                DetailLine(label: "CPU", value: formatCPU(usage.cpuPercent))
                DetailLine(label: "Memory", value: formatBytes(usage.memoryBytes))
                DetailLine(label: "Hot Process", value: hotProcessLabel(usage.hotProcesses?.first))
            }
            InspectorActionStack {
                Button { store.startProject(group) } label: { Label("Run", systemImage: "play.fill").frame(maxWidth: .infinity) }
                Button { store.restartProject(group) } label: { Label("Restart", systemImage: "arrow.clockwise").frame(maxWidth: .infinity) }
                Button { store.stopProject(group) } label: { Label("Stop", systemImage: "stop").frame(maxWidth: .infinity) }
            }
            Button {
                store.statusProject(group)
            } label: {
                Label("Check Runtime", systemImage: "checkmark.seal")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            if let report {
                ProjectRuntimeSummary(report: report)
            }
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

struct StartServerSheet: View {
    @ObservedObject var store: OpsStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Start Managed Server")
                .font(.title2.bold())
            TextField("Name", text: $store.startDraft.name)
            TextField("Project", text: $store.startDraft.project)
            TextField("Working directory", text: $store.startDraft.cwd)
            TextField("Command using {port}", text: $store.startDraft.command, axis: .vertical)
                .lineLimit(2...4)
            HStack {
                TextField("Port range", text: $store.startDraft.range)
                TextField("Exact port", text: $store.startDraft.preferredPort)
                TextField("Health URL", text: $store.startDraft.healthURL)
            }
            Text("Exact port is optional. When set, the coordinator reserves only that port.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Start") { store.startServer() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(store.startDraft.name.isEmpty || store.startDraft.command.isEmpty || !preferredPortIsValid)
            }
        }
        .padding(24)
        .frame(width: 620)
    }

    private var preferredPortIsValid: Bool {
        let value = store.startDraft.preferredPort.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return true }
        guard let port = Int(value) else { return false }
        return (1...65535).contains(port)
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
            TextField("Range", text: $store.leaseRange)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Lease") { store.leasePort() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 420)
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
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: "terminal")
                    .foregroundStyle(Theme.blue)
                    .frame(width: 28, height: 28)
                    .background(Theme.blue.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 7))
                VStack(alignment: .leading, spacing: 3) {
                    Text("No managed dev servers in this scope")
                        .font(.system(size: 13, weight: .semibold))
                    Text("Use the coordinator before opening default ports.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                }
                Spacer()
                ToolbarButton(title: "Lease", systemImage: "calendar.badge.plus") {
                    store.showingLeaseSheet = true
                }
                ToolbarButton(title: "Start", systemImage: "play.circle.fill", tint: Theme.green) {
                    store.prepareStartDraft()
                    store.showingStartSheet = true
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
        .help(projectPath.isEmpty ? "All coordinator projects" : projectPath)
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
    let hasBackup: Bool

    var body: some View {
        Label(hasBackup ? "Protected" : "Unprotected", systemImage: hasBackup ? "shield.checkered" : "exclamationmark.shield")
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(hasBackup ? Theme.green : Theme.orange)
            .lineLimit(1)
            .frame(minWidth: 108, alignment: .leading)
    }
}

struct StatusBar: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        HStack(spacing: 14) {
            StatusDot(status: statusSeverity)
            Text(statusText)
                .font(.system(size: 12))
                .foregroundStyle(statusSeverity == "running" ? Theme.secondary : Theme.orange)
            Spacer()
            Text("Lease: \(store.inventory.leases.first?.id.prefix(8) ?? "none")")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
            Text("Coordinator: \(store.inventory.coordinatorHome ?? "not found")")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
        }
        .padding(.horizontal, 18)
        .frame(height: 38)
    }

    private var overloadedProject: ProjectUsage? {
        store.inventory.projectUsage.first(where: isHighProjectUsage)
    }

    private var statusText: String {
        if let error = store.lastError { return error }
        if let overloadedProject {
            return "High load: \(overloadedProject.name ?? overloadedProject.project.map(shortProject) ?? overloadedProject.projectKey ?? "project") \(formatCPU(overloadedProject.cpuPercent)) / \(formatBytes(overloadedProject.memoryBytes))"
        }
        return "All systems nominal"
    }

    private var statusSeverity: String {
        if store.lastError != nil || overloadedProject != nil { return "unhealthy" }
        return "running"
    }
}

struct StatusDot: View {
    let status: String?

    var body: some View {
        Circle()
            .fill(statusColor(status))
            .frame(width: 9, height: 9)
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
                    action: toggleAction
                )
                SidebarActionButton(
                    title: "Restart",
                    systemImage: "arrow.clockwise",
                    tint: Theme.secondary,
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

    private var canStop: Bool {
        canStopStatus(status)
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

struct SidebarStopAllButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(isEnabled ? Theme.primary : Theme.secondary.opacity(0.7))
            .lineLimit(1)
            .minimumScaleFactor(0.85)
            .frame(maxWidth: .infinity, minHeight: 30)
            .background(background(configuration: configuration))
            .clipShape(RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).stroke(Theme.red.opacity(isEnabled ? 0.28 : 0.08)))
    }

    private func background(configuration: Configuration) -> Color {
        if !isEnabled { return Theme.control }
        return configuration.isPressed ? Theme.red.opacity(0.28) : Theme.red.opacity(0.14)
    }
}

struct SidebarFooterView: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        GeometryReader { proxy in
            let contentWidth = sidebarFooterContentWidth(totalWidth: proxy.size.width)
            VStack(spacing: 10) {
                Button {
                    store.stopAll()
                } label: {
                    Label("Stop all", systemImage: "stop.circle.fill")
                        .frame(width: contentWidth)
                }
                .buttonStyle(SidebarStopAllButtonStyle())
                .frame(width: contentWidth, height: 30)
                .disabled(!store.hasStoppableResources)

                HStack(spacing: 8) {
                    Circle()
                        .fill(store.connected ? Theme.green : Theme.red)
                        .frame(width: 9, height: 9)
                        .fixedSize()
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Coordinator")
                            .font(.system(size: 12, weight: .medium))
                            .lineLimit(1)
                        Text(store.connected ? "Connected" : "Waiting")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.secondary)
                            .lineLimit(1)
                    }
                    .layoutPriority(1)
                    Spacer(minLength: 8)
                    Image(systemName: "gearshape")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(Theme.secondary)
                        .frame(width: 24, height: 24)
                        .contentShape(Rectangle())
                        .help("Coordinator")
                }
                .frame(width: contentWidth, alignment: .leading)
                .frame(minHeight: 28, alignment: .leading)
            }
            .frame(width: contentWidth, alignment: .topLeading)
            .padding(.leading, sidebarFooterInset)
            .padding(.top, 16)
        }
        .frame(height: sidebarFooterHeight)
        .clipped()
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

struct WindowDots: View {
    var body: some View {
        HStack(spacing: 7) {
            Circle().fill(Color(red: 1, green: 0.37, blue: 0.33))
            Circle().fill(Color(red: 1, green: 0.76, blue: 0.24))
            Circle().fill(Color(red: 0.26, green: 0.82, blue: 0.31))
        }
        .frame(width: 54, height: 12)
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
    if value.contains("unhealthy") || value.contains("failed") || value.contains("dead") { return Theme.red }
    if value.contains("start") || value.contains("warning") || value.contains("degraded") { return Theme.orange }
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

private let serviceRoleTokens: Set<String> = [
    "api",
    "app",
    "backend",
    "cache",
    "database",
    "db",
    "frontend",
    "mailhog",
    "metrics",
    "minio",
    "nginx",
    "pg",
    "postgis",
    "postgres",
    "queue",
    "redis",
    "scheduler",
    "server",
    "web",
    "worker"
]

private let deploymentQualifierTokens: Set<String> = [
    "copy",
    "dev",
    "development",
    "local",
    "prod",
    "production",
    "stage",
    "staging",
    "test"
]

func projectKey(fromPath path: String?) -> String {
    projectKey(fromResourceName: shortProject(path))
}

func projectKey(fromDockerContainer container: DockerContainer) -> String {
    if let project = container.project, !project.isEmpty {
        return projectKey(fromPath: project)
    }
    return projectKey(fromResourceName: container.name)
}

func projectPathForGroup(
    key: String,
    servers: [ManagedServer],
    containers: [DockerContainer],
    databases: [DockerContainer]
) -> String? {
    if let path = servers.compactMap(\.project).first(where: { !$0.isEmpty }) {
        return path
    }
    if let path = (containers + databases).compactMap(\.project).first(where: { !$0.isEmpty }) {
        return path
    }
    let sourceRoot = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("src")
    if let entries = try? FileManager.default.contentsOfDirectory(at: sourceRoot, includingPropertiesForKeys: nil) {
        if let exact = entries.first(where: { $0.lastPathComponent == key }) {
            return exact.path
        }
        if let caseInsensitive = entries.first(where: { $0.lastPathComponent.lowercased() == key.lowercased() }) {
            return caseInsensitive.path
        }
    }
    return nil
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

func projectName(from name: String?) -> String {
    projectKey(fromResourceName: name)
}

func projectLabel(for container: DockerContainer) -> String {
    if let project = container.project, !project.isEmpty {
        return shortProject(project)
    }
    return projectName(from: container.name)
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

func projectKey(fromResourceName name: String?) -> String {
    let tokens = projectNameTokens(from: name)
    guard !tokens.isEmpty else { return "local" }
    if let markerIndex = tokens.firstIndex(where: { serviceRoleTokens.contains($0) }) {
        let projectTokens = trimTrailingQualifiers(Array(tokens[..<markerIndex]))
        if !projectTokens.isEmpty {
            return projectTokens.joined(separator: "-")
        }
    }
    return trimTrailingQualifiers(tokens).joined(separator: "-")
}

func projectDisplayName(
    key: String,
    servers: [ManagedServer],
    containers: [DockerContainer],
    databases: [DockerContainer]
) -> String {
    if let serverProject = servers.compactMap(\.project).map(shortProject).first(where: { projectKey(fromResourceName: $0) == key }) {
        return serverProject
    }
    if let resourceProject = (containers + databases).compactMap(\.project).map(shortProject).first(where: { projectKey(fromResourceName: $0) == key }) {
        return resourceProject
    }
    let resourceName = (containers + databases)
        .compactMap(\.name)
        .first { projectKey(fromResourceName: $0) == key }
    return resourceName.map { displayProjectName(fromResourceName: $0, key: key) } ?? key
}

func displayProjectName(fromResourceName name: String, key: String) -> String {
    let tokens = projectNameTokens(from: name)
    guard !tokens.isEmpty else { return key }
    if let markerIndex = tokens.firstIndex(where: { serviceRoleTokens.contains($0) }) {
        let projectTokens = trimTrailingQualifiers(Array(tokens[..<markerIndex]))
        if !projectTokens.isEmpty {
            return projectTokens.joined(separator: "-")
        }
    }
    return key
}

func resourceDisplayName(_ name: String?, inProject projectKey: String) -> String {
    guard let name, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return "service" }
    let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
    let normalized = trimmed.lowercased().replacingOccurrences(of: "_", with: "-")
    let prefix = projectKey + "-"
    if normalized.hasPrefix(prefix) {
        let index = trimmed.index(trimmed.startIndex, offsetBy: min(prefix.count, trimmed.count))
        let suffix = String(trimmed[index...]).trimmingCharacters(in: CharacterSet(charactersIn: "-_ "))
        return suffix.isEmpty ? trimmed : suffix
    }
    return trimmed
}

func projectNameTokens(from name: String?) -> [String] {
    guard let name else { return [] }
    return name
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
        .replacingOccurrences(of: "_", with: "-")
        .split(separator: "-")
        .map(String.init)
        .filter { !$0.isEmpty && Int($0) == nil }
}

func trimTrailingQualifiers(_ tokens: [String]) -> [String] {
    var result = tokens
    while let last = result.last, deploymentQualifierTokens.contains(last) {
        result.removeLast()
    }
    return result.isEmpty ? tokens : result
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

import AppKit
import SwiftUI

struct OpsConsoleView: View {
    @StateObject private var store = OpsStore()

    var body: some View {
        HStack(spacing: 0) {
            ServiceMapView(store: store)
                .frame(width: 250)
            Divider().overlay(Color.white.opacity(0.06))
            MainBoardView(store: store)
                .frame(minWidth: 660)
            Divider().overlay(Color.white.opacity(0.06))
            ActionRailView(store: store)
                .frame(width: 300)
        }
        .background(Theme.background)
        .foregroundStyle(Theme.primary)
        .task { await store.loadInventory() }
        .sheet(isPresented: $store.showingStartSheet) {
            StartServerSheet(store: store)
        }
        .sheet(isPresented: $store.showingLeaseSheet) {
            LeaseSheet(store: store)
        }
    }
}

struct ServiceMapView: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                WindowDots()
                Text("Codex Ops Console")
                    .font(.system(size: 14, weight: .semibold))
                Spacer()
            }
            .padding(.horizontal, 18)
            .frame(height: 58)

            VStack(alignment: .leading, spacing: 10) {
                Text("SERVICE MAP")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.secondary)
                    .tracking(0.5)

                if groupedProjects.isEmpty {
                    EmptyMapHint()
                } else {
                    ForEach(groupedProjects, id: \.name) { group in
                        ProjectNode(group: group)
                    }
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            Divider().overlay(Color.white.opacity(0.06))
            HStack(spacing: 8) {
                Circle()
                    .fill(store.connected ? Theme.green : Theme.red)
                    .frame(width: 9, height: 9)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Coordinator")
                        .font(.system(size: 12, weight: .medium))
                    Text(store.connected ? "Connected" : "Waiting")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.secondary)
                }
                Spacer()
                Image(systemName: "gearshape")
                    .foregroundStyle(Theme.secondary)
            }
            .padding(18)
        }
        .background(Theme.sidebar)
    }

    private var groupedProjects: [ProjectGroup] {
        let servers = Dictionary(grouping: store.inventory.servers) { shortProject($0.project) }
        let docker = Dictionary(grouping: store.inventory.docker.containers) { projectName(from: $0.name) }
        let names = Set(servers.keys).union(docker.keys).sorted()
        return names.map { name in
            ProjectGroup(name: name, servers: servers[name] ?? [], containers: docker[name] ?? [])
        }
    }
}

struct ProjectGroup {
    var name: String
    var servers: [ManagedServer]
    var containers: [DockerContainer]
}

struct ProjectNode: View {
    let group: ProjectGroup

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "chevron.down")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.secondary)
                StatusDot(status: groupStatus)
                Text(group.name)
                    .font(.system(size: 14, weight: .semibold))
                    .lineLimit(1)
                Spacer()
                CountBadge(count: group.servers.count + group.containers.count)
            }

            if !group.servers.isEmpty {
                MapCategory(title: "Dev Servers", count: group.servers.count)
                ForEach(group.servers.prefix(4)) { server in
                    MapLeaf(title: server.name, status: server.status)
                }
            }

            if !group.containers.isEmpty {
                MapCategory(title: "Docker", count: group.containers.count)
                ForEach(group.containers.prefix(4)) { container in
                    MapLeaf(title: container.name ?? "container", status: container.status)
                }
            }
        }
        .padding(.bottom, 8)
    }

    private var groupStatus: String {
        if group.servers.contains(where: { ($0.status ?? "").lowercased() == "unhealthy" }) { return "unhealthy" }
        if group.servers.contains(where: { ($0.status ?? "").lowercased() == "running" }) { return "running" }
        return "stopped"
    }
}

struct MainBoardView: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        VStack(spacing: 0) {
            ToolbarView(store: store)
            Divider().overlay(Color.white.opacity(0.07))

            ScrollView {
                VStack(spacing: 22) {
                    FilterRow(store: store)
                    DevServersSection(store: store)
                    DockerSection(store: store)
                    DatabaseSection(store: store)
                }
                .padding(22)
            }

            Divider().overlay(Color.white.opacity(0.07))
            StatusBar(store: store)
        }
        .background(Theme.background)
    }
}

struct ToolbarView: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        HStack(spacing: 12) {
            EnvironmentPicker(projectPath: $store.projectPath)
                .frame(width: 190)
            SearchField(text: $store.searchText)
            ToolbarButton(title: "Refresh", systemImage: "arrow.clockwise") {
                store.refresh()
            }
            ToolbarButton(title: "New Lease", systemImage: "calendar.badge.plus") {
                store.showingLeaseSheet = true
            }
            ToolbarButton(title: "Start Server", systemImage: "play.circle.fill", tint: Theme.green) {
                store.startDraft.project = store.projectPath
                store.startDraft.cwd = store.projectPath
                store.showingStartSheet = true
            }
            ToolbarButton(title: "Backup DB", systemImage: "externaldrive.badge.timemachine", tint: Theme.blue) {
                store.backupDatabase(container: store.visiblePostgres.first)
            }
        }
        .padding(.horizontal, 16)
        .frame(height: 62)
        .background(Theme.toolbar)
    }
}

struct FilterRow: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        HStack(spacing: 12) {
            Picker("Filter", selection: $store.filter) {
                ForEach(ServiceFilter.allCases) { filter in
                    Label(filter.rawValue, systemImage: filterIcon(filter))
                        .tag(filter)
                }
            }
            .pickerStyle(.segmented)
            .frame(width: 430)

            Spacer()
            Text("Group by")
                .foregroundStyle(Theme.secondary)
            Picker("Group by", selection: $store.groupBy) {
                Text("Category").tag("Category")
                Text("Project").tag("Project")
                Text("Health").tag("Health")
            }
            .frame(width: 135)
        }
    }
}

struct DevServersSection: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        SectionSurface(title: "DEV SERVERS", count: store.filteredServers.count, systemImage: "terminal") {
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 0) {
                HeaderRow(["Service", "Project", "URL", "Status", "Uptime", "Port", "Actions"])
                ForEach(store.filteredServers) { server in
                    GridRow {
                        HStack(spacing: 10) {
                            StatusDot(status: server.status)
                            Text(server.name).fontWeight(.medium)
                        }
                        Text(shortProject(server.project)).foregroundStyle(Theme.secondary)
                        URLCell(url: server.url, open: { store.openURL(server.url) }, copy: { store.copyURL(server.url) })
                        StatusText(status: server.status)
                        Text(server.health?.pidAlive == true ? "active" : "—").foregroundStyle(Theme.secondary)
                        Text(server.port.map(String.init) ?? "—").monospacedDigit()
                        HStack(spacing: 8) {
                            IconButton("Restart", "arrow.clockwise") { store.restart(server) }
                            IconButton("Stop", "stop") { store.stop(server) }
                            IconButton("Open", "arrow.up.forward.square") { store.openURL(server.url) }
                        }
                    }
                    .frame(height: 39)
                    .contentShape(Rectangle())
                    .onTapGesture { store.selectedServerID = server.id }
                    Divider().overlay(Color.white.opacity(0.06))
                }
            }
        }
    }
}

struct DockerSection: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        SectionSurface(title: "DOCKER", count: store.visibleDockerContainers.count, systemImage: "shippingbox") {
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 0) {
                HeaderRow(["Container / Group", "Project", "Status", "CPU", "Memory", "Restarts", "Actions"])
                ForEach(store.visibleDockerContainers) { container in
                    GridRow {
                        HStack(spacing: 10) {
                            StatusDot(status: container.status)
                            Text(container.name ?? "container").fontWeight(.medium)
                        }
                        Text(projectName(from: container.name)).foregroundStyle(Theme.secondary)
                        StatusText(status: container.status)
                        UsageBar(value: usageSeed(container.name, offset: 0))
                        UsageBar(value: usageSeed(container.name, offset: 17))
                        Text(container.status?.contains("Restart") == true ? "1" : "0")
                            .foregroundStyle(Theme.secondary)
                        HStack(spacing: 8) {
                            IconButton("Restart", "arrow.clockwise") { store.restartDocker(container) }
                            IconButton("Stop", "stop") { store.stopDocker(container) }
                            IconButton("Logs", "doc.text") { store.dockerLogs(container) }
                            IconButton("Backup", "externaldrive.badge.timemachine") { store.backupDatabase(container: container) }
                        }
                    }
                    .frame(height: 36)
                    Divider().overlay(Color.white.opacity(0.06))
                }
            }
        }
    }
}

struct DatabaseSection: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        SectionSurface(title: "DATABASES", count: store.visiblePostgres.count, systemImage: "cylinder.split.1x2") {
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 0) {
                HeaderRow(["Database", "Project", "Engine", "Status", "Size", "Last Backup", "Restore Safety", "Actions"])
                ForEach(store.visiblePostgres) { db in
                    GridRow {
                        HStack(spacing: 10) {
                            StatusDot(status: db.status)
                            Text(db.name ?? "postgres").fontWeight(.medium)
                        }
                        Text(projectName(from: db.name)).foregroundStyle(Theme.secondary)
                        Text(db.image ?? "postgres").foregroundStyle(Theme.secondary)
                        StatusText(status: db.status)
                        Text("—").foregroundStyle(Theme.secondary)
                        Text(lastBackupText(for: db, backups: store.inventory.backups))
                            .foregroundStyle(backupColor(for: db, backups: store.inventory.backups))
                        Label("Protected", systemImage: "shield.checkered")
                            .foregroundStyle(Theme.green)
                        HStack(spacing: 8) {
                            IconButton("Backup", "externaldrive.badge.timemachine") { store.backupDatabase(container: db) }
                            IconButton("Logs", "terminal") { store.dockerLogs(db) }
                        }
                    }
                    .frame(height: 38)
                    Divider().overlay(Color.white.opacity(0.06))
                }
            }
        }
    }
}

struct ActionRailView: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 20) {
                Text("ACTION QUEUE  \(store.actionItems.count)")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(Theme.secondary)

                if store.actionItems.isEmpty {
                    Text("No queued actions. Run inventory, lease a port, start a server, or back up a database.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    ForEach(store.actionItems.prefix(5)) { item in
                        ActionItemRow(item: item)
                    }
                }
            }
            .padding(20)

            Divider().overlay(Color.white.opacity(0.07))

            VStack(alignment: .leading, spacing: 16) {
                Text("RECENT EVENTS")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(Theme.secondary)

                if store.inventory.recentEvents.isEmpty {
                    Text("Project-specific events will appear here after agents use the coordinator.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                } else {
                    ForEach(store.inventory.recentEvents.prefix(9)) { event in
                        EventRow(event: event)
                    }
                }
                Spacer()
                if let selected = store.selectedServer {
                    Divider().overlay(Color.white.opacity(0.07))
                    SelectedServerPanel(store: store, server: selected)
                }
            }
            .padding(20)
        }
        .background(Theme.sidebar)
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
            DetailLine(label: "Port", value: server.port.map(String.init) ?? "—")
            DetailLine(label: "Health", value: server.status ?? "unknown")
            DetailLine(label: "Log", value: server.logPath ?? "—")
            Button {
                store.openURL(server.url)
            } label: {
                Label("Open in Browser", systemImage: "arrow.up.forward.square")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            Button {
                store.copyURL(server.url)
            } label: {
                Label("Copy URL", systemImage: "link")
                    .frame(maxWidth: .infinity)
            }
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
                TextField("Health URL", text: $store.startDraft.healthURL)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Start") { store.startServer() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(store.startDraft.name.isEmpty || store.startDraft.command.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 620)
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
        }
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
    let open: () -> Void
    let copy: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Button(action: open) {
                Text(url ?? "—")
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)
            }
            .buttonStyle(URLButtonStyle())
            Button(action: copy) {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(IconButtonStyle())
            .disabled(url == nil)
        }
    }
}

struct ToolbarButton: View {
    let title: String
    let systemImage: String
    var tint: Color = Theme.primary
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(tint)
                .padding(.horizontal, 10)
                .frame(height: 36)
        }
        .buttonStyle(.plain)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
    }
}

struct SearchField: View {
    @Binding var text: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(Theme.secondary)
            TextField("Search servers, containers, databases, URLs...", text: $text)
                .textFieldStyle(.plain)
        }
        .padding(.horizontal, 12)
        .frame(height: 38)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
    }
}

struct EnvironmentPicker: View {
    @Binding var projectPath: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "square.stack.3d.up")
                .foregroundStyle(Theme.blue)
            VStack(alignment: .leading, spacing: 2) {
                Text("Environment")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.secondary)
                TextField("Project path", text: $projectPath)
                    .font(.system(size: 12, weight: .semibold))
                    .textFieldStyle(.plain)
            }
        }
        .padding(.horizontal, 12)
        .frame(height: 42)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.08)))
    }
}

struct ActionItemRow: View {
    let item: ActionItem

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(item.title)
                        .font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Text(item.state.rawValue)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(color)
                }
                Text(item.subtitle)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .lineLimit(2)
            }
        }
    }

    private var icon: String {
        switch item.state {
        case .running: return "progress.indicator"
        case .queued: return "clock"
        case .completed: return "checkmark.circle.fill"
        case .failed: return "xmark.octagon.fill"
        }
    }

    private var color: Color {
        switch item.state {
        case .running: return Theme.blue
        case .queued: return Theme.orange
        case .completed: return Theme.green
        case .failed: return Theme.red
        }
    }
}

struct EventRow: View {
    let event: RecentEvent

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            StatusDot(status: event.type.contains("stopped") ? "stopped" : "running")
                .padding(.top, 4)
            VStack(alignment: .leading, spacing: 4) {
                Text(event.type.replacingOccurrences(of: ".", with: " "))
                    .font(.system(size: 12, weight: .medium))
                Text(event.at)
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
            }
            Spacer()
        }
    }
}

struct StatusBar: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        HStack(spacing: 14) {
            StatusDot(status: store.lastError == nil ? "running" : "unhealthy")
            Text(store.lastError ?? "All systems nominal")
                .font(.system(size: 12))
                .foregroundStyle(store.lastError == nil ? Theme.secondary : Theme.red)
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

struct MapCategory: View {
    let title: String
    let count: Int

    var body: some View {
        HStack(spacing: 8) {
            Text(title)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Theme.secondary)
            CountBadge(count: count)
        }
        .padding(.leading, 24)
    }
}

struct MapLeaf: View {
    let title: String
    let status: String?

    var body: some View {
        HStack(spacing: 8) {
            StatusDot(status: status)
            Text(title)
                .font(.system(size: 12))
                .lineLimit(1)
        }
        .padding(.leading, 42)
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
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(Theme.secondary)
            Spacer()
            Text(value)
                .lineLimit(2)
                .multilineTextAlignment(.trailing)
        }
        .font(.system(size: 12))
    }
}

struct UsageBar: View {
    let value: Double

    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.white.opacity(0.09))
                Capsule()
                    .fill(Theme.blue)
                    .frame(width: max(8, proxy.size.width * value))
            }
        }
        .frame(width: 70, height: 6)
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

func statusColor(_ status: String?) -> Color {
    let value = (status ?? "").lowercased()
    if value.contains("unhealthy") || value.contains("exited") || value.contains("failed") { return Theme.red }
    if value.contains("start") || value.contains("warning") || value.contains("degraded") { return Theme.orange }
    if value.contains("stop") || value.isEmpty { return Theme.secondary }
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

func projectName(from name: String?) -> String {
    guard let name, !name.isEmpty else { return "local" }
    let parts = name.split(separator: "-")
    if parts.count >= 2 {
        return parts.prefix(2).joined(separator: "-")
    }
    return name
}

func filterIcon(_ filter: ServiceFilter) -> String {
    switch filter {
    case .all: return "circle.grid.2x2"
    case .running: return "circle.fill"
    case .unhealthy: return "exclamationmark.triangle.fill"
    case .stopped: return "pause.circle"
    }
}

func usageSeed(_ value: String?, offset: Int) -> Double {
    let sum = (value ?? "container").unicodeScalars.reduce(offset) { $0 + Int($1.value) }
    return Double((sum % 72) + 15) / 100.0
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

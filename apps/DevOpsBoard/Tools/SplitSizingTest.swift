import CoreGraphics
import Foundation

@main
struct SplitSizingTest {
    static func main() {
        assertEqual(
            resizedPaneWidth(start: 280, startX: 100, currentX: 160, direction: 1, range: 220...520),
            340,
            "left splitter should increase width when dragged right"
        )
        assertEqual(
            resizedPaneWidth(start: 280, startX: 100, currentX: 20, direction: 1, range: 220...520),
            220,
            "left splitter should clamp at minimum"
        )
        assertEqual(
            resizedPaneWidth(start: 340, startX: 900, currentX: 840, direction: -1, range: 320...500),
            400,
            "right splitter should increase inspector width when dragged left"
        )
        assertEqual(
            resizedPaneWidth(start: 340, startX: 900, currentX: 980, direction: -1, range: 320...500),
            320,
            "right splitter should clamp at minimum when dragged right"
        )
        assertMonotonicRightPane()
        assertEqual(
            resizedColumnWidth(start: 120, startX: 300, currentX: 360),
            180,
            "column width should increase when dragged right"
        )
        assertEqual(
            resizedColumnWidth(start: 120, startX: 300, currentX: 180),
            72,
            "column width should clamp at minimum"
        )
        assertMonotonicColumn()
        assertNarrowLayoutDoesNotOverflow()
        assertSidebarFooterWidth()
        assertProjectGrouping()
        assertServerDeduplication()
        assertCurrentURLHandling()
        assertSidebarActionState()
        assertProjectUsageFormatting()
        print("split sizing ok")
    }

    private static func assertMonotonicRightPane() {
        let samples = stride(from: 960.0, through: 820.0, by: -20.0).map {
            resizedPaneWidth(start: 340, startX: 900, currentX: CGFloat($0), direction: -1, range: 320...500)
        }
        for pair in zip(samples, samples.dropFirst()) {
            if pair.1 < pair.0 {
                fail("right splitter width should grow monotonically as cursor moves left")
            }
        }
    }

    private static func assertMonotonicColumn() {
        let samples = stride(from: 250.0, through: 390.0, by: 20.0).map {
            resizedColumnWidth(start: 140, startX: 300, currentX: CGFloat($0))
        }
        for pair in zip(samples, samples.dropFirst()) {
            if pair.1 < pair.0 {
                fail("column width should grow monotonically as cursor moves right")
            }
        }
    }

    private static func assertNarrowLayoutDoesNotOverflow() {
        let layout = consoleLayout(totalWidth: 1180, sidebarPreference: 320, inspectorPreference: 320)
        assert(layout.showsMain, "1180 px layout should still show the main board")
        assert(layout.showsInspector, "1180 px layout should fit the inspector by shrinking the main board")
        assertEqual(layout.sidebarWidth, 320, "1180 px layout should preserve the readable sidebar width")
        let total = layout.sidebarWidth + splitHandleWidth + layout.mainWidth + splitHandleWidth + layout.inspectorWidth
        assertEqual(total, 1180, "1180 px layout should exactly fit without clipping either edge")

        let compact = consoleLayout(totalWidth: 440, sidebarPreference: 320, inspectorPreference: 320)
        assert(!compact.showsMain, "very narrow layout should prioritize an uncropped sidebar over unusable content panes")
        assertEqual(compact.sidebarWidth, 320, "very narrow layout should keep the preferred sidebar width when it fits")
    }

    private static func assertSidebarFooterWidth() {
        assertEqual(
            sidebarFooterContentWidth(totalWidth: 320),
            284,
            "sidebar footer controls should keep equal horizontal insets at readable width"
        )
        assertEqual(
            sidebarFooterContentWidth(totalWidth: 250),
            214,
            "sidebar footer controls should not exceed a narrow visible pane"
        )
        assertEqual(
            sidebarFooterContentWidth(totalWidth: 20),
            0,
            "sidebar footer content width should never become negative"
        )
    }

    private static func assertServerDeduplication() {
        let staleApi = server(
            id: "old-api",
            name: "api",
            project: "/Users/holyglory/src/XFoilFOAM",
            port: 4000,
            status: "stopped",
            updatedAt: "2026-06-27T21:28:11Z"
        )
        let newerApi = server(
            id: "new-api",
            name: "api",
            project: "/Users/holyglory/src/XFoilFOAM",
            port: 4000,
            status: "stopped",
            updatedAt: "2026-06-28T14:09:19Z"
        )
        let web = server(
            id: "web",
            name: "web",
            project: "/Users/holyglory/src/XFoilFOAM",
            port: 3004,
            status: "stopped",
            updatedAt: "2026-06-28T14:09:18Z"
        )
        let deduped = deduplicatedManagedServers([staleApi, newerApi, web])
        assert(deduped.count == 2, "deduplication should keep one api row and one web row")
        let api = deduped.first { $0.name == "api" }
        assert(api?.id == "new-api", "deduplication should keep the newest duplicate logical server")
        assert(api?.duplicateCount == 2, "deduplicated server should expose collapsed duplicate count")

        let inventory = Inventory(
            coordinatorHome: nil,
            statePath: nil,
            project: "/Users/holyglory/src/XFoilFOAM",
            urls: [],
            servers: [staleApi, newerApi, web],
            leases: [],
            recentEvents: [],
            docker: DockerSummary(available: nil, error: nil, statsError: nil, containers: [], postgres: []),
            postgres: [],
            backups: [],
            projectUsage: [
                ProjectUsage(
                    usageKey: "path:/Users/holyglory/src/XFoilFOAM",
                    project: "/Users/holyglory/src/XFoilFOAM",
                    projectKey: "xfoilfoam",
                    name: "XFoilFOAM",
                    serverIDs: ["old-api", "new-api", "web"],
                    containerNames: nil,
                    serverCount: 2,
                    containerCount: 3,
                    processCount: 4,
                    cpuPercent: 329.8,
                    memoryBytes: 15_323_463_680,
                    processCPUPercent: 329.8,
                    processMemoryBytes: 15_081_799_680,
                    dockerCPUPercent: 0,
                    dockerMemoryBytes: 0,
                    processes: nil,
                    hotProcesses: [
                        ProcessUsage(
                            source: nil,
                            pid: 18970,
                            ppid: 18790,
                            rootPIDs: nil,
                            pids: nil,
                            processCount: nil,
                            cpuPercent: 329.8,
                            rssBytes: 15_071_772_672,
                            memoryBytes: nil,
                            command: "next-server (v15.5.19)",
                            sampledAt: nil,
                            project: nil,
                            serverID: nil,
                            serverName: nil,
                            processes: nil,
                            hotProcesses: nil
                        )
                    ]
                )
            ]
        )
        let group = makeProjectGroups(from: inventory).first { $0.id == "path:/Users/holyglory/src/XFoilFOAM" }
        assert(group?.servers.count == 2, "project tree should not show duplicate api server rows")
        assert(group?.usage?.hotProcesses?.first?.pid == 18970, "project tree should retain project usage for XFoilFOAM")
    }

    // Grouping must consume the coordinator's project_usage membership
    // (usage_key / server_ids / container_names), never re-derive repo
    // identity from resource names. Fixtures mirror how real inventories
    // break: sidecar-attributed containers whose names look like another
    // repo, coordinator-claimed containers, name-keyed unclaimed groups,
    // and stray items from older coordinator payloads.
    private static func assertProjectGrouping() {
        let registeredDatabase = DockerContainer(
            id: "3cbab56ad1b2",
            name: "aerodb-pg",
            image: "postgres:16-alpine",
            status: "Up 8 days",
            ports: "0.0.0.0:5544->5432/tcp",
            project: "/Users/holyglory/src/XFoilFOAM",
            agent: "codex",
            role: "postgres",
            metadataSource: "coordinator_sidecar",
            adopted: true,
            stats: nil,
            statsHistory: nil
        )
        let claimedDatabase = DockerContainer(
            id: "9f21c00aa001",
            name: "grouprepo-db",
            image: "postgres:16-alpine",
            status: "Up 2 hours",
            ports: "0.0.0.0:5433->5432/tcp",
            project: nil,
            agent: nil,
            role: nil,
            metadataSource: "none",
            adopted: nil,
            stats: nil,
            statsHistory: nil
        )
        let unclaimedWorker = DockerContainer(
            id: "77aa88bb99cc",
            name: "sharedname-worker",
            image: "node:20",
            status: "Up 1 hour",
            ports: "",
            project: nil,
            agent: nil,
            role: nil,
            metadataSource: "none",
            adopted: nil,
            stats: nil,
            statsHistory: nil
        )
        let strayContainer = DockerContainer(
            id: "00dd11ee22ff",
            name: "legacy-widget",
            image: "nginx:1.27",
            status: "Exited (0) 3 days ago",
            ports: "",
            project: nil,
            agent: nil,
            role: nil,
            metadataSource: "none",
            adopted: nil,
            stats: nil,
            statsHistory: nil
        )
        let groupRepoWeb = server(
            id: "grouprepo-web-1",
            name: "web",
            project: "/Users/holyglory/src/GroupRepo",
            port: 3000,
            status: "running",
            updatedAt: "2026-07-07T10:00:00Z"
        )
        let sharednameRepoWeb = server(
            id: "sharedname-web-1",
            name: "web",
            project: "/Users/holyglory/src/sharedname",
            port: 3100,
            status: "running",
            updatedAt: "2026-07-07T10:00:00Z"
        )
        let inventory = Inventory(
            coordinatorHome: nil,
            statePath: nil,
            project: nil,
            urls: [],
            servers: [groupRepoWeb, sharednameRepoWeb],
            leases: [],
            recentEvents: [],
            docker: DockerSummary(
                available: true,
                error: nil,
                statsError: nil,
                containers: [registeredDatabase, claimedDatabase, unclaimedWorker, strayContainer],
                postgres: [registeredDatabase, claimedDatabase]
            ),
            postgres: [registeredDatabase, claimedDatabase],
            backups: [],
            projectUsage: [
                usageRow(
                    usageKey: "path:/Users/holyglory/src/XFoilFOAM",
                    project: "/Users/holyglory/src/XFoilFOAM",
                    projectKey: "xfoilfoam",
                    name: "XFoilFOAM",
                    containerNames: ["aerodb-pg"]
                ),
                usageRow(
                    usageKey: "path:/Users/holyglory/src/GroupRepo",
                    project: "/Users/holyglory/src/GroupRepo",
                    projectKey: "grouprepo",
                    name: "GroupRepo",
                    serverIDs: ["grouprepo-web-1"],
                    containerNames: ["grouprepo-db"]
                ),
                usageRow(
                    usageKey: "path:/Users/holyglory/src/sharedname",
                    project: "/Users/holyglory/src/sharedname",
                    projectKey: "sharedname",
                    name: "sharedname",
                    serverIDs: ["sharedname-web-1"]
                ),
                usageRow(
                    usageKey: "name:sharedname",
                    project: nil,
                    projectKey: "sharedname",
                    name: "sharedname",
                    containerNames: ["sharedname-worker"]
                )
            ]
        )
        let groups = makeProjectGroups(from: inventory)

        // Must-catch: a sidecar-attributed container whose NAME suggests a
        // different repo ("aerodb") must display under the attributed repo —
        // the exact display-vs-action divergence class fixed coordinator-side.
        let xfoil = groups.first { $0.id == "path:/Users/holyglory/src/XFoilFOAM" }
        assert(xfoil != nil, "attributed repo should form a usage_key-identified group")
        assert(
            xfoil?.databases.contains { $0.stableID == registeredDatabase.stableID } == true,
            "sidecar-attributed aerodb-pg must display under XFoilFOAM, not a name-derived aerodb group"
        )
        assert(
            !groups.contains { $0.name == "aerodb" },
            "no name-derived aerodb group may exist for an attributed container"
        )
        assertString(xfoil?.name ?? "", "XFoilFOAM", "group display name should come from the membership row")
        assertString(xfoil?.projectPath ?? "", "/Users/holyglory/src/XFoilFOAM", "group action path should come from the membership row")

        // Must-catch: an unattributed grouprepo-db the coordinator claims by
        // unique name match must display under the path-keyed repo group.
        let groupRepo = groups.first { $0.id == "path:/Users/holyglory/src/GroupRepo" }
        assert(
            groupRepo?.databases.contains { $0.stableID == claimedDatabase.stableID } == true,
            "coordinator-claimed grouprepo-db must display under the path-keyed GroupRepo group"
        )
        assert(
            groupRepo?.servers.contains { $0.id == groupRepoWeb.id } == true,
            "server membership must come from server_ids, not path key derivation"
        )

        // Must-catch: a container the coordinator left unclaimed must NOT be
        // folded into a repo group whose derived name key happens to match —
        // the old name-key heuristics merged these, so the board showed the
        // container inside a group whose project stop would not touch it.
        let sharednameRepo = groups.first { $0.id == "path:/Users/holyglory/src/sharedname" }
        assert(sharednameRepo != nil, "sharedname repo should form its own path-keyed group")
        assert(
            sharednameRepo?.containers.isEmpty == true && sharednameRepo?.databases.isEmpty == true,
            "an unclaimed same-key container must stay out of the repo group whose actions do not touch it"
        )
        let unclaimed = groups.first { $0.id == "name:sharedname" }
        assert(unclaimed != nil, "unclaimed containers should keep their coordinator name-keyed group")
        assert(unclaimed?.projectPath == nil, "name-keyed groups must not synthesize an action path")
        assert(
            unclaimed?.containers.contains { $0.stableID == unclaimedWorker.stableID } == true,
            "unclaimed worker should display in its name-keyed group"
        )

        // Safety net: a container missing from every membership row (older
        // coordinator payload) must stay visible in the stray fallback group.
        let stray = groups.first { $0.id == strayProjectGroupID }
        assert(
            stray?.containers.contains { $0.stableID == strayContainer.stableID } == true,
            "membership-less containers must stay visible in the stray fallback group"
        )
        let displayed = groups.reduce(0) { $0 + $1.containers.count + $1.databases.count }
        assert(displayed == inventory.docker.containers.count, "every container must be displayed exactly once across groups")

        // Table labels reuse group membership so a row's project column names
        // the group its actions run under.
        assertString(
            projectLabel(for: registeredDatabase, in: groups),
            "XFoilFOAM",
            "Docker/database table project labels should follow membership grouping"
        )
        assertString(
            projectLabel(for: strayContainer, in: groups),
            "other",
            "membership-less containers should be labeled with the stray group"
        )

        assertString(
            resourceDisplayName("globalnewstracker-metrics-worker", inProject: "GlobalNewsTracker"),
            "metrics-worker",
            "leaf labels should drop the repeated project prefix case-insensitively"
        )

        // usage_key is a persisted coordinator contract; the details panel
        // fallback parses it when a selection drops out of cached groups.
        assertString(
            projectPath(fromUsageKey: "path:/Users/holyglory/src/GroupRepo") ?? "",
            "/Users/holyglory/src/GroupRepo",
            "path-keyed selections should recover their runtime action path"
        )
        assert(projectPath(fromUsageKey: "name:sharedname") == nil, "name-keyed selections must not invent an action path")
        assertString(projectName(fromUsageKey: "path:/Users/holyglory/src/GroupRepo"), "GroupRepo", "path-keyed selections should display the repo name")
        assertString(projectName(fromUsageKey: "name:sharedname"), "sharedname", "name-keyed selections should display the derived key")
    }

    private static func usageRow(
        usageKey: String,
        project: String?,
        projectKey: String,
        name: String,
        serverIDs: [String] = [],
        containerNames: [String] = []
    ) -> ProjectUsage {
        ProjectUsage(
            usageKey: usageKey,
            project: project,
            projectKey: projectKey,
            name: name,
            serverIDs: serverIDs.isEmpty ? nil : serverIDs,
            containerNames: containerNames.isEmpty ? nil : containerNames,
            serverCount: serverIDs.count,
            containerCount: containerNames.count,
            processCount: nil,
            cpuPercent: nil,
            memoryBytes: nil,
            processCPUPercent: nil,
            processMemoryBytes: nil,
            dockerCPUPercent: nil,
            dockerMemoryBytes: nil,
            processes: nil,
            hotProcesses: nil
        )
    }

    private static func assertSidebarActionState() {
        assert(canStopStatus("running"), "running status should show stop action")
        assert(canStopStatus("Up 2 weeks (healthy)"), "running Docker status should show stop action")
        assert(!canStopStatus("stopped"), "stopped server should show run action")
        assert(!canStopStatus("Exited (0) 2 hours ago"), "exited Docker status should show run action")
        assert(!canStopStatus(nil), "unknown empty status should not show stop action")
        let stoppedForeignPID = server(
            id: "stale-pid",
            name: "web",
            project: "/Users/holyglory/src/benzovozka",
            port: 3000,
            status: "stopped",
            updatedAt: "2026-07-01T08:39:42Z",
            health: Health(ok: false, pidAlive: true)
        )
        assert(!canStopServer(stoppedForeignPID), "stopped stale metadata rows should not show stop actions for a foreign live PID")
    }

    private static func assertCurrentURLHandling() {
        let staleServer = server(
            id: "skydivelive-web-old",
            name: "skydivelive-web",
            project: "/Users/holyglory/src/skydivelive",
            port: 3001,
            status: "stopped",
            updatedAt: "2026-06-21T19:47:48Z",
            urlIsCurrent: false
        )
        assert(staleServer.currentURL == nil, "stale stopped server rows should not expose openable URLs")
    }

    private static func assertProjectUsageFormatting() {
        let hot = ProcessUsage(
            source: nil,
            pid: 18970,
            ppid: nil,
            rootPIDs: nil,
            pids: nil,
            processCount: nil,
            cpuPercent: 329.8,
            rssBytes: 15_071_772_672,
            memoryBytes: nil,
            command: "next-server (v15.5.19)",
            sampledAt: nil,
            project: nil,
            serverID: nil,
            serverName: nil,
            processes: nil,
            hotProcesses: nil
        )
        assertString(formatCPU(329.8), "329.8%", "CPU formatter should preserve high multi-core percentages")
        assertString(hotProcessLabel(hot), "PID 18970 next-server (v15.5.19)", "hot process labels should expose PID and command")
    }

    private static func assertEqual(_ actual: CGFloat, _ expected: CGFloat, _ message: String) {
        if abs(actual - expected) > 0.0001 {
            fail("\(message): expected \(expected), got \(actual)")
        }
    }

    private static func assertString(_ actual: String, _ expected: String, _ message: String) {
        if actual != expected {
            fail("\(message): expected \(expected), got \(actual)")
        }
    }

    private static func assert(_ condition: Bool, _ message: String) {
        if !condition {
            fail(message)
        }
    }

    private static func server(
        id: String,
        name: String,
        project: String,
        port: Int,
        status: String,
        updatedAt: String,
        health: Health = Health(ok: false, pidAlive: false),
        urlIsCurrent: Bool? = nil
    ) -> ManagedServer {
        ManagedServer(
            id: id,
            name: name,
            agent: "codex",
            project: project,
            cwd: project,
            command: nil,
            commandTemplate: nil,
            port: port,
            host: "127.0.0.1",
            url: "http://127.0.0.1:\(port)",
            healthURL: nil,
            leaseID: nil,
            pid: nil,
            logPath: nil,
            status: status,
            health: health,
            stoppedAt: updatedAt,
            stoppedReason: "Stopped by coordinator",
            adopted: false,
            missingCommand: false,
            metadataSource: "server_start",
            updatedAt: updatedAt,
            duplicateCount: nil,
            duplicateServerIDs: nil,
            urlIsCurrent: urlIsCurrent,
            portReused: nil,
            portReusedBy: nil,
            processUsage: nil
        )
    }

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        exit(1)
    }
}

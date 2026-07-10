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
            project: "/fixtures/projects/XFoilFOAM",
            port: 4000,
            status: "stopped",
            updatedAt: "2026-06-27T21:28:11Z"
        )
        let newerApi = server(
            id: "new-api",
            name: "api",
            project: "/fixtures/projects/XFoilFOAM",
            port: 4000,
            status: "stopped",
            updatedAt: "2026-06-28T14:09:19Z"
        )
        let web = server(
            id: "web",
            name: "web",
            project: "/fixtures/projects/XFoilFOAM",
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
            project: "/fixtures/projects/XFoilFOAM",
            urls: [],
            servers: [staleApi, newerApi, web],
            leases: [],
            recentEvents: [],
            docker: DockerSummary(available: nil, error: nil, statsError: nil, containers: [], postgres: []),
            postgres: [],
            backups: [],
            projectUsage: [
                ProjectUsage(
                    project: "/fixtures/projects/XFoilFOAM",
                    projectKey: "xfoilfoam",
                    name: "XFoilFOAM",
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
        let group = projectGroups(from: inventory).first { $0.id == "xfoilfoam" }
        assert(group?.servers.count == 2, "project tree should not show duplicate api server rows")
        assert(group?.usage?.hotProcesses?.first?.pid == 18970, "project tree should retain project usage for XFoilFOAM")
    }

    private static func assertProjectGrouping() {
        assertString(
            projectKey(fromResourceName: "globalnewstracker-metrics-worker"),
            "globalnewstracker",
            "metrics worker should group under globalnewstracker"
        )
        assertString(
            projectKey(fromResourceName: "globalnewstracker-minio"),
            "globalnewstracker",
            "minio should group under globalnewstracker"
        )
        assertString(
            projectKey(fromResourceName: "globalnewstracker-postgres"),
            "globalnewstracker",
            "postgres should group under globalnewstracker"
        )
        assertString(
            projectKey(fromResourceName: "xfoilfoam-cfd-api"),
            "xfoilfoam-cfd",
            "domain words before api should remain part of the project"
        )
        assertString(
            projectKey(fromResourceName: "kosttracking-prod-copy-pg"),
            "kosttracking",
            "environment qualifiers before pg should not split the project"
        )
        assertString(
            resourceDisplayName("globalnewstracker-metrics-worker", inProject: "globalnewstracker"),
            "metrics-worker",
            "leaf labels should drop the repeated project prefix"
        )
        let registeredDatabase = DockerContainer(
            id: "3cbab56ad1b2",
            name: "aerodb-pg",
            image: "postgres:16-alpine",
            status: "Up 8 days",
            ports: "0.0.0.0:5544->5432/tcp",
            project: "/fixtures/projects/XFoilFOAM",
            agent: "codex",
            role: "postgres",
            metadataSource: "coordinator_sidecar",
            adopted: true,
            stats: nil,
            statsHistory: nil
        )
        assertString(
            projectKey(fromDockerContainer: registeredDatabase),
            "xfoilfoam",
            "registered Docker sidecar project should beat aerodb-pg name-derived grouping"
        )
        assertString(
            projectDisplayName(key: "xfoilfoam", servers: [], containers: [], databases: [registeredDatabase]),
            "XFoilFOAM",
            "project display name should come from registered Docker project path"
        )
        assertString(
            projectLabel(for: registeredDatabase),
            "XFoilFOAM",
            "Docker/database table project labels should prefer registered project paths"
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
            project: "/fixtures/projects/sample-commerce",
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
            project: "/fixtures/projects/sample-dashboard",
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

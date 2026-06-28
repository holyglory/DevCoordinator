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
        assertSidebarActionState()
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
            project: "/Users/holyglory/src/XFoilFOAM",
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

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        exit(1)
    }
}

import AppKit
import CoreGraphics
import Foundation
import SwiftUI
import XCTest
@testable import DevOpsBoard

@MainActor
final class MainBoardVerticalLayoutTests: XCTestCase {
    private let mainPaneWidth = 524
    private let minimumWindowHeight = 760
    private let desktopMainPaneWidth = 784
    private let desktopWindowHeight = 900

    func testDenseMinimumWindowKeepsToolbarAndStatusInBounds() throws {
        let fixture = try makeDenseMinimumWindowFixture()

        XCTAssertEqual(fixture.store.inventory.projectUsage.count, 6)
        XCTAssertEqual(fixture.store.projectGroups.filter(\.isRepository).count, 6)
        XCTAssertFalse(fixture.store.projectGroups.contains { !$0.isRepository })
        XCTAssertEqual(fixture.store.filteredServers.count, 19)
        XCTAssertNotNil(fixture.store.actionIssue)
        XCTAssertEqual(fixture.store.actionResults.count, 1)
        XCTAssertTrue(
            fixture.store.resourceAttentionItems.isEmpty,
            "intentionally stopped servers must remain ordinary lifecycle state"
        )
        XCTAssertEqual(fixture.store.presentationSnapshot.statusTitle, "Restart service-1 failed")
        XCTAssertEqual(fixture.store.presentationSnapshot.statusMessage, "The health check did not become ready.")
        XCTAssertNotEqual(
            fixture.store.presentationSnapshot.statusTitle,
            fixture.store.presentationSnapshot.statusMessage,
            "the banner must not repeat generic attention copy"
        )

        let raster = try renderMainBoard(
            store: fixture.store,
            width: mainPaneWidth,
            height: minimumWindowHeight
        )
        try captureRasterIfRequested(
            raster,
            name: "main-board-dense-524x760"
        )
        let assessment = MainBoardEdgeDetector.assess(raster)

        XCTAssertTrue(
            assessment.toolbarIsVisible,
            "dense minimum-window rendering cropped the fixed toolbar: \(assessment.toolbar)"
        )
        XCTAssertTrue(
            assessment.statusIsVisible,
            "dense minimum-window rendering cropped the fixed status footer: \(assessment.status)"
        )
        XCTAssertTrue(
            assessment.bodyHasVisibleContent,
            "dense minimum-window rendering left no usable variable-body content: \(assessment.body)"
        )
    }

    func testFullThreePaneMinimumWindowKeepsTheMiddlePaneEdgesAndPrimaryContentVisible() throws {
        let fixture = try makeDenseMinimumWindowFixture()
        let raster = try renderOpsConsole(
            store: fixture.store,
            width: 1_180,
            height: minimumWindowHeight
        )
        let layout = consoleLayout(
            totalWidth: 1_180,
            sidebarPreference: defaultSidebarWidth,
            inspectorPreference: minimumInspectorWidth
        )
        XCTAssertEqual(layout.mainWidth, CGFloat(mainPaneWidth), accuracy: 0.001)
        let mainStart = Int(layout.sidebarWidth + splitHandleWidth)
        let middlePane = raster.cropped(
            xRange: mainStart..<(mainStart + Int(layout.mainWidth))
        )
        try captureRasterIfRequested(raster, name: "ops-console-dense-1180x760")
        let assessment = MainBoardEdgeDetector.assess(middlePane)

        XCTAssertTrue(
            assessment.hasBothFixedEdges,
            "the full split shell cropped the middle pane: toolbar=\(assessment.toolbar), status=\(assessment.status)"
        )
        XCTAssertTrue(
            assessment.bodyHasVisibleContent,
            "the full split shell hid the middle pane's primary inventory content: \(assessment.body)"
        )
    }

    func testDenseNormalDesktopKeepsFixedEdgesAndUsableBodyInBounds() throws {
        let fixture = try makeDenseMinimumWindowFixture()
        let raster = try renderMainBoard(
            store: fixture.store,
            width: desktopMainPaneWidth,
            height: desktopWindowHeight
        )
        try captureRasterIfRequested(
            raster,
            name: "main-board-dense-784x900"
        )
        let assessment = MainBoardEdgeDetector.assess(raster)

        XCTAssertTrue(
            assessment.hasBothFixedEdges,
            "normal desktop rendering cropped fixed chrome: toolbar=\(assessment.toolbar), status=\(assessment.status)"
        )
        XCTAssertTrue(
            assessment.bodyHasVisibleContent,
            "normal desktop rendering left no usable variable-body content: \(assessment.body)"
        )
    }

    func testDetectorCatchesRealisticCenterOnlyUpwardCrop() throws {
        let fixture = try makeDenseMinimumWindowFixture()
        let intact = try renderMainBoard(
            store: fixture.store,
            width: mainPaneWidth,
            height: minimumWindowHeight
        )
        XCTAssertTrue(MainBoardEdgeDetector.assess(intact).hasBothFixedEdges)

        // This models the failure produced when an oversized center pane is
        // centered in an exact-height frame and then clipped. Only this pane
        // moves; the sidebar and inspector remain correctly positioned.
        let centerOnlyCrop = intact.shiftedUp(by: 48)
        let assessment = MainBoardEdgeDetector.assess(centerOnlyCrop)

        XCTAssertFalse(
            assessment.hasBothFixedEdges,
            "the detector missed a production-shaped center-only upward crop"
        )
    }

    func testDetectorAllowsIntentionalInnerTableScrollingAndEmptyBody() throws {
        let fixture = try makeDenseMinimumWindowFixture()
        let intact = try renderMainBoard(
            store: fixture.store,
            width: mainPaneWidth,
            height: minimumWindowHeight
        )

        let internallyScrolled = intact.scrollingOnlyVariableBody(upBy: 72)
        XCTAssertTrue(
            MainBoardEdgeDetector.assess(internallyScrolled).hasBothFixedEdges,
            "ordinary inner-table scrolling must not be classified as pane-edge cropping"
        )
        XCTAssertTrue(
            MainBoardEdgeDetector.assess(internallyScrolled).bodyHasVisibleContent,
            "ordinary inner-table scrolling must retain the surrounding primary controls"
        )

        let emptyResourceRows = intact.clearingResourceRows(yRange: 505..<678)
        let emptyResourceAssessment = MainBoardEdgeDetector.assess(emptyResourceRows)
        XCTAssertTrue(
            emptyResourceAssessment.hasBothFixedEdges && emptyResourceAssessment.bodyHasVisibleContent,
            "an intentionally empty resource table must retain its Project Load, filters, tabs, and heading"
        )

        let emptyBody = intact.clearingOnlyVariableBody()
        XCTAssertTrue(
            MainBoardEdgeDetector.assess(emptyBody).hasBothFixedEdges,
            "an intentionally empty resource body must retain valid fixed pane edges"
        )
    }

    func testDetectorRejectsBannerAndActivityWithoutPrimaryDecisionContent() throws {
        let fixture = try makeDenseMinimumWindowFixture()
        let intact = try renderMainBoard(
            store: fixture.store,
            width: mainPaneWidth,
            height: minimumWindowHeight
        )

        // Production-shaped loss: keep the actionable banner, toolbar,
        // Activity, and status exactly where they render, but erase Project
        // Load, filters, tabs, section heading, and resource rows.
        let bannerAndActivityOnly = intact.clearingPrimaryContent(yRange: 151..<678)
        let legacyBodyObservation = bannerAndActivityOnly.brightPixelObservation(yRange: 55..<721)
        XCTAssertTrue(
            legacyBodyObservation.meetsVariableBodyMinimum,
            "the fixture must prove banner and Activity alone satisfy the former whole-body detector"
        )

        let assessment = MainBoardEdgeDetector.assess(bannerAndActivityOnly)
        XCTAssertTrue(
            assessment.hasBothFixedEdges,
            "the fixture must retain toolbar and status so this is primary-content loss, not edge cropping"
        )
        XCTAssertFalse(
            assessment.bodyHasVisibleContent,
            "the detector accepted a banner and Activity while the primary decision content was erased"
        )
    }

    func testConcreteResourceAttentionKeepsActionableBannerAndFixedEdgesVisible() throws {
        let fixture = try makeDenseMinimumWindowFixture()
        fixture.store.actionIssue = nil
        fixture.store.actionResults.removeAll()

        var unhealthy = fixture.store.inventory.servers[0]
        unhealthy.status = "unhealthy"
        unhealthy.health = Health(ok: false, pidAlive: true)
        unhealthy.stoppedReason = nil
        fixture.store.inventory.servers[0] = unhealthy

        let attention = try XCTUnwrap(fixture.store.resourceAttentionItems.first)
        XCTAssertEqual(fixture.store.resourceAttentionItems.count, 1)
        XCTAssertEqual(attention.title, "service-1 is unhealthy")
        XCTAssertTrue(attention.reason.localizedCaseInsensitiveContains("unhealthy"))
        XCTAssertEqual(attention.reviewTarget.actionLabel, "Review server")
        XCTAssertEqual(fixture.store.presentationSnapshot.statusTitle, attention.title)
        XCTAssertNotEqual(
            fixture.store.presentationSnapshot.statusTitle,
            fixture.store.presentationSnapshot.statusMessage
        )

        let raster = try renderMainBoard(
            store: fixture.store,
            width: mainPaneWidth,
            height: minimumWindowHeight
        )
        try captureRasterIfRequested(
            raster,
            name: "main-board-resource-attention-524x760"
        )
        let assessment = MainBoardEdgeDetector.assess(raster)
        XCTAssertTrue(assessment.hasBothFixedEdges)
        XCTAssertTrue(assessment.bodyHasVisibleContent)
    }

    func testActivityReviewRequestIsRetainedUntilTheMainBoardConsumesIt() throws {
        let coordinator = ActivityReviewCoordinator.shared
        if let existing = coordinator.pendingRequestID {
            coordinator.consume(existing)
        }

        coordinator.requestReview()
        let requestID = try XCTUnwrap(coordinator.pendingRequestID)

        coordinator.consume(UUID())
        XCTAssertEqual(coordinator.pendingRequestID, requestID)

        coordinator.consume(requestID)
        XCTAssertNil(coordinator.pendingRequestID)
    }

    func testMainBoardConsumesBufferedActivityReviewWhenItAppears() throws {
        let fixture = try makeDenseMinimumWindowFixture()
        let coordinator = ActivityReviewCoordinator.shared
        if let existing = coordinator.pendingRequestID {
            coordinator.consume(existing)
        }
        coordinator.requestReview()
        XCTAssertNotNil(coordinator.pendingRequestID)

        _ = try renderMainBoard(
            store: fixture.store,
            width: mainPaneWidth,
            height: minimumWindowHeight
        )

        XCTAssertNil(
            coordinator.pendingRequestID,
            "the main board must consume a menu-bar Activity request after it appears"
        )
    }
}

@MainActor
private func makeDenseMinimumWindowFixture() throws -> DenseMinimumWindowFixture {
    let origin = CoordinatorOrigin(
        label: "Dense fixture",
        home: "/fixtures/dense-minimum/coordinator",
        statePath: "/fixtures/dense-minimum/coordinator/state.json"
    )
    let projectNames = ["Nevod", "GlobalFinance", "progress", "SkydiveLive", "mailcheck", "aerodb"]
    let fixtureRoot = FileManager.default.temporaryDirectory
        .appendingPathComponent("devops-board-dense-layout-\(UUID().uuidString)", isDirectory: true)
    var keepFixture = false
    defer {
        if !keepFixture { try? FileManager.default.removeItem(at: fixtureRoot) }
    }
    let projectURLs = projectNames.map {
        fixtureRoot.appendingPathComponent($0, isDirectory: true)
    }
    for projectURL in projectURLs {
        try FileManager.default.createDirectory(
            at: projectURL.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
    }
    let projects = projectURLs.map(\.path)
    let nativeServerIDs = (0..<19).map { "dense-server-\($0 + 1)" }

    let servers: [[String: Any]] = nativeServerIDs.indices.map { index in
        let projectIndex = index % projects.count
        let running = index < 3
        return [
            "id": nativeServerIDs[index],
            "name": "service-\(index + 1)",
            "agent": "fixture-agent",
            "project": projects[projectIndex],
            "cwd": projects[projectIndex],
            "cmd": "fixture-server --port \(4_300 + index)",
            "port": 4_300 + index,
            "host": "127.0.0.1",
            "url": "http://127.0.0.1:\(4_300 + index)",
            "status": running ? "running" : "stopped",
            "health": ["ok": running, "pid_alive": running],
            "updated_at": "2026-07-13T12:00:00Z",
            "created_at": "2026-07-13T11:00:00Z",
        ]
    }
    let usage: [[String: Any]] = projects.indices.map { projectIndex in
        let memberIDs = nativeServerIDs.indices
            .filter { $0 % projects.count == projectIndex }
            .map { nativeServerIDs[$0] }
        return [
            "usage_key": "path:\(projects[projectIndex])",
            "project": projects[projectIndex],
            "project_key": projectNames[projectIndex].lowercased(),
            "name": projectNames[projectIndex],
            "server_ids": memberIDs,
            "container_names": [],
            "server_count": memberIDs.count,
            "container_count": projectIndex < 3 ? 2 : 1,
            "process_count": projectIndex + 1,
            "cpu_percent": 2.5 + Double(projectIndex),
            "memory_bytes": 512_000_000 + (projectIndex * 64_000_000),
            "process_cpu_percent": 2.5 + Double(projectIndex),
            "process_memory_bytes": 256_000_000 + (projectIndex * 32_000_000),
            "docker_cpu_percent": 0.0,
            "docker_memory_bytes": 0,
        ]
    }
    let document: [String: Any] = [
        "coordinator_home": origin.home,
        "state_path": origin.statePath ?? "\(origin.home)/state.json",
        "urls": [],
        "servers": servers,
        "leases": [],
        "recent_events": [],
        "docker": [
            "available": true,
            "error": NSNull(),
            "stats_error": NSNull(),
            "containers": [],
            "postgres": [],
        ],
        "postgres": [],
        "backups": [],
        "project_usage": usage,
    ]
    let data = try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys])
    var inventory = try JSONDecoder().decode(Inventory.self, from: data)
    inventory.origin = origin
    inventory.servers = inventory.servers.map { server in
        var server = server
        server.origin = origin
        server.coordinatorID = server.id
        server.id = ResourceIdentity(origin: origin, kind: .server, nativeID: server.id).rawValue
        return server
    }
    inventory.projectUsage = inventory.projectUsage.map { row in
        var row = row
        row.origin = origin
        return row
    }

    let now = Date(timeIntervalSince1970: 1_768_219_200)
    let store = OpsStore(
        originDiscovery: VerticalLayoutOriginDiscovery(values: [origin]),
        configurationStore: VerticalLayoutConfigurationStore(),
        clock: VerticalLayoutClock(value: now)
    )
    store.inventory = inventory
    store.sourceStates = [
        CoordinatorSourceState(
            origin: origin,
            phase: .loaded,
            checkedAt: now,
            resourceCount: inventory.servers.count
        )
    ]
    store.capabilityStates = CoordinatorCapability.allCases.map {
        CoordinatorCapabilityState(
            origin: origin,
            capability: $0,
            phase: .available,
            checkedAt: now,
            error: nil
        )
    }

    let actionID = UUID(uuidString: "00000000-0000-0000-0000-000000000760")!
    let request = ActionRequest(
        id: actionID,
        kind: .restartServer,
        title: "Restart service-1",
        origin: origin,
        resource: inventory.servers[0].resourceIdentity,
        projectPath: projects[0]
    )
    store.actionResults[actionID] = RetainedActionResult(
        request: request,
        phase: .failed,
        queuedAt: now.addingTimeInterval(-2),
        startedAt: now.addingTimeInterval(-1),
        finishedAt: now,
        exitStatus: 1,
        stdout: "",
        stderr: "Fixture health check timed out.",
        failure: "The health check did not become ready."
    )
    store.actionIssue = OpsIssue(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000761")!,
        kind: .action,
        title: "Restart service-1 failed",
        summary: "The health check did not become ready.",
        details: "Fixture health check timed out while restarting service-1.",
        createdAt: now,
        relatedActionID: actionID
    )

    keepFixture = true
    return DenseMinimumWindowFixture(store: store, fixtureRoot: fixtureRoot)
}

@MainActor
private func renderMainBoard(store: OpsStore, width: Int, height: Int) throws -> BoardRaster {
    let view = MainBoardView(store: store)
        // Keep the default frame alignment here: before the repair, the dense
        // intrinsic height was centered and both fixed edges were clipped.
        .frame(width: CGFloat(width), height: CGFloat(height))
        .background(Theme.background)
        .preferredColorScheme(.dark)
    return try renderRaster(view, width: width, height: height)
}

@MainActor
private func renderOpsConsole(store: OpsStore, width: Int, height: Int) throws -> BoardRaster {
    try renderRaster(
        OpsConsoleView(store: store)
            .frame(width: CGFloat(width), height: CGFloat(height), alignment: .topLeading)
            .background(Theme.background)
            .preferredColorScheme(.dark),
        width: width,
        height: height
    )
}

@MainActor
private func renderRaster<Content: View>(
    _ view: Content,
    width: Int,
    height: Int
) throws -> BoardRaster {
    let hostingView = NSHostingView(rootView: view)
    hostingView.frame = NSRect(x: 0, y: 0, width: CGFloat(width), height: CGFloat(height))
    hostingView.layoutSubtreeIfNeeded()
    hostingView.displayIfNeeded()
    guard let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: width,
        pixelsHigh: height,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else {
        throw VerticalLayoutFixtureError.renderFailed
    }
    bitmap.size = hostingView.bounds.size
    hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
    guard let sourceImage = bitmap.cgImage else {
        throw VerticalLayoutFixtureError.renderFailed
    }

    var pixels = [UInt8](repeating: 0, count: width * height * 4)
    let rendered = pixels.withUnsafeMutableBytes { bytes -> Bool in
        guard let baseAddress = bytes.baseAddress,
              let context = CGContext(
                  data: baseAddress,
                  width: width,
                  height: height,
                  bitsPerComponent: 8,
                  bytesPerRow: width * 4,
                  space: CGColorSpaceCreateDeviceRGB(),
                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
              )
        else { return false }
        context.setFillColor(NSColor.black.cgColor)
        context.fill(CGRect(x: 0, y: 0, width: CGFloat(width), height: CGFloat(height)))
        context.draw(sourceImage, in: CGRect(x: 0, y: 0, width: CGFloat(width), height: CGFloat(height)))
        return true
    }
    guard rendered else { throw VerticalLayoutFixtureError.renderFailed }
    return BoardRaster(width: width, height: height, pixels: pixels)
}

private final class DenseMinimumWindowFixture {
    let store: OpsStore
    let fixtureRoot: URL

    init(store: OpsStore, fixtureRoot: URL) {
        self.store = store
        self.fixtureRoot = fixtureRoot
    }

    deinit {
        try? FileManager.default.removeItem(at: fixtureRoot)
    }
}

private struct VerticalLayoutOriginDiscovery: CoordinatorOriginDiscovering {
    let values: [CoordinatorOrigin]
    func origins() -> [CoordinatorOrigin] { values }
}

private struct VerticalLayoutConfigurationStore: CoordinatorConfigurationPersisting {
    func load() -> CoordinatorConfigurationLoadResult {
        CoordinatorConfigurationLoadResult(
            configuration: CoordinatorConfiguration(refreshPolicy: .manual()),
            warning: nil,
            usedLastKnownGood: false
        )
    }

    func save(_ configuration: CoordinatorConfiguration) throws {}
}

private struct VerticalLayoutClock: Clock {
    let value: Date
    func now() -> Date { value }
}

private struct MainBoardEdgeAssessment {
    let toolbar: BrightPixelObservation
    let body: BrightPixelObservation
    let status: BrightPixelObservation

    var toolbarIsVisible: Bool { toolbar.meetsFixedEdgeMinimum }
    var bodyHasVisibleContent: Bool { body.meetsVariableBodyMinimum }
    var statusIsVisible: Bool { status.meetsFixedEdgeMinimum }
    var hasBothFixedEdges: Bool { toolbarIsVisible && statusIsVisible }
}

private enum MainBoardEdgeDetector {
    static func assess(_ raster: BoardRaster) -> MainBoardEdgeAssessment {
        let toolbarHeight = min(54, raster.height)
        let statusHeight = min(38, raster.height)
        let bodyStart = min(toolbarHeight + 1, raster.height)
        let bodyEnd = max(bodyStart, raster.height - statusHeight - 1)
        // The banner and Activity are useful contextual chrome, but neither is
        // the primary inventory decision surface. Exclude their maximum
        // collapsed footprints so they cannot hide a blank project/resource
        // viewport behind a passing aggregate brightness score.
        let primaryStart = min(bodyStart + 96, bodyEnd)
        let primaryEnd = max(primaryStart, bodyEnd - 43)
        return MainBoardEdgeAssessment(
            toolbar: raster.brightPixelObservation(yRange: 0..<toolbarHeight),
            body: raster.brightPixelObservation(yRange: primaryStart..<primaryEnd),
            status: raster.brightPixelObservation(yRange: (raster.height - statusHeight)..<raster.height)
        )
    }
}

private struct BrightPixelObservation: CustomStringConvertible {
    let brightPixels: Int
    let activeXBins: Int
    let activeYBins: Int

    var meetsFixedEdgeMinimum: Bool {
        brightPixels >= 40 && activeXBins >= 4 && activeYBins >= 2
    }

    var meetsVariableBodyMinimum: Bool {
        brightPixels >= 200 && activeXBins >= 8 && activeYBins >= 6
    }

    var description: String {
        "bright=\(brightPixels), x-bins=\(activeXBins), y-bins=\(activeYBins)"
    }
}

private struct BoardRaster {
    let width: Int
    let height: Int
    var pixels: [UInt8]

    func pngData() -> Data? {
        let data = Data(pixels)
        guard let provider = CGDataProvider(data: data as CFData),
              let image = CGImage(
                  width: width,
                  height: height,
                  bitsPerComponent: 8,
                  bitsPerPixel: 32,
                  bytesPerRow: width * 4,
                  space: CGColorSpaceCreateDeviceRGB(),
                  bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue),
                  provider: provider,
                  decode: nil,
                  shouldInterpolate: false,
                  intent: .defaultIntent
              )
        else { return nil }
        return NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
    }

    func brightPixelObservation(yRange: Range<Int>) -> BrightPixelObservation {
        var brightPixels = 0
        var xBins = Set<Int>()
        var yBins = Set<Int>()
        for y in yRange where y >= 0 && y < height {
            for x in 0..<width {
                let offset = ((y * width) + x) * 4
                if max(pixels[offset], max(pixels[offset + 1], pixels[offset + 2])) >= 80 {
                    brightPixels += 1
                    xBins.insert(x / 8)
                    yBins.insert((y - yRange.lowerBound) / 4)
                }
            }
        }
        return BrightPixelObservation(
            brightPixels: brightPixels,
            activeXBins: xBins.count,
            activeYBins: yBins.count
        )
    }

    func shiftedUp(by distance: Int) -> BoardRaster {
        var output = backgroundFilledRaster()
        let distance = min(max(0, distance), height)
        guard distance < height else { return output }
        for destinationY in 0..<(height - distance) {
            output.copyRow(from: self, sourceY: destinationY + distance, destinationY: destinationY)
        }
        return output
    }

    func cropped(xRange: Range<Int>) -> BoardRaster {
        let lower = min(max(0, xRange.lowerBound), width)
        let upper = min(max(lower, xRange.upperBound), width)
        let outputWidth = upper - lower
        var output = BoardRaster(
            width: outputWidth,
            height: height,
            pixels: [UInt8](repeating: 0, count: outputWidth * height * 4)
        )
        guard outputWidth > 0 else { return output }
        for y in 0..<height {
            let sourceStart = ((y * width) + lower) * 4
            let destinationStart = y * outputWidth * 4
            let count = outputWidth * 4
            output.pixels.replaceSubrange(
                destinationStart..<(destinationStart + count),
                with: pixels[sourceStart..<(sourceStart + count)]
            )
        }
        return output
    }

    func scrollingOnlyVariableBody(upBy distance: Int) -> BoardRaster {
        var output = self
        let bodyStart = min(55, height)
        let bodyEnd = max(bodyStart, height - 39)
        let distance = min(max(0, distance), max(0, bodyEnd - bodyStart))
        for destinationY in bodyStart..<bodyEnd {
            let sourceY = destinationY + distance
            if sourceY < bodyEnd {
                output.copyRow(from: self, sourceY: sourceY, destinationY: destinationY)
            } else {
                output.fillRow(destinationY, color: backgroundColor)
            }
        }
        return output
    }

    func clearingOnlyVariableBody() -> BoardRaster {
        var output = self
        let bodyStart = min(55, height)
        let bodyEnd = max(bodyStart, height - 39)
        for y in bodyStart..<bodyEnd {
            output.fillRow(y, color: backgroundColor)
        }
        return output
    }

    func clearingPrimaryContent(yRange: Range<Int>) -> BoardRaster {
        var output = self
        for y in yRange where y >= 0 && y < height {
            output.fillRow(y, color: backgroundColor)
        }
        return output
    }

    func clearingResourceRows(yRange: Range<Int>) -> BoardRaster {
        clearingPrimaryContent(yRange: yRange)
    }

    private var backgroundColor: [UInt8] { [16, 19, 20, 255] }

    private func backgroundFilledRaster() -> BoardRaster {
        var output = BoardRaster(
            width: width,
            height: height,
            pixels: [UInt8](repeating: 0, count: width * height * 4)
        )
        for y in 0..<height {
            output.fillRow(y, color: backgroundColor)
        }
        return output
    }

    private mutating func copyRow(from source: BoardRaster, sourceY: Int, destinationY: Int) {
        let sourceStart = sourceY * width * 4
        let destinationStart = destinationY * width * 4
        let count = width * 4
        pixels.replaceSubrange(
            destinationStart..<(destinationStart + count),
            with: source.pixels[sourceStart..<(sourceStart + count)]
        )
    }

    private mutating func fillRow(_ y: Int, color: [UInt8]) {
        let start = y * width * 4
        for x in 0..<width {
            let offset = start + (x * 4)
            pixels[offset] = color[0]
            pixels[offset + 1] = color[1]
            pixels[offset + 2] = color[2]
            pixels[offset + 3] = color[3]
        }
    }
}

private func captureRasterIfRequested(_ raster: BoardRaster, name: String) throws {
    guard let rawDirectory = ProcessInfo.processInfo.environment["DEVOPS_BOARD_UI_CAPTURE_DIR"]?
        .trimmingCharacters(in: .whitespacesAndNewlines),
          !rawDirectory.isEmpty
    else { return }

    let directory = URL(fileURLWithPath: rawDirectory, isDirectory: true).standardizedFileURL
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true
    )
    guard let data = raster.pngData() else {
        throw VerticalLayoutFixtureError.pngEncodingFailed
    }
    let destination = directory.appendingPathComponent("\(name).png", isDirectory: false)
    try data.write(to: destination, options: .atomic)
    print("DEVOPS_BOARD_UI_CAPTURE=\(destination.path)")
}

private enum VerticalLayoutFixtureError: Error {
    case renderFailed
    case pngEncodingFailed
}

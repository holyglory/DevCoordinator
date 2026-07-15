import AppKit
import Foundation
import XCTest

final class CanonicalSnapshotGenerationTests: XCTestCase {
    func testDesktopShellDetectorCatchesToolbarOnlyCropDespiteBrightBodyContent() {
        let intact = syntheticDesktopShell(includeToolbar: true, includeBottomDecoy: true)
        let toolbarOnlyCrop = syntheticDesktopShell(includeToolbar: false, includeBottomDecoy: true)

        XCTAssertTrue(
            desktopToolbarObservation(intact).isVisible,
            "intentional dark-content control must retain all compact toolbar anchors"
        )
        XCTAssertFalse(
            desktopToolbarObservation(toolbarOnlyCrop).isVisible,
            "must-catch fixture removes only the toolbar while preserving the rendered body"
        )
        XCTAssertGreaterThanOrEqual(
            legacyBroadToolbarBrightPixelCount(toolbarOnlyCrop),
            100,
            "the realistic crop must prove the former 90-pixel aggregate could false-pass on bright body content"
        )
        XCTAssertGreaterThanOrEqual(
            brightPixelCount(in: toolbarOnlyCrop, xRange: 330..<1_110, topYRange: 54..<90),
            100,
            "the must-catch fixture must preserve visible content immediately below the missing toolbar"
        )
    }

    @MainActor
    func testRegenerateCanonicalArtifactsWhenExplicitlyEnabled() throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["DEVOPS_BOARD_REGENERATE_CANONICAL_SNAPSHOTS"] == "1" else {
            throw XCTSkip("Canonical snapshot generation requires an explicit regeneration request.")
        }

        let projectRoot = try SnapshotSourceProvenance.projectRoot()
        let outputDirectory = try approvedOutputDirectory(
            projectRoot: projectRoot,
            requestedPath: environment["DEVOPS_BOARD_SNAPSHOT_OUTPUT_DIR"]
        )

        let serverSnapshot = outputDirectory.appendingPathComponent("dev-servers.png")
        try SnapshotMain.render(arguments: [
            serverSnapshot.path,
            "servers",
            "1440",
            "1024",
        ])
        assertDesktopShellVisible(serverSnapshot)

        let dockerSnapshot = outputDirectory.appendingPathComponent("docker-board.png")
        try SnapshotMain.render(arguments: [
            dockerSnapshot.path,
            "docker",
            "1440",
            "1024",
        ])
        assertDesktopShellVisible(dockerSnapshot)

        let databaseSnapshot = outputDirectory.appendingPathComponent("databases.png")
        try SnapshotMain.render(arguments: [
            databaseSnapshot.path,
            "databases",
            "1440",
            "1024",
        ])
        assertDesktopShellVisible(databaseSnapshot)
        try MenuBarSnapshotMain.render(arguments: [
            outputDirectory.appendingPathComponent("menu-action-error.png").path,
            "error",
        ])
    }

    /// Canonical evidence must never bless the cold-render failure that shifts
    /// the desktop shell upward and leaves the first viewport's toolbar blank.
    /// Keep this independent of text OCR: a real toolbar has a conservative
    /// density of visible controls, while the reported crop is nearly black.
    private func assertDesktopShellVisible(
        _ snapshot: URL,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let data = try? Data(contentsOf: snapshot),
              let bitmap = NSBitmapImageRep(data: data)
        else {
            XCTFail("desktop snapshot could not be decoded: \(snapshot.path)", file: file, line: line)
            return
        }
        let toolbar = desktopToolbarObservation(bitmap)
        XCTAssertTrue(
            toolbar.isVisible,
            "desktop snapshot cropped or failed to render the main toolbar (anchors: \(toolbar)): \(snapshot.lastPathComponent)",
            file: file,
            line: line
        )
    }

    private func brightPixelCount(
        in bitmap: NSBitmapImageRep,
        xRange: Range<Int>,
        topYRange: Range<Int>
    ) -> Int {
        let width = bitmap.pixelsWide
        let height = bitmap.pixelsHigh
        guard xRange.lowerBound >= 0,
              xRange.upperBound <= width,
              topYRange.lowerBound >= 0,
              topYRange.upperBound <= height,
              !bitmap.isPlanar,
              bitmap.bitsPerSample == 8,
              bitmap.bitsPerPixel >= 24,
              bitmap.bitsPerPixel % 8 == 0,
              let pixels = bitmap.bitmapData
        else { return 0 }
        let bytesPerPixel = bitmap.bitsPerPixel / 8
        var count = 0
        // Decoded PNG bitmapData is stored in file scanline order: row zero is
        // the visible top row. Read those bytes directly, and keep a synthetic
        // bottom-decoy control below to prevent a future accidental flip.
        for topY in topYRange {
            for x in xRange {
                let offset = (topY * bitmap.bytesPerRow) + (x * bytesPerPixel)
                var brightBytes = 0
                for component in 0..<bytesPerPixel where pixels[offset + component] >= 90 {
                    brightBytes += 1
                }
                if brightBytes >= 2 {
                    count += 1
                }
            }
        }
        return count
    }

    private func desktopToolbarObservation(_ image: NSBitmapImageRep) -> DesktopToolbarObservation {
        DesktopToolbarObservation(
            environmentPicker: brightPixelCount(
                in: image,
                xRange: 340..<510,
                topYRange: 0..<54
            ),
            searchField: brightPixelCount(
                in: image,
                xRange: 515..<740,
                topYRange: 0..<54
            ),
            sourceAndActions: brightPixelCount(
                in: image,
                xRange: 745..<1_110,
                topYRange: 0..<54
            )
        )
    }

    private func legacyBroadToolbarBrightPixelCount(_ image: NSBitmapImageRep) -> Int {
        brightPixelCount(in: image, xRange: 330..<1_110, topYRange: 0..<90)
    }

    private func syntheticDesktopShell(
        includeToolbar: Bool,
        includeBottomDecoy: Bool
    ) -> NSBitmapImageRep {
        let width = 1_440
        let height = 1_024
        let bitmap = NSBitmapImageRep(
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
        )!
        let bytesPerPixel = bitmap.bitsPerPixel / 8
        let pixels = bitmap.bitmapData!

        func fillTopRelative(_ rect: CGRect) {
            for topY in Int(rect.minY)..<Int(rect.maxY) {
                for x in Int(rect.minX)..<Int(rect.maxX) {
                    let offset = (topY * bitmap.bytesPerRow) + (x * bytesPerPixel)
                    for component in 0..<bytesPerPixel {
                        pixels[offset + component] = 255
                    }
                }
            }
        }

        // Preserve realistic, bright body controls directly beneath the
        // toolbar. The former broad detector incorrectly counted these as
        // evidence that the toolbar itself had rendered.
        fillTopRelative(CGRect(x: 400, y: 68, width: 220, height: 12))
        if includeToolbar {
            fillTopRelative(CGRect(x: 370, y: 28, width: 16, height: 8))
            fillTopRelative(CGRect(x: 560, y: 28, width: 16, height: 8))
            fillTopRelative(CGRect(x: 900, y: 28, width: 16, height: 8))
        }
        if includeBottomDecoy {
            fillTopRelative(CGRect(x: 370, y: height - 36, width: 16, height: 8))
            fillTopRelative(CGRect(x: 560, y: height - 36, width: 16, height: 8))
            fillTopRelative(CGRect(x: 900, y: height - 36, width: 16, height: 8))
        }
        return bitmap
    }
}

private struct DesktopToolbarObservation: CustomStringConvertible {
    static let minimumBrightPixelsPerAnchor = 40

    var environmentPicker: Int
    var searchField: Int
    var sourceAndActions: Int

    var isVisible: Bool {
        environmentPicker >= Self.minimumBrightPixelsPerAnchor
            && searchField >= Self.minimumBrightPixelsPerAnchor
            && sourceAndActions >= Self.minimumBrightPixelsPerAnchor
    }

    var description: String {
        "environment=\(environmentPicker), search=\(searchField), sources/actions=\(sourceAndActions)"
    }
}

private func approvedOutputDirectory(projectRoot: URL, requestedPath: String?) throws -> URL {
    let canonicalDirectory = projectRoot
        .appendingPathComponent("Artifacts/Canonical", isDirectory: true)
        .standardizedFileURL
    guard let requestedPath, !requestedPath.isEmpty else {
        return canonicalDirectory
    }

    let requestedDirectory = URL(fileURLWithPath: requestedPath, isDirectory: true)
        .standardizedFileURL
    let qaDirectory = projectRoot
        .appendingPathComponent(".build/qa", isDirectory: true)
        .standardizedFileURL
    let qaPrefix = qaDirectory.path.hasSuffix("/") ? qaDirectory.path : qaDirectory.path + "/"
    guard requestedDirectory == canonicalDirectory || requestedDirectory.path.hasPrefix(qaPrefix) else {
        throw CanonicalSnapshotGenerationError.unapprovedOutputDirectory(requestedDirectory.path)
    }
    return requestedDirectory
}

private enum CanonicalSnapshotGenerationError: LocalizedError {
    case unapprovedOutputDirectory(String)

    var errorDescription: String? {
        switch self {
        case let .unapprovedOutputDirectory(path):
            "Snapshot output must be Artifacts/Canonical or a project-local .build/qa directory: \(path)"
        }
    }
}

import AppKit
import CryptoKit
import Foundation
import SwiftUI

@main
struct MenuBarSnapshotMain {
    @MainActor
    static func main() async throws {
        let output = CommandLine.arguments.dropFirst().first ?? ".build/qa/snapshots/menu-error.png"
        let mode = CommandLine.arguments.dropFirst().dropFirst().first
        let width: CGFloat = 430
        let height: CGFloat = 600
        let store = OpsStore()
        let fixture = try menuFixtureInventory()
        store.inventory = fixture.inventory
        store.sourceStates = [
            CoordinatorSourceState(
                origin: fixture.origin,
                phase: .loaded,
                checkedAt: Date(timeIntervalSince1970: 1_767_225_600),
                resourceCount: fixture.resourceCount
            )
        ]
        store.capabilityStates = CoordinatorCapability.allCases.map {
            CoordinatorCapabilityState(
                origin: fixture.origin,
                capability: $0,
                phase: .available,
                checkedAt: Date(timeIntervalSince1970: 1_767_225_600)
            )
        }
        if mode == "error" {
            let desktop = CoordinatorOrigin(label: "Desktop", home: "/fixtures/desktop-coordinator")
            store.sourceStates.append(
                CoordinatorSourceState(
                    origin: desktop,
                    phase: .failed,
                    checkedAt: Date(timeIntervalSince1970: 1_767_225_600),
                    error: "Fixture source unavailable"
                )
            )
            store.capabilityStates.append(
                CoordinatorCapabilityState(
                    origin: desktop,
                    capability: .docker,
                    phase: .unavailable,
                    checkedAt: Date(timeIntervalSince1970: 1_767_225_600),
                    error: "Fixture Docker unavailable"
                )
            )
            let request = ActionRequest(
                id: UUID(uuidString: "00000000-0000-0000-0000-000000000431")!,
                kind: .restartServer,
                title: "Restart web",
                resource: ResourceIdentity(origin: fixture.origin, kind: .server, nativeID: "fixture-server-web")
            )
            store.actionResults[request.id] = RetainedActionResult(
                request: request,
                phase: .failed,
                queuedAt: Date(timeIntervalSince1970: 1_767_225_600),
                startedAt: Date(timeIntervalSince1970: 1_767_225_601),
                finishedAt: Date(timeIntervalSince1970: 1_767_225_602),
                exitStatus: 1,
                stderr: "Fixture health check rejected the restart.",
                failure: "Health check failed"
            )
            try validateFixtureCopy(store)
        }

        let view = MenuBarRuntimeView(
            store: store,
            openConsole: {},
            quit: {},
            loadsInventoryOnAppear: false
        )
        .frame(width: width, height: height)
        .preferredColorScheme(.dark)

        let hostingView = NSHostingView(rootView: view)
        hostingView.frame = NSRect(x: 0, y: 0, width: width, height: height)
        hostingView.layoutSubtreeIfNeeded()
        hostingView.displayIfNeeded()

        guard let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: Int(width),
            pixelsHigh: Int(height),
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: 0,
            bitsPerPixel: 0
        ) else {
            throw MenuBarSnapshotError.renderFailed
        }
        bitmap.size = hostingView.bounds.size
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try opaqueMenuPNGRepresentation(from: bitmap, size: hostingView.bounds.size)

        try writeMenuSnapshotArtifact(
            png,
            to: URL(fileURLWithPath: output),
            width: Int(width),
            height: Int(height)
        )
    }
}

@MainActor
private func validateFixtureCopy(_ store: OpsStore) throws {
    guard let result = store.actionResults.values.first else {
        throw MenuBarSnapshotError.fixtureCopyDoesNotFit
    }
    let footerWidth = (result.request.title as NSString).size(
        withAttributes: [.font: NSFont.systemFont(ofSize: 11)]
    ).width
    guard footerWidth <= 190 else { throw MenuBarSnapshotError.fixtureCopyDoesNotFit }

    let attributes: [NSAttributedString.Key: Any] = [
        .font: NSFont.monospacedSystemFont(ofSize: 10, weight: .regular)
    ]
    let widestDetailLine = store.actionResultDetails(result)
        .split(separator: "\n", omittingEmptySubsequences: false)
        .map { (String($0) as NSString).size(withAttributes: attributes).width }
        .max() ?? 0
    guard widestDetailLine <= 360 else { throw MenuBarSnapshotError.fixtureCopyDoesNotFit }
}

private func opaqueMenuPNGRepresentation(from bitmap: NSBitmapImageRep, size: NSSize) throws -> Data {
    let width = Int(size.width)
    let height = Int(size.height)
    let colorSpace = CGColorSpaceCreateDeviceRGB()
    guard let sourceImage = bitmap.cgImage,
          let context = CGContext(
              data: nil,
              width: width,
              height: height,
              bitsPerComponent: 8,
              bytesPerRow: width * 4,
              space: colorSpace,
              bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue
          )
    else {
        throw MenuBarSnapshotError.renderFailed
    }
    context.setFillColor(NSColor.black.cgColor)
    context.fill(CGRect(x: 0, y: 0, width: width, height: height))
    context.draw(sourceImage, in: CGRect(x: 0, y: 0, width: width, height: height))
    guard let flattened = context.makeImage(),
          let png = NSBitmapImageRep(cgImage: flattened).representation(using: .png, properties: [:])
    else {
        throw MenuBarSnapshotError.renderFailed
    }
    return png
}

private struct MenuFixtureInventory {
    var inventory: Inventory
    var origin: CoordinatorOrigin

    var resourceCount: Int {
        inventory.servers.count + inventory.leases.count + inventory.docker.containers.count + inventory.postgres.count
    }
}

private func menuFixtureInventory() throws -> MenuFixtureInventory {
    var inventory = try JSONDecoder().decode(Inventory.self, from: Data(menuFixtureInventoryJSON.utf8))
    let origin = CoordinatorOrigin(
        label: "Fixture",
        home: "/fixtures/coordinator",
        statePath: "/fixtures/coordinator/state.json"
    )
    inventory.origin = origin
    inventory.urls = inventory.urls.map { value in
        var value = value
        value.origin = origin
        return value
    }
    inventory.servers = inventory.servers.map { value in
        var value = value
        value.origin = origin
        value.coordinatorID = value.id
        value.id = ResourceIdentity(origin: origin, kind: .server, nativeID: value.id).rawValue
        return value
    }
    inventory.docker.containers = inventory.docker.containers.map { value in
        var value = value
        value.origin = origin
        return value
    }
    inventory.docker.postgres = inventory.docker.postgres.map { value in
        var value = value
        value.origin = origin
        return value
    }
    inventory.postgres = inventory.postgres.map { value in
        var value = value
        value.origin = origin
        value.database = "appdb"
        return value
    }
    inventory.projectUsage = inventory.projectUsage.map { value in
        var value = value
        value.origin = origin
        return value
    }
    return MenuFixtureInventory(inventory: inventory, origin: origin)
}

private let menuFixtureInventoryJSON = #"""
{
  "coordinator_home": "/fixtures/coordinator",
  "state_path": "/fixtures/coordinator/state.json",
  "project": "/fixtures/projects/sample-console",
  "urls": [
    {"name": "web", "project": "/fixtures/projects/sample-console", "url": "http://127.0.0.1:4310", "health_url": "http://127.0.0.1:4310/health", "status": "running"}
  ],
  "servers": [
    {
      "id": "fixture-server-web",
      "name": "web",
      "agent": "fixture-agent",
      "project": "/fixtures/projects/sample-console",
      "cwd": "/fixtures/projects/sample-console",
      "cmd": "npm run dev -- --port 4310",
      "port": 4310,
      "url": "http://127.0.0.1:4310",
      "health_url": "http://127.0.0.1:4310/health",
      "log_path": "/fixtures/logs/sample-console-web.log",
      "status": "running",
      "health": {"ok": true, "pid_alive": true},
      "updated_at": "2026-01-01T00:00:00Z",
      "created_at": "2026-01-01T00:00:00Z",
      "url_is_current": true
    }
  ],
  "leases": [],
  "recent_events": [],
  "docker": {
    "available": true,
    "error": null,
    "stats_error": null,
    "containers": [
      {
        "id": "fixture-container-web",
        "name": "sample-console-web",
        "image": "sample/web:fixture",
        "status": "Up 5 minutes (healthy)",
        "ports": "127.0.0.1:4310->4310/tcp",
        "project": "/fixtures/projects/sample-console",
        "agent": "fixture-agent",
        "role": "web",
        "metadata_source": "fixture",
        "adopted": false
      }
    ],
    "postgres": [
      {
        "id": "fixture-container-postgres",
        "name": "sample-console-postgres",
        "image": "postgres:16",
        "status": "Up 5 minutes (healthy)",
        "ports": "127.0.0.1:5543->5432/tcp",
        "project": "/fixtures/projects/sample-console",
        "agent": "fixture-agent",
        "role": "database",
        "metadata_source": "fixture",
        "adopted": false
      }
    ]
  },
  "postgres": [
    {
      "id": "fixture-container-postgres",
      "name": "sample-console-postgres",
      "image": "postgres:16",
      "status": "Up 5 minutes (healthy)",
      "ports": "127.0.0.1:5543->5432/tcp",
      "project": "/fixtures/projects/sample-console",
      "agent": "fixture-agent",
      "role": "database",
      "metadata_source": "fixture",
      "adopted": false
    }
  ],
  "backups": [],
  "project_usage": [
    {"project": "/fixtures/projects/sample-console", "project_key": "sample-console", "name": "sample-console", "server_count": 1, "container_count": 2, "process_count": 12, "cpu_percent": 3.1, "memory_bytes": 100663296}
  ]
}
"""#

private func writeMenuSnapshotArtifact(_ png: Data, to outputURL: URL, width: Int, height: Int) throws {
    let cleanPNG = try menuPNGRemovingSensitiveMetadata(png)
    try FileManager.default.createDirectory(
        at: outputURL.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    try cleanPNG.write(to: outputURL, options: .atomic)

    let digest = SHA256.hash(data: cleanPNG).map { String(format: "%02x", $0) }.joined()
    let sourceRoot = try SnapshotSourceProvenance.projectRoot()
    let sourceFiles = SnapshotSourceProvenance.menuSourceFiles.sorted()
    let provenance: [String: Any] = [
        "schema_version": 1,
        "artifact_type": "test-fixture-snapshot",
        "source": "isolated-test-fixture",
        "fixture_id": "codex-ops-menu-neutral-v1",
        "generator": "apps/CodexOpsConsole/Tools/MenuBarSnapshotMain.swift",
        "width": width,
        "height": height,
        "sha256": digest,
        "source_files": sourceFiles,
        "source_sha256": try SnapshotSourceProvenance.fingerprint(
            sourceRoot: sourceRoot,
            relativePaths: sourceFiles
        ),
    ]
    var encoded = try JSONSerialization.data(withJSONObject: provenance, options: [.prettyPrinted, .sortedKeys])
    encoded.append(0x0A)
    try encoded.write(
        to: URL(fileURLWithPath: outputURL.path + ".provenance.json"),
        options: .atomic
    )
}

private func menuPNGRemovingSensitiveMetadata(_ data: Data) throws -> Data {
    let bytes = [UInt8](data)
    let signature: [UInt8] = [137, 80, 78, 71, 13, 10, 26, 10]
    guard bytes.count >= signature.count, Array(bytes.prefix(signature.count)) == signature else {
        throw MenuBarSnapshotError.invalidPNG
    }
    var output = signature
    var offset = signature.count
    var sawEnd = false
    let sensitiveChunkTypes: Set<String> = ["tEXt", "zTXt", "iTXt", "eXIf", "tIME"]

    while offset < bytes.count {
        guard offset + 12 <= bytes.count else { throw MenuBarSnapshotError.invalidPNG }
        let length = Int(
            UInt32(bytes[offset]) << 24
                | UInt32(bytes[offset + 1]) << 16
                | UInt32(bytes[offset + 2]) << 8
                | UInt32(bytes[offset + 3])
        )
        let end = offset + 12 + length
        guard end <= bytes.count,
              let type = String(bytes: bytes[(offset + 4)..<(offset + 8)], encoding: .ascii)
        else {
            throw MenuBarSnapshotError.invalidPNG
        }
        if !sensitiveChunkTypes.contains(type) {
            output.append(contentsOf: bytes[offset..<end])
        }
        offset = end
        if type == "IEND" {
            sawEnd = true
            break
        }
    }
    guard sawEnd, offset == bytes.count else { throw MenuBarSnapshotError.invalidPNG }
    return Data(output)
}

enum MenuBarSnapshotError: Error {
    case fixtureCopyDoesNotFit
    case invalidPNG
    case renderFailed
}

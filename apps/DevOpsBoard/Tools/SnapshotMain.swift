import AppKit
import CryptoKit
import Foundation
import SwiftUI

#if SWIFT_PACKAGE
@testable import DevOpsBoard
#endif

#if !SWIFT_PACKAGE
@main
#endif
struct SnapshotMain {
    @MainActor
    static func main() async throws {
        try render(arguments: Array(CommandLine.arguments.dropFirst()))
    }

    @MainActor
    static func render(arguments: [String]) throws {
        let output = arguments.first ?? ".build/qa/snapshots/dev-servers.png"
        let tab = arguments.dropFirst().first
        let width = CGFloat(Double(arguments.dropFirst(2).first ?? "1440") ?? 1440)
        let height = CGFloat(Double(arguments.dropFirst(3).first ?? "1024") ?? 1024)
        let store = OpsStore()
        let fixture = try fixtureInventory()
        store.inventory = fixture.inventory
        guard store.repositoryCatalog.repositories.count == 1,
              store.projectGroups.count == 1,
              store.projectGroups.first?.isRepository == true,
              store.projectGroups.first?.projectPath == fixture.repositoryPath
        else {
            throw SnapshotError.invalidRepositoryFixture
        }
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
        guard store.resourceAttentionItems.isEmpty,
              store.presentationSnapshot.level == .nominal
        else {
            throw SnapshotError.invalidAttentionFixture
        }
        if let identity = store.inventory.postgres.first?.databaseIdentity {
            store.backupRecords = [
                BackupRecord(
                    identity: identity,
                    path: "/fixtures/backups/sample-console-appdb.dump",
                    createdAt: Date(timeIntervalSince1970: 1_767_225_600),
                    checksum: .verified,
                    restoreTest: .passed,
                    format: "custom",
                    scope: "database"
                )
            ]
        }
        switch tab?.lowercased() {
        case "docker":
            store.activeTab = .docker
            if let container = store.visibleDockerContainers.first {
                store.selectDocker(container)
            }
        case "databases":
            store.activeTab = .databases
            if let database = store.visiblePostgres.first {
                store.selectDatabase(database)
            }
        default:
            store.activeTab = .servers
            let lease = LeaseActionResult(
                origin: fixture.origin,
                payload: LeaseCommandPayload(
                    id: "fixture-lease-4310",
                    port: 4310,
                    agent: "fixture-agent",
                    project: fixture.repositoryPath,
                    purpose: "manual",
                    status: "active",
                    expiresAtISO: "2099-01-01T01:00:00Z",
                    serverID: nil,
                    pendingOperationID: nil
                )
            )
            store.latestLeaseResult = lease
            store.leaseResults[lease.identity] = lease
            if let server = store.filteredServers.first {
                store.selectServer(server)
            }
        }

        let layout = consoleLayout(totalWidth: width, sidebarPreference: defaultSidebarWidth, inspectorPreference: 320)
        let mainX = layout.sidebarWidth + splitHandleWidth
        let inspectorSplitX = mainX + layout.mainWidth
        let view = ZStack(alignment: .topLeading) {
            ServiceMapView(store: store)
                .frame(width: layout.sidebarWidth, height: height)
                .position(x: layout.sidebarWidth / 2, y: height / 2)
                .zIndex(1)
            if layout.showsMain {
                SplitGripPreview()
                    .frame(width: splitHandleWidth, height: height)
                    .position(x: layout.sidebarWidth + (splitHandleWidth / 2), y: height / 2)
                    .zIndex(5)
                MainBoardView(store: store)
                    .frame(width: layout.mainWidth, height: height, alignment: .topLeading)
                    .clipped()
                    .position(x: mainX + (layout.mainWidth / 2), y: height / 2)
                    .zIndex(0)
            }
            if layout.showsInspector {
                SplitGripPreview()
                    .frame(width: splitHandleWidth, height: height)
                    .position(x: inspectorSplitX + (splitHandleWidth / 2), y: height / 2)
                    .zIndex(5)
                DetailsRailView(store: store)
                    .frame(width: layout.inspectorWidth, height: height)
                    .position(x: inspectorSplitX + splitHandleWidth + (layout.inspectorWidth / 2), y: height / 2)
                    .zIndex(2)
            }
        }
        .frame(width: width, height: height)
        .background(Theme.background)
        .foregroundStyle(Theme.primary)
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
            throw SnapshotError.renderFailed
        }
        bitmap.size = hostingView.bounds.size
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try opaquePNGRepresentation(from: bitmap, size: hostingView.bounds.size)

        try writeSnapshotArtifact(
            png,
            to: URL(fileURLWithPath: output),
            width: Int(width),
            height: Int(height),
            fixtureID: "devops-board-neutral-v1",
            generator: "apps/DevOpsBoard/Tools/SnapshotMain.swift"
        )
    }
}

private func opaquePNGRepresentation(from bitmap: NSBitmapImageRep, size: NSSize) throws -> Data {
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
        throw SnapshotError.renderFailed
    }
    context.setFillColor(NSColor.black.cgColor)
    context.fill(CGRect(x: 0, y: 0, width: width, height: height))
    context.draw(sourceImage, in: CGRect(x: 0, y: 0, width: width, height: height))
    guard let flattened = context.makeImage(),
          let png = NSBitmapImageRep(cgImage: flattened).representation(using: .png, properties: [:])
    else {
        throw SnapshotError.renderFailed
    }
    return png
}

private struct FixtureInventory {
    var inventory: Inventory
    var origin: CoordinatorOrigin
    var repositoryPath: String

    var resourceCount: Int {
        inventory.servers.count + inventory.leases.count + inventory.docker.containers.count + inventory.postgres.count
    }
}

private func fixtureInventory() throws -> FixtureInventory {
    let repositoryPath = try SnapshotSourceProvenance.fixtureRepository(named: "sample-console").path
    let fixtureJSON = fixtureInventoryJSON.replacingOccurrences(
        of: "/fixtures/projects/sample-console",
        with: repositoryPath
    )
    let data = Data(fixtureJSON.utf8)
    var inventory = try JSONDecoder().decode(Inventory.self, from: data)
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
    inventory.leases = inventory.leases.map { value in
        var value = value
        value.origin = origin
        value.coordinatorID = value.id
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
        value.databaseSizeBytes = 48_234_496
        value.startedAt = "2026-01-01T00:00:00Z"
        return value
    }
    inventory.backups = inventory.backups.map { value in
        var value = value
        value.origin = origin
        return value
    }
    inventory.projectUsage = inventory.projectUsage.map { value in
        var value = value
        value.origin = origin
        return value
    }
    return FixtureInventory(
        inventory: inventory,
        origin: origin,
        repositoryPath: repositoryPath
    )
}

private let fixtureInventoryJSON = #"""
{
  "coordinator_home": "/fixtures/coordinator",
  "state_path": "/fixtures/coordinator/state.json",
  "project": "/fixtures/projects/sample-console",
  "urls": [
    {
      "name": "web",
      "project": "/fixtures/projects/sample-console",
      "url": "http://127.0.0.1:4310",
      "health_url": "http://127.0.0.1:4310/health",
      "status": "running"
    }
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
      "host": "127.0.0.1",
      "url": "http://127.0.0.1:4310",
      "health_url": "http://127.0.0.1:4310/health",
      "lease_id": "fixture-lease-4310",
      "pid": 4101,
      "log_path": "/fixtures/logs/sample-console-web.log",
      "status": "running",
      "health": {"ok": true, "pid_alive": true},
      "updated_at": "2026-01-01T00:00:00Z",
      "created_at": "2026-01-01T00:00:00Z",
      "url_is_current": true,
      "process_usage": {
        "source": "fixture",
        "pid": 4101,
        "process_count": 2,
        "cpu_percent": 2.4,
        "rss_bytes": 67108864,
        "sampled_at": "2026-01-01T00:00:00Z"
      }
    },
    {
      "id": "fixture-server-worker",
      "name": "worker",
      "agent": "fixture-agent",
      "project": "/fixtures/projects/sample-console",
      "cwd": "/fixtures/projects/sample-console",
      "cmd": "npm run worker",
      "log_path": "/fixtures/logs/sample-console-worker.log",
      "status": "stopped",
      "health": {"ok": false, "pid_alive": false},
      "stopped_at": "2026-01-01T00:00:00Z",
      "stopped_reason": "fixture-maintenance",
      "updated_at": "2026-01-01T00:00:00Z",
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "leases": [
    {
      "id": "fixture-lease-4310",
      "port": 4310,
      "agent": "fixture-agent",
      "project": "/fixtures/projects/sample-console",
      "purpose": "web",
      "status": "active",
      "expires_at_iso": "2026-01-01T01:00:00Z"
    }
  ],
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
        "adopted": false,
        "stats": {
          "id": "fixture-container-web",
          "container_id": "fixture-container-web",
          "name": "sample-console-web",
          "timestamp": "2026-01-01T00:00:00Z",
          "timestamp_ts": 1767225600,
          "live": true,
          "cpu_percent": 1.8,
          "memory_percent": 3.2,
          "memory_usage_bytes": 50331648,
          "memory_limit_bytes": 1073741824,
          "network_rx_bytes": 4096,
          "network_tx_bytes": 8192,
          "block_read_bytes": 2048,
          "block_write_bytes": 1024,
          "pids": 4
        },
        "stats_history": [
          {"container_id": "fixture-container-web", "timestamp_ts": 1767225540, "cpu_percent": 1.2, "memory_percent": 3.0, "network_rx_rate_bytes_per_second": 80, "network_tx_rate_bytes_per_second": 120, "block_read_rate_bytes_per_second": 20, "block_write_rate_bytes_per_second": 12},
          {"container_id": "fixture-container-web", "timestamp_ts": 1767225600, "cpu_percent": 1.8, "memory_percent": 3.2, "network_rx_rate_bytes_per_second": 96, "network_tx_rate_bytes_per_second": 140, "block_read_rate_bytes_per_second": 24, "block_write_rate_bytes_per_second": 16}
        ]
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
      "adopted": false,
      "stats": {
        "id": "fixture-container-postgres",
        "container_id": "fixture-container-postgres",
        "name": "sample-console-postgres",
        "timestamp": "2026-01-01T00:00:00Z",
        "timestamp_ts": 1767225600,
        "live": true,
        "cpu_percent": 0.8,
        "memory_percent": 2.1,
        "memory_usage_bytes": 33554432,
        "memory_limit_bytes": 1073741824,
        "network_rx_bytes": 1024,
        "network_tx_bytes": 2048,
        "block_read_bytes": 8192,
        "block_write_bytes": 4096,
        "pids": 7
      }
    }
  ],
  "backups": [
    {
      "path": "/fixtures/backups/sample-console-appdb.dump",
      "size": 24576,
      "modified_at": "2026-01-01T00:00:00Z",
      "manifest": "/fixtures/backups/sample-console-appdb.dump.manifest.json",
      "database": "appdb",
      "container": "sample-console-postgres",
      "format": "custom",
      "sha256": "fixture-sha256"
    }
  ],
  "project_usage": [
    {
      "project": "/fixtures/projects/sample-console",
      "project_key": "sample-console",
      "name": "sample-console",
      "server_count": 2,
      "container_count": 2,
      "process_count": 13,
      "cpu_percent": 5.0,
      "memory_bytes": 150994944,
      "process_cpu_percent": 2.4,
      "process_memory_bytes": 67108864,
      "docker_cpu_percent": 2.6,
      "docker_memory_bytes": 83886080
    }
  ]
}
"""#

private func writeSnapshotArtifact(
    _ png: Data,
    to outputURL: URL,
    width: Int,
    height: Int,
    fixtureID: String,
    generator: String
) throws {
    let cleanPNG = try pngRemovingSensitiveMetadata(png)
    try FileManager.default.createDirectory(
        at: outputURL.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    try cleanPNG.write(to: outputURL, options: .atomic)

    let digest = SHA256.hash(data: cleanPNG).map { String(format: "%02x", $0) }.joined()
    let sourceRoot = try SnapshotSourceProvenance.projectRoot()
    let sourceFiles = SnapshotSourceProvenance.boardSourceFiles.sorted()
    let provenance: [String: Any] = [
        "schema_version": 1,
        "artifact_type": "test-fixture-snapshot",
        "source": "isolated-test-fixture",
        "fixture_id": fixtureID,
        "generator": generator,
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

private func pngRemovingSensitiveMetadata(_ data: Data) throws -> Data {
    let bytes = [UInt8](data)
    let signature: [UInt8] = [137, 80, 78, 71, 13, 10, 26, 10]
    guard bytes.count >= signature.count, Array(bytes.prefix(signature.count)) == signature else {
        throw SnapshotError.invalidPNG
    }
    var output = signature
    var offset = signature.count
    var sawEnd = false
    let sensitiveChunkTypes: Set<String> = ["tEXt", "zTXt", "iTXt", "eXIf", "tIME"]

    while offset < bytes.count {
        guard offset + 12 <= bytes.count else { throw SnapshotError.invalidPNG }
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
            throw SnapshotError.invalidPNG
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
    guard sawEnd, offset == bytes.count else { throw SnapshotError.invalidPNG }
    return Data(output)
}

enum SnapshotError: Error {
    case invalidAttentionFixture
    case invalidPNG
    case invalidRepositoryFixture
    case renderFailed
}

struct SplitGripPreview: View {
    var body: some View {
        ZStack {
            Rectangle().fill(Color.white.opacity(0.035))
            Rectangle().fill(Color.white.opacity(0.16)).frame(width: 1)
        }
        .frame(width: splitHandleWidth)
    }
}

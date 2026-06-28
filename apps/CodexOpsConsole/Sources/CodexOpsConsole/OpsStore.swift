import AppKit
import Foundation
import SwiftUI

@MainActor
final class OpsStore: ObservableObject {
    @Published var inventory: Inventory = .empty
    @Published var selectedServerID: ManagedServer.ID?
    @Published var selectedDockerID: String?
    @Published var selectedDatabaseID: String?
    @Published var selectedProjectName: String?
    @Published var sidebarSelection: SidebarSelection?
    @Published var activeTab: ResourceTab = .servers
    @Published var searchText = ""
    @Published var filter: ServiceFilter = .all
    @Published var isLoading = false
    @Published var lastError: String?
    @Published var lastErrorDetails: String?
    @Published var lastErrorTitle: String?
    @Published var projectPath: String
    @Published var startDraft = StartServerDraft()
    @Published var showingStartSheet = false
    @Published var showingLeaseSheet = false
    @Published var showingServerLogs = false
    @Published var serverLogTitle = "Server Logs"
    @Published var serverLogText = ""
    @Published var serverLogMetadata = ""
    @Published var leaseRange = "3000-3999"
    @Published var projectRuntimeReports: [String: ProjectRuntimeReport] = [:]

    private let coordinatorScript: String
    private let backupScript: String
    private var lastErrorSource: String?

    init() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        coordinatorScript = "\(home)/.codex/skills/codex-dev-coordinator/scripts/dev_coordinator.py"
        backupScript = "\(home)/.codex/skills/postgres-docker-backup/scripts/postgres_docker_backup.py"
        projectPath = ""
    }

    var selectedServer: ManagedServer? {
        guard let selectedServerID else { return nil }
        return inventory.servers.first { $0.id == selectedServerID }
    }

    var selectedDocker: DockerContainer? {
        guard let selectedDockerID else { return nil }
        return inventory.docker.containers.first { $0.stableID == selectedDockerID }
    }

    var selectedDatabase: DockerContainer? {
        guard let selectedDatabaseID else { return nil }
        return inventory.postgres.first { $0.stableID == selectedDatabaseID }
    }

    var filteredServers: [ManagedServer] {
        inventory.servers.filter { server in
            let status = (server.status ?? "").lowercased()
            let matchesFilter: Bool
            switch filter {
            case .all:
                matchesFilter = true
            case .running:
                matchesFilter = status == "running"
            case .unhealthy:
                matchesFilter = status == "unhealthy" || status == "degraded" || server.health?.ok == false
            case .stopped:
                matchesFilter = status == "stopped"
            }

            guard matchesFilter else { return false }
            let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !query.isEmpty else { return true }
            return [server.name, server.project, server.url, server.agent, server.logPath]
                .compactMap { $0?.lowercased() }
                .contains { $0.contains(query) }
        }
    }

    var visibleDockerContainers: [DockerContainer] {
        filterDocker(inventory.docker.containers)
    }

    var visiblePostgres: [DockerContainer] {
        filterDocker(inventory.postgres)
    }

    var connected: Bool {
        inventory.coordinatorHome != nil || !inventory.servers.isEmpty || !inventory.leases.isEmpty
    }

    var scopedProjectPath: String? {
        let trimmed = projectPath.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    var actionProjectPath: String {
        scopedProjectPath ?? FileManager.default.currentDirectoryPath
    }

    private var agentID: String {
        NSUserName()
    }

    func refresh() {
        Task { await loadInventory() }
    }

    func loadInventory() async {
        isLoading = true
        defer { isLoading = false }
        do {
            var arguments = ["inventory"]
            if let scopedProjectPath {
                arguments.append(contentsOf: ["--project", scopedProjectPath])
            }
            let result = try await runPython(script: coordinatorScript, arguments: arguments)
            try ensureSuccess(result)
            let data = Data(result.output.utf8)
            let decoded = try JSONDecoder().decode(Inventory.self, from: data)
            inventory = decoded
            keepSelectionValid()
            if lastErrorSource == "inventory" {
                clearLastError()
            }
        } catch {
            setLastError(
                title: "Inventory refresh failed",
                summary: error.localizedDescription,
                details: error.localizedDescription,
                source: "inventory"
            )
        }
    }

    func openURL(_ url: String?) {
        guard let raw = url, let url = URL(string: raw) else { return }
        NSWorkspace.shared.open(url)
    }

    func copyURL(_ url: String?) {
        guard let url else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(url, forType: .string)
    }

    func copyLastErrorDetails() {
        let detail = lastErrorDetails ?? lastError ?? ""
        guard !detail.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(detail, forType: .string)
    }

    func clearLastError() {
        lastError = nil
        lastErrorDetails = nil
        lastErrorTitle = nil
        lastErrorSource = nil
    }

    func selectProject(_ name: String) {
        selectedProjectName = name
        sidebarSelection = .project(name)
    }

    func statusProject(_ group: ProjectGroup) {
        runProjectRuntime("status", group: group)
    }

    func startProject(_ group: ProjectGroup) {
        runProjectRuntime("start", group: group)
    }

    func restartProject(_ group: ProjectGroup) {
        runProjectRuntime("restart", group: group)
    }

    func stopProject(_ group: ProjectGroup) {
        runProjectRuntime("stop", group: group)
    }

    func selectServer(_ server: ManagedServer) {
        activeTab = .servers
        selectedServerID = server.id
        sidebarSelection = .server(server.id)
    }

    func selectDocker(_ container: DockerContainer) {
        activeTab = .docker
        selectedDockerID = container.stableID
        sidebarSelection = .docker(container.stableID)
    }

    func selectDatabase(_ container: DockerContainer) {
        activeTab = .databases
        selectedDatabaseID = container.stableID
        sidebarSelection = .database(container.stableID)
    }

    func restart(_ server: ManagedServer) {
        let project = server.project ?? actionProjectPath
        runTracked(
            title: "Restart \(server.name)",
            subtitle: project,
            arguments: ["server", "restart", "--agent", agentID, "--project", project, "--name", server.name]
        )
    }

    func stop(_ server: ManagedServer) {
        let project = server.project ?? actionProjectPath
        runTracked(
            title: "Stop \(server.name)",
            subtitle: project,
            arguments: ["server", "stop", "--agent", agentID, "--project", project, "--name", server.name, "--reason", "Stopped from Codex Ops Console"]
        )
    }

    func toggle(_ server: ManagedServer) {
        if canStopServer(server) {
            stop(server)
        } else {
            restart(server)
        }
    }

    func startServer() {
        let project = startDraft.project.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? actionProjectPath : startDraft.project
        let cwd = startDraft.cwd.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? project : startDraft.cwd
        var args = [
            "server", "start",
            "--agent", startDraft.agent,
            "--project", project,
            "--name", startDraft.name,
            "--cwd", cwd,
            "--cmd", startDraft.command,
        ]
        let preferred = startDraft.preferredPort.trimmingCharacters(in: .whitespacesAndNewlines)
        if let preferredPort = Int(preferred) {
            args.append(contentsOf: ["--range", "\(preferredPort)-\(preferredPort)", "--preferred", "\(preferredPort)"])
        } else {
            args.append(contentsOf: ["--range", startDraft.range])
        }
        if !startDraft.healthURL.isEmpty {
            args.append(contentsOf: ["--health-url", startDraft.healthURL])
        }
        runTracked(title: "Start \(startDraft.name)", subtitle: project, arguments: args)
        showingStartSheet = false
    }

    func leasePort() {
        let args = [
            "port", "lease",
            "--agent", agentID,
            "--project", actionProjectPath,
            "--range", leaseRange,
            "--purpose", "manual"
        ]
        runTracked(title: "Lease port", subtitle: leaseRange, arguments: args)
        showingLeaseSheet = false
    }

    func backupDatabase(container: DockerContainer?) {
        var args = ["backup", "--out-dir", "\(actionProjectPath)/.codex-db-backups"]
        if let name = container?.name, !name.isEmpty {
            args.append(contentsOf: ["--container", name])
        }
        runTracked(title: "Backup database", subtitle: container?.name ?? "auto-detect Postgres", script: backupScript, arguments: args)
    }

    func prepareStartDraft() {
        let project = actionProjectPath
        startDraft.project = project
        startDraft.cwd = project
    }

    func dockerLogs(_ container: DockerContainer) {
        guard let name = container.name else { return }
        runTracked(title: "Docker logs", subtitle: name, arguments: ["docker", "logs", "--container", name, "--tail", "80"])
    }

    func restartDocker(_ container: DockerContainer) {
        guard let name = container.name else { return }
        let project = container.project ?? actionProjectPath
        runTracked(title: "Restart container", subtitle: name, arguments: ["docker", "restart", "--agent", agentID, "--project", project, "--container", name])
    }

    func toggleDocker(_ container: DockerContainer) {
        if container.isRunning {
            stopDocker(container)
        } else {
            startDocker(container)
        }
    }

    func startDocker(_ container: DockerContainer) {
        guard let name = container.name else { return }
        let project = container.project ?? actionProjectPath
        runTracked(title: "Start container", subtitle: name, arguments: ["docker", "start", "--agent", agentID, "--project", project, "--container", name])
    }

    func stopDocker(_ container: DockerContainer) {
        guard let name = container.name else { return }
        let project = container.project ?? actionProjectPath
        runTracked(title: "Stop container", subtitle: name, arguments: ["docker", "stop", "--agent", agentID, "--project", project, "--container", name])
    }

    func showServerLogs(_ server: ManagedServer) {
        let project = server.project ?? actionProjectPath
        serverLogTitle = "\(server.name) logs"
        serverLogMetadata = "Loading logs..."
        serverLogText = ""
        showingServerLogs = true
        Task {
            do {
                let result = try await runPython(
                    script: coordinatorScript,
                    arguments: ["server", "logs", "--server-id", server.id, "--project", project, "--name", server.name, "--tail", "300"]
                )
                try ensureSuccess(result)
                let payload = try JSONDecoder().decode(ServerLogPayload.self, from: Data(result.output.utf8))
                let reason = payload.server.stoppedReason ?? server.stoppedReason ?? "No stop reason recorded"
                let stoppedAt = payload.server.stoppedAt ?? server.stoppedAt ?? "Not stopped"
                let logPath = payload.server.logPath ?? server.logPath ?? "No log path"
                serverLogTitle = "\(payload.server.name ?? server.name) logs"
                serverLogMetadata = "Status: \(payload.server.status ?? server.status ?? "unknown") | Stopped: \(stoppedAt) | Reason: \(reason) | Log: \(logPath)"
                serverLogText = payload.text.isEmpty ? "No log output recorded yet." : payload.text
            } catch {
                serverLogMetadata = "Failed to load logs"
                serverLogText = error.localizedDescription
            }
        }
    }

    var hasStoppableResources: Bool {
        inventory.servers.contains(where: canStopServer)
            || inventory.docker.containers.contains(where: \.isRunning)
    }

    func stopAll() {
        let servers = inventory.servers.filter(canStopServer)
        let containers = inventory.docker.containers.filter(\.isRunning)
        let count = servers.count + containers.count
        guard count > 0 else {
            return
        }

        for server in servers {
            stop(server)
        }
        for container in containers {
            stopDocker(container)
        }
    }

    private func filterDocker(_ containers: [DockerContainer]) -> [DockerContainer] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return containers.filter { container in
            let matchesFilter: Bool
            switch filter {
            case .all:
                matchesFilter = true
            case .running:
                matchesFilter = isRunningStatus(container.status)
            case .unhealthy:
                let status = (container.status ?? "").lowercased()
                matchesFilter = status.contains("restart") || status.contains("unhealthy") || status.contains("dead")
            case .stopped:
                matchesFilter = isStoppedStatus(container.status)
            }
            guard matchesFilter else { return false }
            guard !query.isEmpty else { return true }
            return [container.name, container.image, container.status, container.ports]
                .compactMap { $0?.lowercased() }
                .contains { $0.contains(query) }
        }
    }

    private func hasBackup(for container: DockerContainer) -> Bool {
        inventory.backups.contains { backup in
            backup.container == container.name || backup.database == container.name
        }
    }

    private func keepSelectionValid() {
        if let selectedServerID, !inventory.servers.contains(where: { $0.id == selectedServerID }) {
            self.selectedServerID = nil
        }
        if let selectedDockerID, !inventory.docker.containers.contains(where: { $0.stableID == selectedDockerID }) {
            self.selectedDockerID = nil
        }
        if let selectedDatabaseID, !inventory.postgres.contains(where: { $0.stableID == selectedDatabaseID }) {
            self.selectedDatabaseID = nil
        }
        if selectedServerID == nil, selectedDockerID == nil, selectedDatabaseID == nil {
            selectedServerID = inventory.servers.first?.id
            if let selectedServerID {
                sidebarSelection = .server(selectedServerID)
                activeTab = .servers
            }
        }
    }

    private func runTracked(title: String, subtitle: String, script: String? = nil, arguments: [String]) {
        Task {
            do {
                let result = try await runPython(script: script ?? coordinatorScript, arguments: arguments)
                if result.status == 0 {
                    clearLastError()
                    await loadInventory()
                } else {
                    setCommandFailure(title: title, script: script ?? coordinatorScript, arguments: arguments, result: result)
                }
            } catch {
                setLastError(
                    title: "\(title) failed",
                    summary: error.localizedDescription,
                    details: commandFailureDetails(
                        title: title,
                        script: script ?? coordinatorScript,
                        arguments: arguments,
                        result: nil,
                        thrownError: error
                    ),
                    source: "action"
                )
            }
        }
    }

    private func runProjectRuntime(_ action: String, group: ProjectGroup) {
        guard let projectPath = group.projectPath else {
            lastError = "Project runtime failed: no canonical project path is known for \(group.name)"
            return
        }
        Task {
            do {
                var args = ["project", action, "--project", projectPath]
                if action == "start" || action == "restart" || action == "stop" {
                    args.append(contentsOf: ["--agent", agentID])
                }
                let result = try await runPython(script: coordinatorScript, arguments: args)
                try ensureSuccess(result)
                let report = try JSONDecoder().decode(ProjectRuntimeReport.self, from: Data(result.output.utf8))
                projectRuntimeReports[group.id] = report
                if report.ok == true {
                    clearLastError()
                } else {
                    let reason = report.classification ?? report.classifications?.joined(separator: ", ") ?? "runtime not ready"
                    setLastError(
                        title: "Project runtime \(action) failed",
                        summary: "\(group.name): \(reason)",
                        details: projectRuntimeFailureDetails(action: action, group: group, report: report),
                        source: "action"
                    )
                }
                await loadInventory()
            } catch {
                setLastError(
                    title: "Project runtime \(action) failed",
                    summary: "\(group.name): \(error.localizedDescription)",
                    details: commandFailureDetails(
                        title: "Project runtime \(action) for \(group.name)",
                        script: coordinatorScript,
                        arguments: ["project", action, "--project", projectPath] + ((action == "start" || action == "restart" || action == "stop") ? ["--agent", agentID] : []),
                        result: nil,
                        thrownError: error
                    ),
                    source: "action"
                )
            }
        }
    }

    private func ensureSuccess(_ result: CommandResult) throws {
        guard result.status == 0 else {
            throw RuntimeError(result.error.isEmpty ? result.output : result.error)
        }
    }

    private func setCommandFailure(title: String, script: String, arguments: [String], result: CommandResult) {
        let message = commandFailureMessage(result)
        setLastError(
            title: "\(title) failed",
            summary: message,
            details: commandFailureDetails(title: title, script: script, arguments: arguments, result: result, thrownError: nil),
            source: "action"
        )
    }

    private func setLastError(title: String, summary: String, details: String, source: String) {
        lastErrorTitle = title
        lastError = summary.trimmingCharacters(in: .whitespacesAndNewlines)
        lastErrorDetails = details.trimmingCharacters(in: .whitespacesAndNewlines)
        lastErrorSource = source
    }

    private func commandFailureMessage(_ result: CommandResult) -> String {
        let raw = result.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? result.output : result.error
        if let data = raw.data(using: .utf8),
           let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = object["error"] as? String,
           !error.isEmpty {
            return error
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "Exited with status \(result.status)" : trimmed
    }

    private func commandFailureDetails(
        title: String,
        script: String,
        arguments: [String],
        result: CommandResult?,
        thrownError: Error?
    ) -> String {
        var lines = [
            title,
            "Command: \(shellCommand(["python3", script] + arguments))"
        ]
        if let result {
            lines.append("Exit status: \(result.status)")
            if !result.error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                lines.append("stderr:\n\(result.error.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
            if !result.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                lines.append("stdout:\n\(result.output.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
        }
        if let thrownError {
            lines.append("Error: \(thrownError.localizedDescription)")
        }
        return lines.joined(separator: "\n\n")
    }

    private func projectRuntimeFailureDetails(action: String, group: ProjectGroup, report: ProjectRuntimeReport) -> String {
        var lines = [
            "Project runtime \(action) for \(group.name)",
            "Project: \(report.project ?? group.projectPath ?? "unknown")",
            "Classification: \(report.classification ?? report.classifications?.joined(separator: ", ") ?? "not ready")"
        ]
        let failedServices = report.services.filter { $0.ok == false || $0.classification != nil }
        if !failedServices.isEmpty {
            lines.append("Failed services:")
            for service in failedServices {
                lines.append("- \(service.name ?? service.container ?? service.type ?? "service"): \(service.classification ?? service.status ?? "failed")")
                if let reason = service.previousExitReason, !reason.isEmpty {
                    lines.append("  previous exit: \(reason)")
                }
                if let logs = service.recentLogs, !logs.isEmpty {
                    lines.append("  recent logs:\n\(logs)")
                }
            }
        }
        if let errors = report.actionErrors, !errors.isEmpty {
            lines.append("Action errors:")
            for error in errors {
                lines.append("- \(error.name ?? "action"): \(error.error ?? error.classification ?? "failed")")
            }
        }
        return lines.joined(separator: "\n")
    }
}

func shellCommand(_ parts: [String]) -> String {
    parts.map(shellQuote).joined(separator: " ")
}

func shellQuote(_ value: String) -> String {
    if value.range(of: #"^[A-Za-z0-9_@%+=:,./-]+$"#, options: .regularExpression) != nil {
        return value
    }
    return "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
}

struct StartServerDraft {
    var agent = NSUserName()
    var project = FileManager.default.currentDirectoryPath
    var name = "web"
    var cwd = FileManager.default.currentDirectoryPath
    var command = "npm run dev -- --host 127.0.0.1 --port {port}"
    var range = "3000-3999"
    var preferredPort = ""
    var healthURL = "http://127.0.0.1:{port}/"
}

struct RuntimeError: LocalizedError {
    var message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

func runPython(script: String, arguments: [String]) async throws -> CommandResult {
    try await Task.detached(priority: .userInitiated) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", script] + arguments

        let temporaryDirectory = FileManager.default.temporaryDirectory
        let outputURL = temporaryDirectory.appendingPathComponent("codex-ops-\(UUID().uuidString).out")
        let errorURL = temporaryDirectory.appendingPathComponent("codex-ops-\(UUID().uuidString).err")
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        FileManager.default.createFile(atPath: errorURL.path, contents: nil)
        let outputHandle = try FileHandle(forWritingTo: outputURL)
        let errorHandle = try FileHandle(forWritingTo: errorURL)
        defer {
            try? outputHandle.close()
            try? errorHandle.close()
            try? FileManager.default.removeItem(at: outputURL)
            try? FileManager.default.removeItem(at: errorURL)
        }
        process.standardOutput = outputHandle
        process.standardError = errorHandle

        try process.run()
        process.waitUntilExit()

        let output = String(data: (try? Data(contentsOf: outputURL)) ?? Data(), encoding: .utf8) ?? ""
        let error = String(data: (try? Data(contentsOf: errorURL)) ?? Data(), encoding: .utf8) ?? ""
        return CommandResult(output: output, error: error, status: process.terminationStatus)
    }.value
}

import AppKit
import Foundation
import SwiftUI

enum BoardIncidentStatus: Equatable {
    case queued
    case running
    case succeeded
    case failed
    case timedOut
    case cancelled
    case warning

    init(phase: ActionPhase) {
        switch phase {
        case .queued: self = .queued
        case .running: self = .running
        case .succeeded: self = .succeeded
        case .failed: self = .failed
        case .timedOut: self = .timedOut
        case .cancelled: self = .cancelled
        }
    }

    var label: String {
        switch self {
        case .queued: return "Queued"
        case .running: return "Running"
        case .succeeded: return "Succeeded"
        case .failed: return "Failed"
        case .timedOut: return "Timed out"
        case .cancelled: return "Cancelled"
        case .warning: return "Warning"
        }
    }

    var icon: String {
        switch self {
        case .queued: return "clock.fill"
        case .running: return "arrow.triangle.2.circlepath"
        case .succeeded: return "checkmark.circle.fill"
        case .failed: return "exclamationmark.circle.fill"
        case .timedOut: return "clock.badge.exclamationmark.fill"
        case .cancelled: return "xmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        }
    }

    var tint: Color {
        switch self {
        case .queued, .running: return Theme.blue
        case .succeeded: return Theme.green
        case .failed, .timedOut, .cancelled: return Theme.red
        case .warning: return Theme.orange
        }
    }
}

struct BoardWorkspaceTabs: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        HStack(spacing: 22) {
            workspaceButton("Resources", workspace: .resources)
            workspaceButton("Activity", workspace: .activity)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .frame(height: 40)
        .background(Theme.toolbar)
        .overlay(alignment: .bottom) {
            Rectangle().fill(Color.white.opacity(0.07)).frame(height: 1)
        }
        .accessibilityIdentifier("board-workspace-tabs")
    }

    private func workspaceButton(_ title: String, workspace: BoardWorkspace) -> some View {
        Button {
            if workspace == .resources {
                store.showResources()
            } else {
                store.showActivity()
            }
        } label: {
            Text(title)
                .font(.system(size: 13, weight: store.boardWorkspace == workspace ? .semibold : .regular))
                .foregroundStyle(store.boardWorkspace == workspace ? Theme.primary : Theme.secondary)
                .padding(.horizontal, 4)
                .frame(height: 40)
                .overlay(alignment: .bottom) {
                    Rectangle()
                        .fill(store.boardWorkspace == workspace ? Theme.blue : Color.clear)
                        .frame(height: 2)
                }
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(workspace == .resources
            ? "board-workspace-resources"
            : "board-workspace-activity")
        .accessibilityAddTraits(store.boardWorkspace == workspace ? .isSelected : [])
    }
}

struct WorkspaceAttentionHeader: View {
    @ObservedObject var store: OpsStore
    @State private var showingDetails = false

    private var snapshot: OpsPresentationSnapshot { store.presentationSnapshot }

    private var relatedResult: RetainedActionResult? {
        if store.boardWorkspace == .activity {
            return store.selectedActivityActionResult
        }
        guard let actionID = snapshot.actionIssue?.relatedActionID else { return nil }
        return store.actionResults[actionID]
    }

    private var contextualIssue: OpsIssue? {
        if store.boardWorkspace == .activity {
            return store.selectedActivityActionIssue
        }
        return snapshot.actionIssue ?? snapshot.inventoryIssue
    }

    private var selectedRecovery: ResourceRetirementRecoveryContext? {
        guard store.boardWorkspace == .activity else { return nil }
        return store.selectedRetirementRecoveryContext
    }

    private var isInitialLoading: Bool { store.isInitialInventoryLoading }

    private var shouldShow: Bool {
        if store.boardWorkspace == .activity {
            return isInitialLoading || contextualIssue != nil || relatedResult != nil
        }
        return isInitialLoading
            || snapshot.level != .nominal
            || !store.explicitlyUnavailableDockerCapabilities.isEmpty
            || selectedRecovery != nil
    }

    private var isFailedRetirement: Bool {
        let failedResult = relatedResult?.request.kind == .retireStandaloneResource
            && relatedResult?.phase != .succeeded
            && relatedResult?.phase != .queued
            && relatedResult?.phase != .running
        if store.boardWorkspace == .activity { return failedResult }
        return failedResult
            || snapshot.actionIssue?.title.localizedCaseInsensitiveContains("retire") == true
            || snapshot.actionIssue?.summary.localizedCaseInsensitiveContains("fingerprint changed") == true
    }

    private var retirementRecoveryTitle: String? {
        guard isFailedRetirement else { return nil }
        return store.selectedRetirementRecoveryActionTitle
    }

    private var title: String {
        if isInitialLoading { return "Refreshing inventory" }
        if isFailedRetirement { return "Retirement failed" }
        if store.boardWorkspace == .activity {
            if let contextualIssue { return contextualIssue.title }
            if let relatedResult {
                return "\(relatedResult.request.title) \(relatedResult.phase.rawValue)"
            }
        }
        return snapshot.statusTitle
    }

    private var summary: String {
        if isInitialLoading {
            return store.sourceStates.isEmpty
                ? "Looking for configured coordinator sources."
                : snapshot.statusMessage
        }
        if isFailedRetirement,
           selectedRecovery?.recoveryAction == .retryConfirmedOperation
        {
            return "Partial retirement is fenced. Resume the exact confirmed plan; do not create a replacement."
        }
        if isFailedRetirement,
           selectedRecovery?.commandFailure?.isPreMutationStalePlan == true
        {
            return "Resource changed after the retirement plan was reviewed."
        }
        if store.boardWorkspace == .activity {
            if let contextualIssue { return contextualIssue.summary }
            if let failure = relatedResult?.failure, !failure.isEmpty { return failure }
        }
        let dockerUnavailable = store.explicitlyUnavailableDockerCapabilities
        if !dockerUnavailable.isEmpty, snapshot.actionIssue == nil {
            let sources = dockerUnavailable.map(\.origin.label).joined(separator: ", ")
            return "Docker is unavailable for \(sources). Server and port lease actions remain available."
        }
        return snapshot.statusMessage
    }

    private var tint: Color {
        if isInitialLoading { return Theme.blue }
        if isFailedRetirement { return Theme.red }
        if store.boardWorkspace == .activity, let relatedResult {
            return BoardIncidentStatus(phase: relatedResult.phase).tint
        }
        if store.boardWorkspace == .activity, let contextualIssue {
            return contextualIssue.kind == .action ? Theme.red : Theme.orange
        }
        return healthLevelColor(snapshot.level)
    }

    @ViewBuilder
    var body: some View {
        if shouldShow {
            ViewThatFits(in: .horizontal) {
                regularHeader
                compactHeader
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(tint.opacity(0.1))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(tint.opacity(0.3)))
            .popover(isPresented: $showingDetails, arrowEdge: .bottom) {
                issueDetails
            }
            .accessibilityIdentifier("workspace-attention-header")
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
        }
    }

    private var regularHeader: some View {
        HStack(alignment: .center, spacing: 11) {
            statusIcon
            headerCopy
            Spacer(minLength: 12)
            headerActions
        }
    }

    private var compactHeader: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .top, spacing: 10) {
                statusIcon
                headerCopy
            }
            headerActions
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
    }

    @ViewBuilder
    private var statusIcon: some View {
        if isInitialLoading {
            ProgressView().controlSize(.small)
        } else {
            Image(systemName: statusIconName)
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(tint)
                .frame(width: 18)
                .accessibilityHidden(true)
        }
    }

    private var statusIconName: String {
        if isFailedRetirement { return BoardIncidentStatus.failed.icon }
        if store.boardWorkspace == .activity, let relatedResult {
            return BoardIncidentStatus(phase: relatedResult.phase).icon
        }
        if store.boardWorkspace == .activity, let contextualIssue {
            return contextualIssue.kind == .action
                ? BoardIncidentStatus.failed.icon
                : BoardIncidentStatus.warning.icon
        }
        return inventoryBannerIcon(snapshot.level)
    }

    private var headerCopy: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.system(size: 15, weight: .bold))
                .lineLimit(1)
            Text(summary)
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var headerActions: some View {
        HStack(spacing: 8) {
            if store.boardWorkspace == .activity {
                if let retirementRecoveryTitle {
                    Button(retirementRecoveryTitle) {
                        store.recoverSelectedRetirement()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.blue)
                    .accessibilityIdentifier("activity-refresh-and-replan")
                } else if isFailedRetirement {
                    Button("Refresh") { store.refresh() }
                        .buttonStyle(.borderedProminent)
                        .disabled(store.isLoading)
                } else if contextualIssue.map({ $0.kind != .action }) == true {
                    Button("Refresh") { store.refresh() }
                        .buttonStyle(.borderedProminent)
                        .disabled(store.isLoading)
                }
                Button("Back to resources") { store.showResources() }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("activity-back-to-resources")
            } else if let issue = snapshot.actionIssue {
                Button("View incident") {
                    store.showActivity(issueID: issue.id)
                }
                .buttonStyle(.borderedProminent)
                .tint(Theme.blue)
                .accessibilityIdentifier("attention-view-incident")
            } else if snapshot.resourceAttentionItems.count == 1,
                      let item = snapshot.resourceAttentionItems.first
            {
                Button(item.reviewTarget.actionLabel) {
                    _ = store.reviewAttentionItem(item)
                }
                .buttonStyle(.bordered)
            } else if snapshot.resourceAttentionItems.count > 1 {
                Menu("Review (\(snapshot.resourceAttentionItems.count))") {
                    ForEach(snapshot.resourceAttentionItems) { item in
                        Button(item.title) { _ = store.reviewAttentionItem(item) }
                    }
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }

            if store.boardWorkspace == .resources,
               contextualIssue != nil || relatedResult != nil
            {
                Button("Details") { showingDetails.toggle() }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("attention-show-details")
            }
        }
        .controlSize(store.boardWorkspace == .activity ? .large : .small)
    }

    private var issueDetails: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 12) {
                Text(title)
                    .font(.system(size: 14, weight: .bold))
                if let issue = contextualIssue {
                    Text(issue.details)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Button("Copy details") { store.copyIssueDetails(issue) }
                        if issue.kind == .action {
                            Button("Dismiss") { store.dismissActionIssue() }
                        }
                    }
                    .buttonStyle(.bordered)
                } else if let result = relatedResult {
                    Text(store.actionResultDetails(result))
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Button("Copy details") { store.copyActionResultDetails(result) }
                        if isTerminalActionPhase(result.phase) {
                            Button("Dismiss") { store.dismissActionResult(result) }
                        }
                    }
                    .buttonStyle(.bordered)
                } else {
                    Text(summary)
                        .foregroundStyle(Theme.secondary)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(width: 430, height: 260)
        .background(Theme.sidebar)
    }
}

struct ResourcesWorkspaceView: View {
    @ObservedObject var store: OpsStore
    @Binding var bulkSelectionMode: Bool
    let reviewSelection: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            CompactProjectLoadBar(store: store)
            CompactLeaseBar(store: store)
            FilterRow(
                store: store,
                bulkSelectionMode: $bulkSelectionMode,
                reviewSelection: reviewSelection
            )
            ResourceTabBar(store: store)
            resourceContent
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .layoutPriority(1)
        }
        .padding(14)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .accessibilityIdentifier("resources-workspace")
    }

    @ViewBuilder
    private var resourceContent: some View {
        switch store.activeTab {
        case .servers:
            DevServersSection(store: store, bulkSelectionMode: bulkSelectionMode)
        case .docker:
            DockerSection(store: store, bulkSelectionMode: bulkSelectionMode)
        case .databases:
            DatabaseSection(store: store, bulkSelectionMode: bulkSelectionMode)
        case .tests:
            ScrollView(.vertical) {
                TestStatisticsSection(store: store)
            }
            .accessibilityIdentifier("resource-table-scroll")
        }
    }
}

private struct CompactProjectLoadEntry: Identifiable {
    let id: String
    let name: String
    let usage: ProjectUsage
}

private struct CompactProjectLoadBar: View {
    @ObservedObject var store: OpsStore

    private var entries: [CompactProjectLoadEntry] {
        Array(
            store.repositoryTrees
                .compactMap { tree -> CompactProjectLoadEntry? in
                    guard let usage = tree.usage,
                          (usage.serverCount ?? 0) > 0
                            || (usage.containerCount ?? 0) > 0
                            || (usage.cpuPercent ?? 0) > 0
                            || (usage.memoryBytes ?? 0) > 0
                    else { return nil }
                    return CompactProjectLoadEntry(
                        id: tree.familyID,
                        name: tree.root.displayName,
                        usage: usage
                    )
                }
                .sorted { usageRank($0.usage) > usageRank($1.usage) }
                .prefix(6)
        )
    }

    @ViewBuilder
    var body: some View {
        if !entries.isEmpty {
            HStack(spacing: 10) {
                Label("PROJECT LOAD", systemImage: "gauge.with.dots.needle.bottom.100percent")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(Theme.secondary)
                    .fixedSize()
                ScrollView(.horizontal) {
                    LazyHStack(spacing: 7) {
                        ForEach(entries) { entry in
                            CompactProjectLoadChip(entry: entry)
                        }
                    }
                }
                .scrollIndicators(.hidden)
            }
            .frame(height: 42)
            .accessibilityIdentifier("compact-project-load")
        }
    }
}

private struct CompactProjectLoadChip: View {
    let entry: CompactProjectLoadEntry

    var body: some View {
        HStack(spacing: 7) {
            Text(entry.name)
                .font(.system(size: 11, weight: .semibold))
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 116, alignment: .leading)
            Text("CPU \(formatCPU(entry.usage.cpuPercent))")
                .foregroundStyle(usageSeverityColor(entry.usage))
            Text("MEM \(formatBytes(entry.usage.memoryBytes))")
                .foregroundStyle(Theme.secondary)
        }
        .font(.system(size: 10, design: .monospaced))
        .padding(.horizontal, 9)
        .frame(height: 30)
        .background(Theme.control)
        .clipShape(RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.white.opacity(0.07)))
    }
}

private struct CompactLeaseBar: View {
    @ObservedObject var store: OpsStore

    private var latest: LeaseActionResult? { store.latestLeaseResult }

    private var otherLeases: [LeaseActionResult] {
        store.manageableLeaseResults.filter { $0.identity != latest?.identity }
    }

    @ViewBuilder
    var body: some View {
        if latest != nil || !otherLeases.isEmpty {
            HStack(spacing: 9) {
                Image(systemName: "network.badge.shield.half.filled")
                    .foregroundStyle(Theme.blue)
                    .accessibilityHidden(true)
                if let latest {
                    Text("Port \(latest.port)")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .textSelection(.enabled)
                    Text("leased to \(projectDisplayLabel(latest.project))")
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.secondary)
                        .lineLimit(1)
                    Spacer(minLength: 6)
                    leaseButtons(latest)
                    Button { store.dismissLatestLeaseResult() } label: {
                        Image(systemName: "xmark")
                    }
                    .buttonStyle(.plain)
                    .help("Dismiss lease result")
                    .accessibilityLabel("Dismiss lease result")
                } else {
                    Text("Managed port leases")
                        .font(.system(size: 11, weight: .semibold))
                    Spacer(minLength: 6)
                }
                if !otherLeases.isEmpty {
                    managedLeaseMenu
                }
            }
            .padding(.horizontal, 10)
            .frame(height: 38)
            .background(Theme.blue.opacity(0.07))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.blue.opacity(0.2)))
            .accessibilityIdentifier("compact-lease-bar")
        }
    }

    private func leaseButtons(_ lease: LeaseActionResult) -> some View {
        HStack(spacing: 5) {
            IconButton("Copy port", "doc.on.doc") { store.copyLeasePort(lease) }
            IconButton("Start using lease", "play.fill") {
                if store.prepareStartDraft(using: lease) { store.showingStartSheet = true }
            }
            .disabled(
                !lease.canStartServer
                    || !store.mutationAvailability(
                        kind: .startServer,
                        origin: lease.identity.origin,
                        resource: nil,
                        leaseID: lease.leaseID,
                        projectPath: lease.project
                    ).isAllowed
            )
            IconButton("Release lease", "xmark.circle") { store.releaseLease(lease) }
                .disabled(
                    !lease.canReleaseDirectly
                        || !store.mutationAvailability(
                            kind: .releasePort,
                            origin: lease.identity.origin,
                            resource: lease.identity,
                            leaseID: lease.leaseID,
                            projectPath: lease.project
                        ).isAllowed
                )
        }
        .fixedSize()
    }

    private var managedLeaseMenu: some View {
        Menu("\(otherLeases.count) more") {
            ForEach(otherLeases) { lease in
                Menu("Port \(lease.port) · \(projectDisplayLabel(lease.project))") {
                    Button("Copy port") { store.copyLeasePort(lease) }
                    Button("Start using lease") {
                        if store.prepareStartDraft(using: lease) { store.showingStartSheet = true }
                    }
                    .disabled(!lease.canStartServer)
                    Button("Release", role: .destructive) { store.releaseLease(lease) }
                        .disabled(!lease.canReleaseDirectly)
                }
            }
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }
}

struct BoardIncident: Identifiable {
    let id: String
    let actionID: UUID?
    let result: RetainedActionResult?
    let issue: OpsIssue?
    let timestamp: Date

    var phase: ActionPhase { result?.phase ?? .failed }
    var status: BoardIncidentStatus {
        if let result { return BoardIncidentStatus(phase: result.phase) }
        return issue?.kind == .action ? .failed : .warning
    }
    var title: String { result?.request.title ?? issue?.title ?? "Coordinator incident" }
    var operationLabel: String {
        let prefixes = ["Start ", "Stop ", "Restart ", "Retire "]
        guard let prefix = prefixes.first(where: { title.hasPrefix($0) }) else { return title }
        return String(title.dropFirst(prefix.count))
    }
    var source: String { result?.request.origin?.label ?? "Coordinator" }
}

@MainActor
func activityIncidents(in store: OpsStore) -> [BoardIncident] {
    var values = store.visibleActivityActionResults.map { result in
        BoardIncident(
            id: "action:\(result.id.uuidString)",
            actionID: result.id,
            result: result,
            issue: store.activityIssues.first { $0.relatedActionID == result.id },
            timestamp: result.finishedAt ?? result.startedAt ?? result.queuedAt
        )
    }
    let representedIssueIDs = Set(values.compactMap { $0.issue?.id })
    for issue in store.activityIssues where !representedIssueIDs.contains(issue.id) {
        values.append(
            BoardIncident(
                id: "issue:\(issue.id.uuidString)",
                actionID: issue.relatedActionID,
                result: nil,
                issue: issue,
                timestamp: issue.createdAt
            )
        )
    }
    return values.sorted { $0.timestamp > $1.timestamp }
}

struct ActivityWorkspaceView: View {
    @ObservedObject var store: OpsStore

    private var incidents: [BoardIncident] {
        activityIncidents(in: store)
    }

    private var selectedIncident: BoardIncident? {
        if let selectedIssueID = store.selectedActivityIssueID,
           let selected = incidents.first(where: { $0.issue?.id == selectedIssueID })
        {
            return selected
        }
        if let selectedID = store.selectedActionResultID,
           let selected = incidents.first(where: { $0.actionID == selectedID })
        {
            return selected
        }
        if let issue = store.activityIssues.first,
           let selected = incidents.first(where: { $0.issue?.id == issue.id })
        {
            return selected
        }
        return incidents.first
    }

    var body: some View {
        GeometryReader { proxy in
            ScrollView(.vertical) {
                if let selectedIncident {
                    if proxy.size.width >= 690 {
                        HStack(alignment: .top, spacing: 0) {
                            ActivityOperationList(
                                incidents: incidents,
                                selectedID: selectedIncident.id,
                                selectIncident: selectIncident
                            )
                            .frame(width: min(330, max(250, proxy.size.width * 0.34)))
                            Divider().overlay(Color.white.opacity(0.08))
                            ActivityIncidentDetail(store: store, incident: selectedIncident)
                                .frame(maxWidth: .infinity, alignment: .topLeading)
                        }
                        .frame(
                            maxWidth: .infinity,
                            minHeight: proxy.size.height,
                            alignment: .topLeading
                        )
                    } else {
                        VStack(alignment: .leading, spacing: 0) {
                            CompactActivitySelector(
                                incidents: incidents,
                                selected: selectedIncident,
                                selectIncident: selectIncident
                            )
                            Divider().overlay(Color.white.opacity(0.08))
                            ActivityIncidentDetail(store: store, incident: selectedIncident)
                        }
                        .frame(
                            maxWidth: .infinity,
                            minHeight: proxy.size.height,
                            alignment: .topLeading
                        )
                    }
                } else {
                    ActivityEmptyState(store: store)
                        .frame(
                            maxWidth: .infinity,
                            minHeight: proxy.size.height,
                            alignment: .center
                        )
                }
            }
            .accessibilityIdentifier("activity-workspace-scroll")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityIdentifier("activity-workspace")
    }

    private func selectIncident(_ incident: BoardIncident) {
        if let actionID = incident.actionID {
            store.showActivity(actionID: actionID)
        } else if let issueID = incident.issue?.id {
            store.showActivity(issueID: issueID)
        }
    }
}

private struct ActivityOperationList: View {
    let incidents: [BoardIncident]
    let selectedID: String
    let selectIncident: (BoardIncident) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("OPERATION")
                Spacer()
                Text("TIME")
            }
            .font(.system(size: 10, weight: .bold))
            .foregroundStyle(Theme.secondary)
            .padding(.horizontal, 14)
            .frame(height: 34)
            .background(Color.white.opacity(0.018))
            ForEach(incidents) { incident in
                ActivityOperationRow(
                    incident: incident,
                    isSelected: incident.id == selectedID,
                    select: { selectIncident(incident) }
                )
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .accessibilityIdentifier("activity-operation-list")
    }
}

private struct ActivityOperationRow: View {
    let incident: BoardIncident
    let isSelected: Bool
    let select: () -> Void

    var body: some View {
        Button(action: select) {
            HStack(alignment: .top, spacing: 9) {
                Image(systemName: phaseIcon)
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(incident.status.tint)
                    .frame(width: 14, height: 18)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text(phaseLabel)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(incident.status.tint)
                    Text(incident.operationLabel)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(Theme.primary)
                        .lineLimit(2)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 6)
                Text(incident.timestamp.formatted(date: .omitted, time: .shortened))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.secondary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .frame(maxWidth: .infinity, minHeight: 64, alignment: .leading)
            .background(isSelected ? Theme.blue.opacity(0.14) : Color.clear)
            .contentShape(Rectangle())
            .overlay(alignment: .bottom) {
                Rectangle().fill(Color.white.opacity(0.06)).frame(height: 1)
            }
            .overlay {
                if isSelected {
                    RoundedRectangle(cornerRadius: 3).stroke(Theme.blue.opacity(0.55))
                }
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(phaseLabel), \(incident.operationLabel), \(formatDate(incident.timestamp))")
        .accessibilityIdentifier("activity-operation-\(safeAccessibilityID(incident.id))")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private var phaseLabel: String {
        incident.status.label
    }

    private var phaseIcon: String {
        incident.status.icon
    }
}

private struct CompactActivitySelector: View {
    let incidents: [BoardIncident]
    let selected: BoardIncident
    let selectIncident: (BoardIncident) -> Void

    var body: some View {
        HStack(spacing: 10) {
            Text("Operation")
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(Theme.secondary)
            Menu {
                ForEach(incidents) { incident in
                    Button {
                        selectIncident(incident)
                    } label: {
                        Text("\(incident.status.label): \(incident.operationLabel)")
                    }
                }
            } label: {
                HStack(spacing: 7) {
                    IncidentStatusBadge(status: selected.status)
                    Text(selected.operationLabel).lineLimit(1)
                }
            }
            .menuStyle(.borderlessButton)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 14)
        .frame(height: 44)
        .accessibilityIdentifier("activity-operation-list")
    }
}

private struct IncidentFailurePayload: Decodable {
    let mutationPerformed: Bool?
    let priorOperationEffectsPossible: Bool?
    let actionRequired: String?
    let code: String?
    let classification: String?

    private enum CodingKeys: String, CodingKey {
        case mutationPerformed = "mutation_performed"
        case priorOperationEffectsPossible = "prior_operation_effects_possible"
        case actionRequired = "action_required"
        case code
        case classification
    }

    static func decode(from rawText: String) -> IncidentFailurePayload? {
        let text = rawText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }

        if let payload = decodeJSON(text) { return payload }
        guard let start = text.firstIndex(of: "{"),
              let end = text.lastIndex(of: "}"),
              start <= end
        else {
            return nil
        }
        return decodeJSON(String(text[start...end]))
    }

    private static func decodeJSON(_ text: String) -> IncidentFailurePayload? {
        guard let data = text.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(IncidentFailurePayload.self, from: data)
    }
}

private struct ActivityIncidentDetail: View {
    @ObservedObject var store: OpsStore
    let incident: BoardIncident
    @State private var technicalDetailsExpanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top, spacing: 10) {
                IncidentStatusBadge(status: incident.status)
                VStack(alignment: .leading, spacing: 3) {
                    Text(incident.title)
                        .font(.system(size: 15, weight: .bold))
                        .fixedSize(horizontal: false, vertical: true)
                    Text("\(formatDate(incident.timestamp)) · \(incident.source)")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.secondary)
                }
                Spacer(minLength: 12)
                if canDismissIncident {
                    Button(role: .destructive) {
                        dismissIncident()
                    } label: {
                        Label("Dismiss incident", systemImage: "trash")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .accessibilityIdentifier("activity-dismiss-incident")
                }
            }

            IncidentExplanationSection(
                title: "What happened",
                systemImage: "exclamationmark.circle.fill",
                tint: Theme.red,
                text: whatHappened
            )
            IncidentExplanationSection(
                title: "What changed",
                systemImage: "point.3.connected.trianglepath.dotted",
                tint: Color.purple,
                text: whatChanged
            )
            IncidentNextStepsSection(steps: nextSteps)
            technicalDetails
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .textSelection(.enabled)
        .accessibilityIdentifier("activity-incident-detail")
    }

    private var whatHappened: String {
        if isRetirement && fingerprintChanged {
            return "The retirement failed because the host resource controller fingerprint changed after the retirement plan was reviewed but before the retire action executed."
        }
        if let failure = incident.result?.failure, !failure.isEmpty { return failure }
        if let issue = incident.issue { return issue.summary }
        switch incident.phase {
        case .queued: return "The coordinator accepted the operation and is waiting to run it."
        case .running: return "The coordinator is currently running this operation."
        case .succeeded: return "The coordinator reported that the operation completed successfully."
        case .failed: return "The coordinator did not prove that the requested operation completed."
        case .timedOut: return "The bounded coordinator operation did not finish before its deadline."
        case .cancelled: return "The operation was cancelled before completion."
        }
    }

    private var whatChanged: String {
        if incident.result == nil, let issue = incident.issue {
            switch issue.kind {
            case .inventory:
                return "The latest inventory contains a condition the Board cannot treat as healthy. No resource action was attempted."
            case .configuration:
                return "Coordinator configuration is incomplete or inconsistent. No resource action was attempted."
            case .action:
                break
            }
        }
        if retirementRecoveryAction == .retryConfirmedOperation {
            return "The coordinator retained the retirement fence and original confirmed plan after an incomplete attempt. Host effects may already exist, so a replacement plan would be unsafe."
        }
        if typedFailurePayload?.priorOperationEffectsPossible == true,
           typedFailurePayload?.mutationPerformed == false
        {
            return "The current retry made no additional change, but the original fenced operation may already have retained host effects."
        }
        if typedFailurePayload?.priorOperationEffectsPossible == true {
            return "The confirmed operation remains fenced and may already have host effects. Inspect retained evidence before retrying the exact operation."
        }
        if isRetirement && fingerprintChanged {
            return "The controller fingerprint changed, indicating a modification to the host resource controller or its configuration since the plan was created. No retirement mutation was performed."
        }
        if typedFailurePayload?.mutationPerformed == false {
            return "No host mutation was performed. The coordinator rejected the operation before changing the resource."
        }
        switch incident.phase {
        case .succeeded:
            return "The retained result records a successful terminal state. Refresh Resources to see the latest inventory projection."
        case .queued, .running:
            return "No terminal result is available yet. The operation remains visible here while it progresses."
        case .failed, .timedOut, .cancelled:
            return "No successful completion is being reported. The retained technical evidence below is authoritative for this attempt."
        }
    }

    private var nextSteps: [String] {
        let requiredAction = typedFailurePayload?.actionRequired?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        var steps: [String]
        if incident.result == nil, incident.issue?.kind == .inventory {
            steps = [
                "Review the technical details for the affected source, capability, or repository evidence.",
                "Resolve the specific condition described by the coordinator without changing unrelated resources.",
                "Refresh Resources and confirm the warning is cleared before running actions.",
            ]
        } else if incident.result == nil, incident.issue?.kind == .configuration {
            steps = [
                "Review the technical details to identify the invalid or missing coordinator setting.",
                "Correct the coordinator configuration for the affected source.",
                "Refresh Resources and confirm the warning is cleared before running actions.",
            ]
        } else if retirementRecoveryAction == .retryConfirmedOperation {
            steps = [
                "Retry the exact confirmed operation from the action above.",
                "Keep the original plan ID and fingerprint; do not create a replacement plan.",
                "Review the new terminal evidence after the coordinator resumes the fenced operation.",
            ]
        } else if isRetirement && fingerprintChanged {
            steps = [
                "Refresh the latest resource state and re-plan the retirement.",
                "Review the controller fingerprint and confirm no unintended changes.",
                "Re-run the retirement plan once validated.",
            ]
        } else if incident.phase == .succeeded {
            steps = ["Return to Resources and confirm the inventory reflects the completed operation."]
        } else {
            steps = [
                "Review the technical evidence and any linked logs.",
                "Refresh Resources after correcting the reported condition.",
                "Retry from the exact resource only when its current identity is proven.",
            ]
        }
        guard !fingerprintChanged,
              let requiredAction,
              !requiredAction.isEmpty
        else { return steps }
        return [requiredAction] + steps.filter { $0 != requiredAction }
    }

    private var isRetirement: Bool {
        incident.result?.request.kind == .retireStandaloneResource
            || incident.title.localizedCaseInsensitiveContains("retire")
            || incident.title.localizedCaseInsensitiveContains("retirement")
    }

    private var fingerprintChanged: Bool {
        if typedFailurePayload?.code == "lifecycle_plan_stale"
            || typedFailurePayload?.classification == "lifecycle_target_identity_changed"
        {
            return true
        }
        return [incident.result?.failure, incident.issue?.summary, incident.issue?.details]
            .compactMap { $0 }
            .joined(separator: " ")
            .localizedCaseInsensitiveContains("fingerprint")
    }

    private var retirementRecoveryAction: ResourceRetirementRecoveryAction? {
        guard let actionID = incident.actionID else { return nil }
        return store.retirementRecoveryContexts[actionID]?.recoveryAction
    }

    private var typedFailurePayload: IncidentFailurePayload? {
        guard let result = incident.result else { return nil }
        return IncidentFailurePayload.decode(from: result.stdout)
            ?? IncidentFailurePayload.decode(from: result.stderr)
    }

    private var technicalText: String {
        if let result = incident.result {
            var details = store.actionResultPresentationDetails(result)
            if let issue = incident.issue,
               !issue.details.isEmpty,
               !details.contains(issue.details)
            {
                details += "\n\nIssue details:\n\(issue.details)"
            }
            return details
        }
        return incident.issue?.details ?? "No technical details were retained."
    }

    private var technicalDetails: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Button {
                    technicalDetailsExpanded.toggle()
                } label: {
                    Image(systemName: technicalDetailsExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 9, weight: .bold))
                }
                .buttonStyle(.plain)
                .accessibilityLabel(technicalDetailsExpanded ? "Hide technical details" : "Show technical details")
                Text("Technical details")
                    .font(.system(size: 12, weight: .semibold))
                Spacer()
                TechnicalEvidenceCopyButton {
                    if let result = incident.result {
                        store.copyActionResultDetails(result)
                    } else if let issue = incident.issue {
                        store.copyIssueDetails(issue)
                    }
                }
                .frame(width: 74, height: 24)
            }
            .padding(.horizontal, 11)
            .frame(height: 40)
            .background(Color.white.opacity(0.025))

            if technicalDetailsExpanded {
                Divider().overlay(Color.white.opacity(0.07))
                SelectableTechnicalEvidence(text: technicalText)
                    .padding(11)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        .background(Color.black.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.1)))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("activity-technical-details")
    }

    private func dismissIncident() {
        if let result = incident.result {
            store.dismissActionResult(result)
        } else if incident.issue?.kind == .action {
            store.dismissActionIssue()
        }
    }

    private var canDismissIncident: Bool {
        if let result = incident.result { return isTerminalActionPhase(result.phase) }
        return incident.issue?.kind == .action
    }
}

private struct IncidentStatusBadge: View {
    let status: BoardIncidentStatus

    var body: some View {
        Text(status.label)
            .font(.system(size: 11, weight: .bold))
            .foregroundStyle(status.tint)
            .padding(.horizontal, 9)
            .frame(height: 24)
            .background(status.tint.opacity(0.12))
            .clipShape(Capsule())
    }
}

private struct SelectableTechnicalEvidence: NSViewRepresentable {
    let text: String

    func makeNSView(context: Context) -> NSTextField {
        let view = NSTextField(wrappingLabelWithString: text)
        view.isEditable = false
        view.isSelectable = true
        view.drawsBackground = false
        view.isBezeled = false
        view.textColor = .labelColor
        view.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        view.lineBreakMode = .byWordWrapping
        view.maximumNumberOfLines = 0
        view.cell?.wraps = true
        view.cell?.isScrollable = false
        view.focusRingType = .none
        view.setAccessibilityIdentifier("activity-technical-details")
        updateNSView(view, context: context)
        return view
    }

    func updateNSView(_ view: NSTextField, context: Context) {
        if view.stringValue != text {
            view.stringValue = text
        }
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        nsView: NSTextField,
        context: Context
    ) -> CGSize? {
        guard let proposedWidth = proposal.width, proposedWidth > 0 else { return nil }
        let width = proposedWidth.isFinite ? min(proposedWidth, 4_000) : 800
        let bounds = (text as NSString).boundingRect(
            with: CGSize(width: width, height: 10_000),
            options: [.usesLineFragmentOrigin, .usesFontLeading],
            attributes: [.font: nsView.font ?? NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)]
        )
        let height = ceil(bounds.height)
        return CGSize(width: width, height: max(height, 1))
    }
}

private struct TechnicalEvidenceCopyButton: NSViewRepresentable {
    let action: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(action: action)
    }

    func makeNSView(context: Context) -> NSButton {
        let button = NSButton(
            title: "Copy",
            target: context.coordinator,
            action: #selector(Coordinator.performAction)
        )
        button.bezelStyle = .rounded
        button.controlSize = .small
        button.image = NSImage(systemSymbolName: "doc.on.doc", accessibilityDescription: nil)
        button.imagePosition = .imageLeading
        button.setAccessibilityIdentifier("activity-copy-technical-details")
        button.setAccessibilityLabel("Copy")
        button.setAccessibilityRole(.button)
        button.setAccessibilityEnabled(true)
        return button
    }

    func updateNSView(_ button: NSButton, context: Context) {
        context.coordinator.action = action
        button.isEnabled = true
    }

    @MainActor
    final class Coordinator: NSObject {
        var action: () -> Void

        init(action: @escaping () -> Void) {
            self.action = action
        }

        @objc func performAction() {
            action()
        }
    }
}

private struct IncidentExplanationSection: View {
    let title: String
    let systemImage: String
    let tint: Color
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 18)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.system(size: 13, weight: .bold))
                Text(text)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.primary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        }
    }
}

private struct IncidentNextStepsSection: View {
    let steps: [String]

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "arrow.down.circle.fill")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Theme.blue)
                .frame(width: 18)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text("What to do next")
                    .font(.system(size: 13, weight: .bold))
                ForEach(Array(steps.enumerated()), id: \.offset) { _, step in
                    HStack(alignment: .firstTextBaseline, spacing: 7) {
                        Text("•")
                        Text(step)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .font(.system(size: 12))
                }
            }
        }
    }
}

private struct ActivityEmptyState: View {
    @ObservedObject var store: OpsStore

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 28))
                .foregroundStyle(Theme.green)
            Text("No retained activity")
                .font(.system(size: 14, weight: .semibold))
            Text("Retained operation outcomes and coordinator warnings appear here. Successful preparation steps are folded into the operation they prepared.")
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
            Button("Back to resources") { store.showResources() }
                .buttonStyle(.borderedProminent)
        }
        .padding(30)
    }
}

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
        XCTAssertTrue(fixture.store.repositoryTrees.isEmpty)
        XCTAssertFalse(fixture.store.repositoryTreesAreAuthoritative)
        XCTAssertTrue(fixture.store.repositoryTreeContractUnavailable)
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

    func testResourcesWorkspaceOwnsExactlyOneVisibleVerticalScrollerAtCompactAndDesktopWidths() throws {
        for (width, height) in [(mainPaneWidth, minimumWindowHeight), (desktopMainPaneWidth, desktopWindowHeight)] {
            let fixture = try makeDenseMinimumWindowFixture()
            fixture.store.showResources()

            let hostingView = hostMainBoard(
                store: fixture.store,
                width: width,
                height: height
            )
            let owners = visibleVerticalScrollOwners(in: hostingView)

            XCTAssertEqual(
                owners.count,
                1,
                "Resources at \(width)x\(height) must have one vertical scroll owner, not nested document/table drawers: \(scrollTopologyDescription(owners))"
            )
        }
    }

    func testActivityFailureWorkspaceOwnsExactlyOneVisibleVerticalScrollerAtCompactAndDesktopWidths() throws {
        for (width, height) in [(mainPaneWidth, minimumWindowHeight), (desktopMainPaneWidth, desktopWindowHeight)] {
            let fixture = try makeDenseMinimumWindowFixture()
            fixture.store.showActivity(actionID: fixture.actionID)

            let hostingView = hostMainBoard(
                store: fixture.store,
                width: width,
                height: height
            )
            let owners = visibleVerticalScrollOwners(in: hostingView)

            XCTAssertEqual(fixture.store.boardWorkspace, .activity)
            XCTAssertEqual(fixture.store.selectedActionResultID, fixture.actionID)
            XCTAssertEqual(
                owners.count,
                1,
                "Activity at \(width)x\(height) must use one shared vertical scroll owner: \(scrollTopologyDescription(owners))"
            )
            let raster = try renderMainBoard(store: fixture.store, width: width, height: height)
            try captureRasterIfRequested(
                raster,
                name: "main-board-activity-failure-\(width)x\(height)"
            )
        }

        let fullShellFixture = try makeDenseMinimumWindowFixture()
        fullShellFixture.store.showActivity(actionID: fullShellFixture.actionID)
        let fullShell = try renderOpsConsole(
            store: fullShellFixture.store,
            width: 1_592,
            height: 842
        )
        try captureRasterIfRequested(
            fullShell,
            name: "ops-console-activity-failure-1592x842"
        )
    }

    func testTypedStaleRetirementFailureRendersActionScopedRecoveryWorkspace() async throws {
        let discovery = AccountCoordinatorOriginDiscovery(
            environment: [:],
            accountHomeResolver: POSIXAccountHomeResolver(
                resolveAccountHome: { "/fixtures/retirement-account" }
            )
        )
        let origin = try XCTUnwrap(discovery.origins().first)
        let staleFailure = CommandExecution(
            stdout: "",
            stderr: #"{"ok":false,"code":"lifecycle_plan_stale","classification":"lifecycle_target_identity_changed","mutation_performed":false,"error":"Resource ownership generation changed after planning.","action_required":"Refresh authoritative inventory, review a newly generated lifecycle plan, and retry."}"#,
            exitStatus: 1
        )
        let firstPlan = retirementVisualPlanJSON(
            planID: "retire-plan-visual-1",
            planFingerprint: "retire-fingerprint-visual-1",
            ownershipFingerprint: "planned-ownership-generation-2"
        )
        let replacementPlan = retirementVisualPlanJSON(
            planID: "retire-plan-visual-2",
            planFingerprint: "retire-fingerprint-visual-2",
            ownershipFingerprint: "planned-ownership-generation-4"
        )
        _ = try JSONDecoder().decode(
            StandaloneRetirementPlan.self,
            from: Data(firstPlan.utf8)
        )
        let service = RetirementVisualCoordinatorService(results: [
            try retirementVisualInventoryExecution(
                home: origin.home,
                ownershipFingerprint: "ownership-fingerprint-1"
            ),
            CommandExecution(stdout: firstPlan, stderr: "", exitStatus: 0),
            staleFailure,
            try retirementVisualInventoryExecution(
                home: origin.home,
                ownershipFingerprint: "refreshed-ownership-generation-3"
            ),
            try retirementVisualInventoryExecution(
                home: origin.home,
                ownershipFingerprint: "refreshed-ownership-generation-3"
            ),
            CommandExecution(stdout: replacementPlan, stderr: "", exitStatus: 0),
        ])
        let now = Date(timeIntervalSince1970: 1_785_080_400)
        let store = OpsStore(
            coordinatorService: service,
            originDiscovery: discovery,
            configurationStore: VerticalLayoutConfigurationStore(),
            clock: VerticalLayoutClock(value: now)
        )

        await store.loadInventory(force: true)
        seedRetirementVisualHistory(store: store, origin: origin, now: now)
        let targetRow = try XCTUnwrap(
            store.repositoryCatalog.unassigned.docker.first {
                $0.representative.name == "kosttracking-prod-copy-pg"
            }
        )
        store.selectDocker(targetRow.representative)
        let target = try XCTUnwrap(targetRow.representative.exactUnassignedResource)
        store.planResourceRetirement(target)
        do {
            try await waitForRetirementVisualState("retirement plan prompt") {
                store.resourceRetirementPrompt != nil
            }
        } catch {
            let issueDetails = store.actionIssue?.details ?? "none"
            let resultDetails = store.actionResults.values.map {
                "\($0.phase.rawValue):\($0.failure ?? "none")"
            }
            XCTFail(
                "retirement planning did not produce a prompt; issue=\(issueDetails) results=\(resultDetails)"
            )
            throw error
        }
        store.applyResourceRetirement(try XCTUnwrap(store.resourceRetirementPrompt))
        try await waitForRetirementVisualState("selected stale-retirement incident") {
            store.resourceRetirementPrompt == nil
                && store.boardWorkspace == .activity
                && store.selectedActionResultID != nil
                && store.actionResults[store.selectedActionResultID!]?.phase == .failed
                && store.selectedRetirementRecoveryActionTitle == "Refresh & re-plan"
                && store.repositoryCatalog.unassigned.docker.contains {
                    $0.representative.exactUnassignedResource?.ownershipFingerprint
                        == "refreshed-ownership-generation-3"
                }
        }

        XCTAssertTrue(
            store.repositoryTreesAreAuthoritative,
            "the visual acceptance state must use the same authoritative repository hierarchy promised by the mockup"
        )
        XCTAssertGreaterThanOrEqual(
            store.repositoryTrees.count,
            5,
            "a sparse empty sidebar is not a faithful full-shell comparison target"
        )
        XCTAssertEqual(
            store.selectedDocker?.name,
            "kosttracking-prod-copy-pg",
            "the exact retirement target must remain selected so the inspector matches the reviewed workflow"
        )
        XCTAssertGreaterThanOrEqual(
            store.actionResults.count,
            8,
            "the Activity workspace must be exercised at the operation density shown in the selected mockup"
        )

        let actionID = try XCTUnwrap(store.selectedActionResultID)
        let planningActionID = try XCTUnwrap(
            store.actionResults.first {
                $0.value.request.title == "Plan retirement of kosttracking-prod-copy-pg"
                    && $0.value.phase == .succeeded
            }?.key
        )
        XCTAssertEqual(
            store.retirementRecoveryContexts[actionID]?.recoveryAction,
            .refreshAndReplan
        )
        XCTAssertEqual(store.actionIssue?.relatedActionID, actionID)
        XCTAssertTrue(store.actionResults[actionID]?.stderr.contains(#""code":"lifecycle_plan_stale""#) == true)
        let failedRetirementResult = try XCTUnwrap(store.actionResults[actionID])
        let rawDetails = store.actionResultDetails(failedRetirementResult)
        let presentationDetails = store.actionResultPresentationDetails(failedRetirementResult)
        XCTAssertTrue(rawDetails.contains(staleFailure.stderr))
        XCTAssertFalse(rawDetails.contains("\n  \"code\""))
        XCTAssertTrue(presentationDetails.contains("\n  \"code\""))
        XCTAssertNotEqual(rawDetails, presentationDetails)
        let pasteboard = NSPasteboard.withUniqueName()
        defer { pasteboard.clearContents() }
        store.copyActionResultDetails(failedRetirementResult, to: pasteboard)
        XCTAssertEqual(pasteboard.string(forType: .string), rawDetails)

        let inventoryIssue = OpsIssue(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000799")!,
            kind: .inventory,
            title: "web-before-repro",
            summary: "Its recorded repository no longer exists; refresh after reinstalling or retiring it.",
            details: "The coordinator retained web-before-repro, but its canonical repository path is unavailable.",
            createdAt: now.addingTimeInterval(-720),
            relatedActionID: nil
        )
        store.inventoryIssue = inventoryIssue

        XCTAssertNil(store.retirementRecoveryContexts[planningActionID])
        store.showActivity(actionID: planningActionID)
        XCTAssertEqual(
            store.selectedActionResultID,
            actionID,
            "a hidden preparatory result must not replace the visible incident selection"
        )
        XCTAssertEqual(store.selectedRetirementRecoveryActionTitle, "Refresh & re-plan")

        let designAcceptanceView = hostMainBoard(
            store: store,
            width: desktopMainPaneWidth,
            height: desktopWindowHeight
        )
        let incidents = activityIncidents(in: store)
        XCTAssertEqual(incidents.count, 8)
        let warning = try XCTUnwrap(incidents.first { $0.status == .warning })
        XCTAssertEqual(warning.operationLabel, "web-before-repro")
        let renderedText = descendantViews(of: NSTextField.self, in: designAcceptanceView)
            .map(\.stringValue)
        XCTAssertTrue(renderedText.contains(
            "The controller fingerprint changed, indicating a modification to the host resource controller or its configuration since the plan was created. No retirement mutation was performed."
        ))
        XCTAssertTrue(renderedText.contains("Re-run the retirement plan once validated."))
        XCTAssertTrue(
            renderedText.contains { $0.contains("Stderr:\n{") && $0.contains("\n  \"code\"") },
            "technical JSON must be readable on screen while Copy retains the original payload"
        )
        XCTAssertFalse(
            descendantViews(of: NSButton.self, in: designAcceptanceView)
                .contains { $0.title == "Details" },
            "Activity must not repeat the technical-details action in its incident header"
        )

        store.showActivity(issueID: inventoryIssue.id)
        let selectedInventoryWarningView = hostMainBoard(
            store: store,
            width: desktopMainPaneWidth,
            height: desktopWindowHeight
        )
        let inventoryWarningText = descendantViews(
            of: NSTextField.self,
            in: selectedInventoryWarningView
        ).map(\.stringValue)
        XCTAssertTrue(inventoryWarningText.contains(
            "The latest inventory contains a condition the Board cannot treat as healthy. No resource action was attempted."
        ))
        XCTAssertTrue(inventoryWarningText.contains(
            "Resolve the specific condition described by the coordinator without changing unrelated resources."
        ))
        XCTAssertFalse(inventoryWarningText.contains {
            $0.contains("No successful completion is being reported")
                || $0.contains("Retry from the exact resource")
        })
        store.showActivity(actionID: actionID)

        for (width, height) in [(mainPaneWidth, minimumWindowHeight), (desktopMainPaneWidth, desktopWindowHeight)] {
            let hostingView = hostMainBoard(store: store, width: width, height: height)
            XCTAssertEqual(
                visibleVerticalScrollOwners(in: hostingView).count,
                1,
                "the exact stale-retirement incident must retain one vertical scroll owner at \(width)x\(height)"
            )
            try captureRasterIfRequested(
                renderMainBoard(store: store, width: width, height: height),
                name: "main-board-retirement-stale-\(width)x\(height)"
            )
        }
        try captureRasterIfRequested(
            renderOpsConsole(store: store, width: 1_592, height: 842),
            name: "ops-console-retirement-stale-1592x842"
        )
        try captureRasterIfRequested(
            renderOpsConsole(store: store, width: 1_728, height: 884),
            name: "ops-console-retirement-stale-1728x884"
        )

        let unowned = try JSONDecoder().decode(
            ManagedServer.self,
            from: Data(
                #"{"id":"unowned-rendered","name":"unowned-rendered","status":"running"}"#.utf8
            )
        )
        store.restart(unowned)
        let unmatchedIssue = try XCTUnwrap(store.actionIssue)

        let selectedRetirementView = hostMainBoard(
            store: store,
            width: desktopMainPaneWidth,
            height: desktopWindowHeight
        )
        XCTAssertEqual(store.selectedRetirementRecoveryActionTitle, "Refresh & re-plan")
        XCTAssertTrue(
            descendantViews(of: NSTextField.self, in: selectedRetirementView)
                .contains {
                    $0.stringValue == "The retirement failed because the host resource controller fingerprint changed after the retirement plan was reviewed but before the retire action executed."
                },
            "the selected retirement must remain the rendered Activity detail when an unrelated alert arrives"
        )
        XCTAssertFalse(
            descendantViews(of: NSTextField.self, in: selectedRetirementView)
                .contains { $0.stringValue == unmatchedIssue.summary },
            "an unmatched alert must not visually replace the explicitly selected retirement"
        )

        store.showActivity(issueID: unmatchedIssue.id)
        let selectedUnmatchedIssueView = hostMainBoard(
            store: store,
            width: desktopMainPaneWidth,
            height: desktopWindowHeight
        )
        XCTAssertNil(
            store.selectedRetirementRecoveryActionTitle,
            "an unmatched alert must never inherit another incident's retirement action"
        )
        XCTAssertTrue(
            descendantViews(of: NSTextField.self, in: selectedUnmatchedIssueView)
                .contains { $0.stringValue == unmatchedIssue.summary },
            "the Activity detail must display the explicitly selected unmatched alert"
        )
        store.showActivity(actionID: actionID)
        XCTAssertEqual(store.selectedRetirementRecoveryActionTitle, "Refresh & re-plan")

        store.recoverSelectedRetirement()
        try await waitForRetirementVisualState("replacement retirement plan") {
            store.boardWorkspace == .resources
                && store.resourceRetirementPrompt?.plan.planID == "retire-plan-visual-2"
                && store.retirementRecoveryContexts[actionID] == nil
        }
        let calls = await service.capturedCalls()
        XCTAssertEqual(calls.count, 6)
        XCTAssertEqual(calls[0].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
        XCTAssertTrue(arguments(calls[1].1, contain: ["resource", "plan-retire"]))
        XCTAssertTrue(arguments(calls[2].1, contain: ["resource", "retire"]))
        XCTAssertEqual(calls[3].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
        XCTAssertEqual(calls[4].1, ["inventory", "--compact-json", "--stats-history-limit", "30"])
        XCTAssertTrue(arguments(calls[5].1, contain: ["resource", "plan-retire"]))
        XCTAssertTrue(
            arguments(calls[5].1, contain: [
                "--ownership-fingerprint", "refreshed-ownership-generation-3",
            ])
        )

        store.showActivity(actionID: actionID)
        store.dismissActionResult(failedRetirementResult)
        let postDismissIncidents = activityIncidents(in: store)
        if let selectedResultID = store.selectedActionResultID {
            let selectedIncident = try XCTUnwrap(
                postDismissIncidents.first { $0.actionID == selectedResultID }
            )
            XCTAssertEqual(store.selectedActivityActionResult?.id, selectedIncident.result?.id)
        } else if let selectedIssueID = store.selectedActivityIssueID {
            let selectedIncident = try XCTUnwrap(
                postDismissIncidents.first { $0.issue?.id == selectedIssueID }
            )
            XCTAssertEqual(store.selectedActivityActionIssue?.id, selectedIncident.issue?.id)
        } else {
            XCTFail("dismissing the selected failure must choose another visible incident")
        }
        XCTAssertNotEqual(
            store.selectedActionResultID,
            planningActionID,
            "a hidden planning success must never drive the Activity header after dismissal"
        )
    }

    func testSelectedInventoryWarningTracksRefreshReplacementAndClear() {
        let now = Date(timeIntervalSince1970: 1_785_080_400)
        let store = OpsStore(
            originDiscovery: VerticalLayoutOriginDiscovery(values: []),
            configurationStore: VerticalLayoutConfigurationStore(),
            clock: VerticalLayoutClock(value: now)
        )
        let firstIssue = OpsIssue(
            kind: .inventory,
            title: "Inventory incomplete",
            summary: "The Docker capability could not be observed.",
            details: "Docker socket unavailable.",
            createdAt: now
        )
        store.inventoryIssue = firstIssue
        store.showActivity(issueID: firstIssue.id)
        XCTAssertEqual(store.selectedActivityActionIssue?.id, firstIssue.id)

        let replacement = OpsIssue(
            kind: .inventory,
            title: "Inventory incomplete",
            summary: "One coordinator source could not be refreshed.",
            details: "Coordinator source timed out.",
            createdAt: now.addingTimeInterval(1)
        )
        store.inventoryIssue = replacement
        XCTAssertEqual(store.selectedActivityIssueID, replacement.id)
        XCTAssertEqual(store.selectedActivityActionIssue?.id, replacement.id)

        store.inventoryIssue = nil
        XCTAssertNil(store.selectedActivityIssueID)
        XCTAssertNil(store.selectedActivityActionIssue)
    }

    func testVerticalScrollTopologyGuardCatchesLegacyNestingWithoutCountingHorizontalOnlyScroll() {
        let legacy = hostView(
            LegacyNestedVerticalScrollFixture(),
            width: mainPaneWidth,
            height: minimumWindowHeight
        )
        let legacyOwners = visibleVerticalScrollOwners(in: legacy)
        XCTAssertGreaterThanOrEqual(
            legacyOwners.count,
            2,
            "the guard must catch the former document plus Activity/table nested vertical scroll structure"
        )

        let horizontalControl = hostView(
            HorizontalOnlyScrollControlFixture(),
            width: mainPaneWidth,
            height: minimumWindowHeight
        )
        let horizontalControlOwners = visibleVerticalScrollOwners(in: horizontalControl)
        XCTAssertEqual(
            horizontalControlOwners.count,
            1,
            "a horizontal resource table must not be misclassified as a second vertical scroll owner: \(scrollTopologyDescription(horizontalControlOwners))"
        )
    }

    func testActivityTechnicalDetailsAreSelectableAndExposeAnAccessibleCopyAction() throws {
        let fixture = try makeDenseMinimumWindowFixture()
        fixture.store.showActivity(actionID: fixture.actionID)
        let hostingView = hostMainBoard(
            store: fixture.store,
            width: desktopMainPaneWidth,
            height: desktopWindowHeight
        )

        let selectableEvidenceFields = descendantViews(of: NSTextField.self, in: hostingView)
            .filter { $0.stringValue.contains("Fixture health check timed out") && $0.isSelectable }
        XCTAssertTrue(
            !selectableEvidenceFields.isEmpty,
            "technical failure evidence must be selectable through the native text system"
        )
        XCTAssertTrue(
            selectableEvidenceFields.allSatisfy { !$0.isEditable },
            "selectable technical evidence must remain read-only"
        )

        let copyAction = try XCTUnwrap(
            accessibilityObject(
                identifier: "activity-copy-technical-details",
                in: hostingView
            ) ?? descendantViews(of: NSButton.self, in: hostingView).first {
                $0.title == "Copy" || $0.accessibilityLabel() == "Copy"
            },
            "Activity must expose a keyboard/assistive-technology reachable Copy technical details action"
        )
        let copyRole = try XCTUnwrap(accessibilityRole(of: copyAction))
        XCTAssertEqual(
            String(describing: copyRole),
            String(describing: NSAccessibility.Role.button)
        )
        XCTAssertTrue(
            accessibilityIsEnabled(copyAction),
            "the copy action must be enabled for a selected failed operation"
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
    let technicalFailure = (1...48)
        .map { "Fixture health check timed out (diagnostic line \($0))." }
        .joined(separator: "\n")
    store.actionResults[actionID] = RetainedActionResult(
        request: request,
        phase: .failed,
        queuedAt: now.addingTimeInterval(-2),
        startedAt: now.addingTimeInterval(-1),
        finishedAt: now,
        exitStatus: 1,
        stdout: "",
        stderr: technicalFailure,
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
    return DenseMinimumWindowFixture(
        store: store,
        fixtureRoot: fixtureRoot,
        actionID: actionID
    )
}

private actor RetirementVisualCoordinatorService: CoordinatorServing {
    private var results: [CommandExecution]
    private var calls: [(CoordinatorOrigin, [String])] = []

    init(results: [CommandExecution]) {
        self.results = results
    }

    func requestProjectRoot() async throws -> String? { "/workflow/repo" }

    func execute(origin: CoordinatorOrigin, arguments: [String]) async throws -> CommandExecution {
        calls.append((origin, arguments))
        guard !results.isEmpty else {
            throw RuntimeError("Retirement visual fixture exhausted its coordinator responses")
        }
        return try normalizedInventoryExecution(
            results.removeFirst(),
            origin: origin,
            arguments: arguments
        )
    }

    func capturedCalls() -> [(CoordinatorOrigin, [String])] { calls }
}

private func retirementVisualPlanJSON(
    planID: String,
    planFingerprint: String,
    ownershipFingerprint: String
) -> String {
    """
    {"schema_version":1,"kind":"standalone_resource_retirement","plan_id":"\(planID)","resource_id":"docker:immutable-copy-pg","fingerprint":"\(planFingerprint)","created_at":"2026-07-26T18:39:00Z","actor":"tester","reason":"Retired from DevOps Board","retained_data":["containers","volumes","databases","backups","audit_history"],"targets":[{"target_id":"docker:immutable-copy-pg","kind":"container","host_resource_id":"docker:immutable-copy-pg","immutable_fingerprint":"container-fingerprint-1","control_binding_id":"docker-binding-1","ownership_fingerprint":"\(ownershipFingerprint)","control_contract_fingerprint":"planned-controller-contract-1","display_name":"kosttracking-prod-copy-pg","current_state":"stopped","policies":[{"policy_id":"docker-policy-1","kind":"restart_policy","immutable_fingerprint":"restart-policy-fingerprint-1","disabled_value":"no"}],"allocations":[]}]}
    """
}

private func retirementVisualInventoryExecution(
    home: String,
    ownershipFingerprint: String
) throws -> CommandExecution {
    let timestamp = "2026-07-26T18:39:00Z"
    let hostID = "host-retirement"
    let sourceID = "retirement-source"
    let rootSpecs: [(id: String, root: String, name: String)] = [
        ("repo-benzovozka", "/fixtures/repos/benzovozka", "benzovozka"),
        ("repo-globalfinance", "/fixtures/repos/GlobalFinance", "GlobalFinance"),
        ("repo-globalnewstracker", "/fixtures/repos/globalnewstracker", "globalnewstracker"),
        ("repo-kosttracking", "/fixtures/repos/KostTracking", "KostTracking"),
        ("repo-nevod", "/fixtures/repos/Nevod", "Nevod"),
        ("repo-skydive", "/fixtures/repos/SkydiveLive", "SkydiveLive"),
    ]
    let temporarySpec = (
        id: "repo-benzovozka-preview",
        root: "/fixtures/repos/benzovozka/.worktrees/preview",
        name: "preview run"
    )
    let serverSpecs: [(id: String, repoID: String, name: String)] = [
        ("server-brand-logo", "repo-benzovozka", "brand-logo-scheduler"),
        ("server-read-cache", "repo-benzovozka", "read-cache-worker"),
        ("server-russiabase", "repo-benzovozka", "russiabase-worker"),
        ("server-station-imports", "repo-benzovozka", "station-imports-worker"),
        ("server-web-bug", "repo-benzovozka", "web-bug-capture"),
        ("server-web-prod", "repo-benzovozka", "web-prod-clone"),
        ("server-web-preview", temporarySpec.id, "web-before-repro"),
        ("server-gnt-web", "repo-globalnewstracker", "web"),
        ("server-prod-copy-web", "repo-kosttracking", "prod-copy-web"),
        ("server-nevod-worker", "repo-nevod", "telegram-worker"),
    ]
    let assignedDockerSpecs: [(id: String, repoID: String, name: String, image: String)] = [
        ("docker-gf-minio", "repo-globalfinance", "gf-minio-1", "minio/minio:latest"),
        ("docker-gnt-metrics", "repo-globalnewstracker", "metrics-worker", "metrics-worker:dev"),
        ("docker-gnt-minio", "repo-globalnewstracker", "minio", "minio/minio:latest"),
        ("docker-nevod-postgres", "repo-nevod", "postgres", "postgres:17-alpine"),
        ("docker-nevod-postgres-shadow", "repo-nevod", "postgres-shadow", "postgres:17-alpine"),
    ]

    var repositories = rootSpecs.map { spec -> [String: Any] in
        [
            "repo_id": spec.id,
            "host_id": hostID,
            "canonical_root": spec.root,
            "display_name": spec.name,
            "state": "active",
            "generation": 1,
            "installation_status": "active",
            "startup_fenced": false,
            "installation_generation": 1,
        ]
    }
    repositories.append([
        "repo_id": temporarySpec.id,
        "host_id": hostID,
        "canonical_root": temporarySpec.root,
        "display_name": temporarySpec.name,
        "state": "active",
        "generation": 1,
        "installation_status": "active",
        "startup_fenced": false,
        "installation_generation": 1,
    ])

    let memberships: [[String: Any]] = serverSpecs.map { spec in
        [
            "membership_id": "membership-\(spec.id)",
            "repo_id": spec.repoID,
            "resource_kind": "server",
            "host_resource_id": spec.id,
            "immutable_fingerprint": "fingerprint-\(spec.id)",
            "control_binding_id": "binding-\(spec.id)",
        ]
    } + assignedDockerSpecs.map { spec in
        [
            "membership_id": "membership-\(spec.id)",
            "repo_id": spec.repoID,
            "resource_kind": "container",
            "host_resource_id": spec.id,
            "immutable_fingerprint": "fingerprint-\(spec.id)",
            "control_binding_id": "binding-\(spec.id)",
        ]
    }

    let authoritativeBindings: [[String: Any]] = serverSpecs.map { spec in
        [
            "binding_id": "binding-\(spec.id)",
            "repo_id": spec.repoID,
            "source_resource_id": spec.id,
            "resource_kind": "server",
            "resource_id": spec.id,
            "source_id": sourceID,
            "capability": "lifecycle",
            "provenance": "normalized_fixture",
            "authority_state": "authoritative",
            "priority": 100,
            "generation": 1,
        ]
    } + assignedDockerSpecs.map { spec in
        [
            "binding_id": "binding-\(spec.id)",
            "repo_id": spec.repoID,
            "source_resource_id": spec.id,
            "resource_kind": "container",
            "resource_id": spec.id,
            "source_id": sourceID,
            "capability": "lifecycle",
            "provenance": "normalized_fixture",
            "authority_state": "authoritative",
            "priority": 100,
            "generation": 1,
        ]
    }

    let serverDefinitions: [[String: Any]] = serverSpecs.map { spec in
        let root = (rootSpecs.first { $0.id == spec.repoID }?.root) ?? temporarySpec.root
        return [
            "server_definition_id": spec.id,
            "repo_id": spec.repoID,
            "name": spec.name,
            "role": "worker",
            "cwd": root,
            "log_path": "/fixtures/logs/\(spec.name).log",
            "definition_fingerprint": "definition-\(spec.id)",
            "generation": 1,
            "arguments": ["fixture-service", spec.name],
        ]
    }
    let dockerResources: [[String: Any]] = assignedDockerSpecs.map { spec in
        [
            "docker_resource_id": spec.id,
            "engine_id": "engine-retirement",
            "full_container_id": "container-\(spec.id)",
            "current_name": spec.name,
            "image": spec.image,
            "created_at": timestamp,
            "updated_at": timestamp,
        ]
    } + [[
        "docker_resource_id": "immutable-copy-pg",
        "engine_id": "engine-retirement",
        "full_container_id": "container-immutable-copy-pg",
        "current_name": "kosttracking-prod-copy-pg",
        "image": "postgres:17-alpine",
        "created_at": timestamp,
        "updated_at": timestamp,
    ]]
    let serverObservations: [[String: Any]] = serverSpecs.map { spec in
        [
            "server_definition_id": spec.id,
            "source_resource_id": spec.id,
            "lifecycle": "stopped",
            "listener_observable": 1,
            "health_classification": "stopped",
            "stopped_at": timestamp,
            "stopped_reason": "fixture",
            "sampled_at": timestamp,
        ]
    }
    let dockerObservations: [[String: Any]] = (assignedDockerSpecs.map(\.id) + ["immutable-copy-pg"])
        .map { resourceID in
            [
                "docker_resource_id": resourceID,
                "lifecycle": "stopped",
                "health": "stopped",
                "restart_policy": "no",
                "sampled_at": timestamp,
            ]
        }

    func scope(
        repoID: String,
        kind: String,
        root: String,
        name: String,
        runID: Any = NSNull(),
        expiresAt: Any = NSNull(),
        killAfterRun: Any = NSNull()
    ) -> [String: Any] {
        let serverIDs = serverSpecs.filter { $0.repoID == repoID }.map(\.id)
        let containerIDs = assignedDockerSpecs.filter { $0.repoID == repoID }.map(\.id)
        return [
            "repo_id": repoID,
            "kind": kind,
            "canonical_root": root,
            "display_name": name,
            "run_id": runID,
            "expires_at": expiresAt,
            "kill_after_run": killAfterRun,
            "usage": [
                "cpu_percent": 0.0,
                "memory_bytes": 0,
                "process_count": 0,
                "server": ["resource_count": serverIDs.count],
                "docker": ["resource_count": containerIDs.count],
            ],
            "server_ids": serverIDs,
            "container_resource_ids": containerIDs,
            "database_binding_ids": [],
        ]
    }
    let repositoryTrees: [[String: Any]] = rootSpecs.map { spec in
        var scopes = [scope(repoID: spec.id, kind: "root", root: spec.root, name: spec.name)]
        if spec.id == "repo-benzovozka" {
            scopes.append(scope(
                repoID: temporarySpec.id,
                kind: "temporary",
                root: temporarySpec.root,
                name: temporarySpec.name,
                runID: "preview-run-1",
                expiresAt: "2099-01-01T00:00:00Z",
                killAfterRun: true
            ))
        }
        let serverCount = scopes.compactMap { $0["server_ids"] as? [String] }.flatMap { $0 }.count
        let containerCount = scopes.compactMap { $0["container_resource_ids"] as? [String] }.flatMap { $0 }.count
        return [
            "family_id": "family-\(spec.id)",
            "root_repository": [
                "repo_id": spec.id,
                "canonical_root": spec.root,
                "display_name": spec.name,
            ],
            "usage": [
                "cpu_percent": 0.0,
                "memory_bytes": 0,
                "process_count": 0,
                "server": ["resource_count": serverCount],
                "docker": ["resource_count": containerCount],
            ],
            "scopes": scopes,
        ]
    }

    let object: [String: Any] = [
        "schema_version": 2,
        "store": [
            "database_generation": "retirement-fixture-generation",
            "state_revision": 3,
            "observation_revision": 3,
            "authority_mode": "sqlite",
            "migration_state": "complete",
            "updated_at": timestamp,
        ],
        "repositories": repositories,
        "repository_trees": repositoryTrees,
        "coordinator_sources": [[
            "source_id": sourceID,
            "canonical_home": home,
            "effective_uid": 501,
            "status": "imported",
        ]],
        "docker_engines": [[
            "engine_id": "engine-retirement",
            "host_id": hostID,
            "capability_state": "available",
        ]],
        "memberships": memberships,
        "resources": [
            "servers": serverDefinitions,
            "docker": dockerResources,
            "docker_ports": [],
            "databases": [],
        ],
        "observations": [
            "servers": serverObservations,
            "docker": dockerObservations,
            "databases": [],
            "telemetry": [],
            "snapshots": [],
        ],
        "leases": [],
        "port_assignments": [],
        "backup_evidence": [],
        "database_backups": [],
        "database_restore_events": [],
        "events": [],
        "unassigned_resources": [[
            "unassigned_id": "unassigned-immutable-copy-pg",
            "resource_kind": "container",
            "resource_id": "immutable-copy-pg",
            "display_name": "kosttracking-prod-copy-pg",
            "reason_code": "ambiguous_control",
            "explanation": "Only a resource name was observed; no authoritative repository path was provided.",
            "observed_by": ["\(home)/coordinator.sqlite3"],
            "controller": "\(home)/coordinator.sqlite3",
            "host_resource_id": "docker:immutable-copy-pg",
            "immutable_fingerprint": "container-fingerprint-1",
            "control_binding_id": "docker-binding-1",
            "ownership_fingerprint": ownershipFingerprint,
            "can_attach": true,
            "can_retire": true,
            "lifecycle_violation": false,
            "recommended_next_step": "Attach it to its root repository, or retire it to stop and hide it without deleting data.",
        ]],
        "lifecycle_violations": [],
        "control_bindings": authoritativeBindings + [[
            "binding_id": "docker-binding-1",
            "repo_id": NSNull(),
            "source_resource_id": "immutable-copy-pg",
            "resource_kind": "container",
            "resource_id": "immutable-copy-pg",
            "source_id": sourceID,
            "capability": "lifecycle",
            "provenance": "host_observation",
            "authority_state": "observed",
            "priority": 10,
            "generation": 1,
        ]],
        "test_statistics": [],
    ]
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return CommandExecution(
        stdout: String(decoding: data, as: UTF8.self),
        stderr: "",
        exitStatus: 0
    )
}

@MainActor
private func seedRetirementVisualHistory(
    store: OpsStore,
    origin: CoordinatorOrigin,
    now: Date
) {
    let entries: [(id: String, kind: ActionKind, title: String, phase: ActionPhase, offset: TimeInterval)] = [
        ("00000000-0000-0000-0000-000000000781", .restartDocker, "Restart aicursegmailcheck-postgres-dev", .failed, -240),
        ("00000000-0000-0000-0000-000000000782", .restartDocker, "Restart aerodb-pg", .failed, -480),
        ("00000000-0000-0000-0000-000000000783", .restartServer, "Restart prod-copy-web", .succeeded, -1_020),
        ("00000000-0000-0000-0000-000000000784", .restartDocker, "Restart metrics-worker", .succeeded, -1_260),
        ("00000000-0000-0000-0000-000000000785", .restartServer, "Restart web-bug-capture", .succeeded, -1_500),
        ("00000000-0000-0000-0000-000000000786", .restartServer, "Restart read-cache-worker", .succeeded, -1_740),
    ]
    for entry in entries {
        guard let id = UUID(uuidString: entry.id) else { continue }
        let finishedAt = now.addingTimeInterval(entry.offset)
        let request = ActionRequest(
            id: id,
            kind: entry.kind,
            title: entry.title,
            origin: origin
        )
        store.actionResults[id] = RetainedActionResult(
            request: request,
            phase: entry.phase,
            queuedAt: finishedAt.addingTimeInterval(-2),
            startedAt: finishedAt.addingTimeInterval(-1),
            finishedAt: finishedAt,
            exitStatus: entry.phase == .succeeded ? 0 : 1,
            stdout: entry.phase == .succeeded ? #"{"ok":true}"# : "",
            stderr: entry.phase == .failed ? "The fixture service did not become ready." : "",
            failure: entry.phase == .failed ? "The service did not become ready." : nil
        )
    }
}

private func arguments(_ actual: [String], contain expected: [String]) -> Bool {
    guard !expected.isEmpty, expected.count <= actual.count else { return false }
    return (0...(actual.count - expected.count)).contains { start in
        Array(actual[start..<(start + expected.count)]) == expected
    }
}

@MainActor
private func waitForRetirementVisualState(
    _ label: String,
    attempts: Int = 100,
    condition: @MainActor () -> Bool
) async throws {
    for _ in 0..<attempts {
        if condition() { return }
        try await Task.sleep(for: .milliseconds(10))
    }
    throw RuntimeError("Timed out waiting for the retirement visual fixture: \(label)")
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
    let actionID: UUID

    init(store: OpsStore, fixtureRoot: URL, actionID: UUID) {
        self.store = store
        self.fixtureRoot = fixtureRoot
        self.actionID = actionID
    }

    deinit {
        try? FileManager.default.removeItem(at: fixtureRoot)
    }
}

private struct LegacyNestedVerticalScrollFixture: View {
    var body: some View {
        ScrollView(.vertical) {
            VStack(spacing: 12) {
                Color.white.opacity(0.08)
                    .frame(height: 720)
                ScrollView(.vertical) {
                    Color.white.opacity(0.12)
                        .frame(height: 620)
                }
                .frame(height: 220)
            }
        }
        .frame(width: 524, height: 760)
    }
}

private struct HorizontalOnlyScrollControlFixture: View {
    var body: some View {
        VStack(spacing: 12) {
            ScrollView(.vertical) {
                Color.white.opacity(0.08)
                    .frame(height: 900)
            }
            ScrollView(.horizontal) {
                Color.white.opacity(0.12)
                    .frame(width: 1_200, height: 80)
            }
            .frame(height: 100)
        }
        .frame(width: 524, height: 760)
    }
}

@MainActor
private func hostMainBoard(store: OpsStore, width: Int, height: Int) -> NSView {
    hostView(
        MainBoardView(store: store)
            .frame(width: CGFloat(width), height: CGFloat(height), alignment: .topLeading)
            .background(Theme.background)
            .preferredColorScheme(.dark),
        width: width,
        height: height
    )
}

@MainActor
private func hostView<Content: View>(
    _ view: Content,
    width: Int,
    height: Int
) -> NSHostingView<Content> {
    let hostingView = NSHostingView(rootView: view)
    hostingView.frame = NSRect(x: 0, y: 0, width: width, height: height)
    hostingView.layoutSubtreeIfNeeded()
    hostingView.displayIfNeeded()
    return hostingView
}

@MainActor
private func descendantViews<ViewType: NSView>(
    of type: ViewType.Type,
    in root: NSView
) -> [ViewType] {
    var matches = root is ViewType ? [root as! ViewType] : []
    for subview in root.subviews {
        matches.append(contentsOf: descendantViews(of: type, in: subview))
    }
    return matches
}

@MainActor
private func visibleVerticalScrollOwners(in root: NSView) -> [NSScrollView] {
    descendantViews(of: NSScrollView.self, in: root).filter { scrollView in
        scrollView.hasVerticalScroller
            && !isHiddenInHierarchy(scrollView, stoppingAt: root)
            && scrollView.frame.width > 1
            && scrollView.frame.height > 1
    }
}

@MainActor
private func isHiddenInHierarchy(_ view: NSView, stoppingAt root: NSView) -> Bool {
    var current: NSView? = view
    while let candidate = current {
        if candidate.isHidden || candidate.alphaValue <= 0.001 { return true }
        if candidate === root { return false }
        current = candidate.superview
    }
    return true
}

@MainActor
private func scrollTopologyDescription(_ scrollViews: [NSScrollView]) -> String {
    scrollViews.map {
        "\(String(describing: type(of: $0))) frame=\($0.frame) horizontal=\($0.hasHorizontalScroller) vertical=\($0.hasVerticalScroller)"
    }.joined(separator: "; ")
}

@MainActor
private func accessibilityObject(identifier: String, in root: NSView) -> NSObject? {
    var pending: [NSObject] = [root]
    var visited = Set<ObjectIdentifier>()
    while let object = pending.popLast() {
        guard visited.insert(ObjectIdentifier(object)).inserted else { continue }
        if accessibilityIdentifier(of: object) == identifier {
            return object
        }
        pending.append(contentsOf: accessibilityChildren(of: object))
        if let view = object as? NSView {
            pending.append(contentsOf: view.subviews)
        }
    }
    return nil
}

@MainActor
private func accessibilityIdentifier(of object: NSObject) -> String? {
    if let view = object as? NSView { return view.accessibilityIdentifier() }
    if let element = object as? NSAccessibilityElement { return element.accessibilityIdentifier() }
    return nil
}

@MainActor
private func accessibilityChildren(of object: NSObject) -> [NSObject] {
    let children: [Any]?
    if let view = object as? NSView {
        children = view.accessibilityChildren()
    } else if let element = object as? NSAccessibilityElement {
        children = element.accessibilityChildren()
    } else {
        children = nil
    }
    return children?.compactMap { $0 as? NSObject } ?? []
}

@MainActor
private func accessibilityRole(of object: NSObject) -> NSAccessibility.Role? {
    if let view = object as? NSView { return view.accessibilityRole() }
    if let element = object as? NSAccessibilityElement { return element.accessibilityRole() }
    return nil
}

@MainActor
private func accessibilityIsEnabled(_ object: NSObject) -> Bool {
    if let view = object as? NSView { return view.isAccessibilityEnabled() }
    if let element = object as? NSAccessibilityElement { return element.isAccessibilityEnabled() }
    return false
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

import Foundation

struct RepositoryLifecyclePolicy: Decodable, Hashable, Sendable, Identifiable {
    var id: String { policyID }
    let policyID: String
    let kind: String
    let immutableFingerprint: String
    let disabledValue: String?

    enum CodingKeys: String, CodingKey {
        case policyID = "policy_id"
        case kind
        case immutableFingerprint = "immutable_fingerprint"
        case disabledValue = "disabled_value"
    }
}

struct RepositoryLifecycleAllocation: Decodable, Hashable, Sendable, Identifiable {
    var id: String { allocationID }
    let allocationID: String
    let kind: String
    let immutableFingerprint: String

    enum CodingKeys: String, CodingKey {
        case allocationID = "allocation_id"
        case kind
        case immutableFingerprint = "immutable_fingerprint"
    }
}

struct RepositoryDecommissionTarget: Decodable, Hashable, Sendable, Identifiable {
    var id: String { targetID }
    let targetID: String
    let kind: String
    let hostResourceID: String
    let immutableFingerprint: String
    let observationFingerprint: String?
    let stableIdentityFingerprint: String?
    let displayName: String?
    let currentState: String?
    let policies: [RepositoryLifecyclePolicy]
    let allocations: [RepositoryLifecycleAllocation]

    enum CodingKeys: String, CodingKey {
        case targetID = "target_id"
        case kind
        case hostResourceID = "host_resource_id"
        case immutableFingerprint = "immutable_fingerprint"
        case observationFingerprint = "observation_fingerprint"
        case stableIdentityFingerprint = "stable_identity_fingerprint"
        case displayName = "display_name"
        case currentState = "current_state"
        case policies
        case allocations
    }

    var identityArguments: [String]? {
        guard let observationFingerprint = observationFingerprint?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !observationFingerprint.isEmpty
        else { return nil }
        return [
            "--resource-kind", kind,
            "--resource-id", hostResourceID,
            "--immutable-fingerprint", immutableFingerprint,
            "--association-fingerprint", observationFingerprint,
        ]
    }
}

struct RepositoryDecommissionPlan: Decodable, Hashable, Sendable, Identifiable {
    var id: String { planID }
    let schemaVersion: Int
    let kind: String
    let planID: String
    let repoID: String
    let repositoryFingerprint: String
    let installationGeneration: Int
    let fingerprint: String
    let createdAt: String
    let actor: String
    let reason: String
    let canonicalRoot: String?
    let displayName: String?
    let retainedData: [String]
    let targets: [RepositoryDecommissionTarget]
    let blockers: [String]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case kind
        case planID = "plan_id"
        case repoID = "repo_id"
        case repositoryFingerprint = "repository_fingerprint"
        case installationGeneration = "installation_generation"
        case fingerprint
        case createdAt = "created_at"
        case actor
        case reason
        case canonicalRoot = "canonical_root"
        case displayName = "display_name"
        case retainedData = "retained_data"
        case targets
        case blockers
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try values.decode(Int.self, forKey: .schemaVersion)
        kind = try values.decode(String.self, forKey: .kind)
        planID = try values.decode(String.self, forKey: .planID)
        repoID = try values.decode(String.self, forKey: .repoID)
        repositoryFingerprint = try values.decode(String.self, forKey: .repositoryFingerprint)
        installationGeneration = try values.decode(Int.self, forKey: .installationGeneration)
        fingerprint = try values.decode(String.self, forKey: .fingerprint)
        createdAt = try values.decode(String.self, forKey: .createdAt)
        actor = try values.decode(String.self, forKey: .actor)
        reason = try values.decode(String.self, forKey: .reason)
        canonicalRoot = try values.decodeIfPresent(String.self, forKey: .canonicalRoot)
        displayName = try values.decodeIfPresent(String.self, forKey: .displayName)
        retainedData = try values.decodeIfPresent([String].self, forKey: .retainedData) ?? []
        targets = try values.decodeIfPresent([RepositoryDecommissionTarget].self, forKey: .targets) ?? []
        blockers = try values.decodeIfPresent([String].self, forKey: .blockers) ?? []
    }
}

struct RepositoryLifecycleTargetResult: Decodable, Hashable, Sendable, Identifiable {
    var id: String { targetID }
    let targetID: String
    let kind: String
    let status: String
    let phase: String
    let error: RepositoryLifecycleFailure?

    enum CodingKeys: String, CodingKey {
        case targetID = "target_id"
        case kind, status, phase, error
    }
}

struct RepositoryLifecycleFailure: Decodable, Hashable, Sendable {
    let code: String?
    let message: String
    let phase: String?

    private enum CodingKeys: String, CodingKey {
        case code, message, phase
    }

    init(from decoder: Decoder) throws {
        if let value = try? decoder.singleValueContainer().decode(String.self) {
            code = nil
            message = value
            phase = nil
            return
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        code = try values.decodeIfPresent(String.self, forKey: .code)
        message = try values.decodeIfPresent(String.self, forKey: .message)
            ?? code
            ?? "Repository lifecycle operation failed"
        phase = try values.decodeIfPresent(String.self, forKey: .phase)
    }
}

struct RepositoryLifecyclePlanReference: Decodable, Hashable, Sendable {
    let planID: String
    let planFingerprint: String

    private enum CodingKeys: String, CodingKey {
        case planID = "plan_id"
        case planFingerprint = "plan_fingerprint"
    }
}

struct LifecycleCommandFailurePayload: Decodable, Hashable, Sendable {
    let error: String
    let code: String?
    let classification: String?
    let mutationPerformed: Bool?
    let priorOperationEffectsPossible: Bool?
    let recoveryScope: String?
    let replacementPlanAllowed: Bool?
    let actionRequired: String?

    private enum CodingKeys: String, CodingKey {
        case error, code, classification
        case mutationPerformed = "mutation_performed"
        case priorOperationEffectsPossible = "prior_operation_effects_possible"
        case recoveryScope = "recovery_scope"
        case replacementPlanAllowed = "replacement_plan_allowed"
        case actionRequired = "action_required"
    }

    var isPreMutationStalePlan: Bool {
        code == "lifecycle_plan_stale"
            && classification == "lifecycle_target_identity_changed"
            && mutationPerformed == false
            && priorOperationEffectsPossible != true
    }

    var isFencedResumeStalePlan: Bool {
        code == "lifecycle_fenced_resume_stale"
            && classification == "lifecycle_fenced_resume_identity_changed"
            && mutationPerformed == false
            && isFencedResumeFailure
    }

    var isFencedResumeFailure: Bool {
        priorOperationEffectsPossible == true
            && recoveryScope == "exact_confirmed_operation"
            && replacementPlanAllowed == false
    }
}

struct RepositoryLifecycleResult: Decodable, Hashable, Sendable {
    let schemaVersion: Int
    let operationID: String
    let planID: String
    let planFingerprint: String
    let kind: String
    let repoID: String?
    let resourceID: String?
    let status: String
    let fence: String
    let hidden: Bool
    let started: Bool
    let retainedData: [String]
    let targets: [RepositoryLifecycleTargetResult]
    let errors: [RepositoryLifecycleFailure]
    let confirmedPlan: RepositoryLifecyclePlanReference?
    let executionPlan: RepositoryLifecyclePlanReference?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case operationID = "operation_id"
        case planID = "plan_id"
        case planFingerprint = "plan_fingerprint"
        case kind
        case repoID = "repo_id"
        case resourceID = "resource_id"
        case status, fence, hidden, started
        case retainedData = "retained_data"
        case targets, errors
        case confirmedPlan = "confirmed_plan"
        case executionPlan = "execution_plan"
    }
}

struct RepositoryDecommissionPrompt: Identifiable, Hashable, Sendable {
    var id: String { plan.planID }
    let plan: RepositoryDecommissionPlan
    let origin: CoordinatorOrigin
    let projectPath: String
    let repositoryID: String?
}

struct ExactUnassignedResource: Identifiable, Hashable, Sendable {
    var id: String { "\(origin.id)|\(kind)|\(hostResourceID)" }
    let origin: CoordinatorOrigin
    let kind: String
    let hostResourceID: String
    let immutableFingerprint: String
    let observationFingerprint: String
    let displayName: String

    var identityArguments: [String] {
        [
            "--resource-kind", kind,
            "--resource-id", hostResourceID,
            "--immutable-fingerprint", immutableFingerprint,
            "--association-fingerprint", observationFingerprint,
        ]
    }
}

struct ResourceAttachPrompt: Identifiable, Hashable, Sendable {
    var id: String { target.id }
    let target: ExactUnassignedResource
}

struct StandaloneRetirementPlan: Decodable, Hashable, Sendable, Identifiable {
    var id: String { planID }
    let schemaVersion: Int
    let kind: String
    let planID: String
    let resourceID: String
    let fingerprint: String
    let createdAt: String
    let actor: String
    let reason: String
    let retainedData: [String]
    let targets: [RepositoryDecommissionTarget]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case kind
        case planID = "plan_id"
        case resourceID = "resource_id"
        case fingerprint
        case createdAt = "created_at"
        case actor, reason
        case retainedData = "retained_data"
        case targets
    }
}

struct ResourceRetirementPrompt: Identifiable, Hashable, Sendable {
    var id: String { plan.planID }
    let target: ExactUnassignedResource
    let plan: StandaloneRetirementPlan
    let requestProject: String
}

enum ResourceRetirementRecoveryAction: String, Hashable, Sendable {
    case refreshAndReplan
    case retryConfirmedOperation
}

struct ResourceRetirementRecoveryContext: Identifiable, Hashable, Sendable {
    var id: UUID { actionID }
    let actionID: UUID
    let prompt: ResourceRetirementPrompt
    let recoveryAction: ResourceRetirementRecoveryAction?
    let commandFailure: LifecycleCommandFailurePayload?
    let resultStatus: String?
}

struct ResourceAttachResult: Decodable, Hashable, Sendable {
    let schemaVersion: Int
    let repoID: String
    let resourceID: String
    let resourceKind: String
    let attached: Bool
    let started: Bool

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case repoID = "repo_id"
        case resourceID = "resource_id"
        case resourceKind = "resource_kind"
        case attached, started
    }
}

struct WorkerRemovalPlanDetail: Decodable, Hashable, Sendable, Identifiable {
    var id: String { "\(code ?? "detail")|\(message)" }
    let code: String?
    let message: String

    private enum CodingKeys: String, CodingKey {
        case code, message, description, effect, name, path
    }

    init(from decoder: Decoder) throws {
        if let value = try? decoder.singleValueContainer().decode(String.self) {
            code = nil
            message = value
            return
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        code = try values.decodeIfPresent(String.self, forKey: .code)
        message = try values.decodeIfPresent(String.self, forKey: .message)
            ?? values.decodeIfPresent(String.self, forKey: .description)
            ?? values.decodeIfPresent(String.self, forKey: .effect)
            ?? values.decodeIfPresent(String.self, forKey: .name)
            ?? values.decodeIfPresent(String.self, forKey: .path)
            ?? code
            ?? "Coordinator plan detail unavailable"
    }
}

struct WorkerRemovalPlan: Decodable, Hashable, Sendable, Identifiable {
    var id: String { planID }
    let planID: String
    let planFingerprint: String
    let confirmationPhrase: String
    let action: String
    let effects: [WorkerRemovalPlanDetail]
    let retained: [WorkerRemovalPlanDetail]
    let deleted: [WorkerRemovalPlanDetail]
    let blockers: [WorkerRemovalPlanDetail]
    let status: String

    enum CodingKeys: String, CodingKey {
        case planID = "plan_id"
        case planFingerprint = "plan_fingerprint"
        case fingerprint
        case confirmationPhrase = "confirmation_phrase"
        case action, effects, retained, deleted, blockers, status
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        planID = try values.decode(String.self, forKey: .planID)
        planFingerprint = try values.decodeIfPresent(String.self, forKey: .planFingerprint)
            ?? values.decode(String.self, forKey: .fingerprint)
        confirmationPhrase = try values.decodeIfPresent(String.self, forKey: .confirmationPhrase) ?? ""
        action = try values.decode(String.self, forKey: .action)
        effects = try values.decodeIfPresent([WorkerRemovalPlanDetail].self, forKey: .effects) ?? []
        retained = try values.decodeIfPresent([WorkerRemovalPlanDetail].self, forKey: .retained) ?? []
        deleted = try values.decodeIfPresent([WorkerRemovalPlanDetail].self, forKey: .deleted) ?? []
        blockers = try values.decodeIfPresent([WorkerRemovalPlanDetail].self, forKey: .blockers) ?? []
        status = try values.decodeIfPresent(String.self, forKey: .status) ?? "planned"
    }

    var isPermanent: Bool { action == "purge" || action == "forget" }
}

struct WorkerRuntimeResult: Decodable, Hashable, Sendable {
    let stage: String?
    let plan: WorkerRemovalPlan?
    let lifecycle: WorkerRuntimeLifecycleResult?
    let nextAction: String?

    enum CodingKeys: String, CodingKey {
        case stage, plan, lifecycle
        case nextAction = "next_action"
    }
}

struct WorkerRuntimeLifecycleResult: Decodable, Hashable, Sendable {
    let ok: Bool?
    let action: String?
    let status: String?
}

struct WorkerRuntimeEnvelope: Decodable, Hashable, Sendable {
    let schemaVersion: Int
    let ok: Bool
    let action: String
    let classification: String
    let target: WorkerRuntimeTarget
    let result: WorkerRuntimeResult
    let error: String?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case ok, action, classification, target, result, error
    }
}

struct WorkerRuntimeTarget: Decodable, Hashable, Sendable {
    let kind: String
    let id: String?
    let name: String?
}

struct WorkerRemovalPrompt: Identifiable, Hashable, Sendable {
    var id: String { plan.planID }
    let serverID: String
    let serverName: String
    let origin: CoordinatorOrigin
    let context: RepositoryExecutionContext
    let plan: WorkerRemovalPlan
    let archivedInThisJourney: Bool
}

func repositoryRetainedDataLabel(_ value: String) -> String {
    switch value {
    case "repository_files": return "Repository files"
    case "containers": return "Container definitions"
    case "volumes": return "Docker volumes"
    case "databases": return "Database data"
    case "backups": return "Backups"
    case "audit_history": return "Operation history"
    default:
        return value.replacingOccurrences(of: "_", with: " ").capitalized
    }
}

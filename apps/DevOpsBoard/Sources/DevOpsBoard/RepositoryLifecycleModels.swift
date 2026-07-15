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
    let controlBindingID: String
    let displayName: String?
    let currentState: String?
    let policies: [RepositoryLifecyclePolicy]
    let allocations: [RepositoryLifecycleAllocation]

    enum CodingKeys: String, CodingKey {
        case targetID = "target_id"
        case kind
        case hostResourceID = "host_resource_id"
        case immutableFingerprint = "immutable_fingerprint"
        case controlBindingID = "control_binding_id"
        case displayName = "display_name"
        case currentState = "current_state"
        case policies
        case allocations
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
    let controlBindingID: String
    let ownershipFingerprint: String
    let displayName: String

    var identityArguments: [String] {
        [
            "--resource-kind", kind,
            "--resource-id", hostResourceID,
            "--immutable-fingerprint", immutableFingerprint,
            "--control-binding-id", controlBindingID,
            "--ownership-fingerprint", ownershipFingerprint,
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

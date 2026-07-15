import Foundation

/// Authoritative inventory consumed by DevOps Board. The coordinator may
/// still emit a v1 compatibility object for external callers, but this model
/// deliberately has no keys for that projection (or its duplicated top-level
/// fields), so neither project identity nor action routing can fall back to it.
struct NormalizedInventoryGraph: Decodable, Sendable {
    let schemaVersion: Int
    let store: NormalizedStoreMetadata
    let repositories: [NormalizedRepository]
    let coordinatorSources: [NormalizedCoordinatorSource]
    let dockerEngines: [NormalizedDockerEngine]
    let memberships: [NormalizedMembership]
    let resources: NormalizedResources
    let leases: [NormalizedLease]
    let portAssignments: [NormalizedPortAssignment]
    let backupEvidence: [NormalizedBackupEvidence]
    let databaseBackups: [NormalizedDatabaseBackup]
    let databaseRestoreEvents: [NormalizedDatabaseRestoreEvent]
    let events: [NormalizedEvent]
    let unassignedResources: [NormalizedUnassignedResource]
    let lifecycleViolations: [NormalizedUnassignedResource]
    let observations: NormalizedObservations
    let controlBindings: [NormalizedControlBinding]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case store, repositories, memberships, resources, leases, events, observations
        case coordinatorSources = "coordinator_sources"
        case dockerEngines = "docker_engines"
        case portAssignments = "port_assignments"
        case backupEvidence = "backup_evidence"
        case databaseBackups = "database_backups"
        case databaseRestoreEvents = "database_restore_events"
        case unassignedResources = "unassigned_resources"
        case lifecycleViolations = "lifecycle_violations"
        case controlBindings = "control_bindings"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try values.decode(Int.self, forKey: .schemaVersion)
        guard schemaVersion == 2 else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: values,
                debugDescription: "DevOps Board requires normalized inventory schema version 2"
            )
        }
        // These six collections are the minimum normalized identity graph.
        // Requiring them makes a v1-only payload fail closed even if it labels
        // itself schema 2.
        store = try values.decode(NormalizedStoreMetadata.self, forKey: .store)
        repositories = try values.decode([NormalizedRepository].self, forKey: .repositories)
        memberships = try values.decode([NormalizedMembership].self, forKey: .memberships)
        resources = try values.decode(NormalizedResources.self, forKey: .resources)
        unassignedResources = try values.decode(
            [NormalizedUnassignedResource].self,
            forKey: .unassignedResources
        )
        observations = try values.decode(NormalizedObservations.self, forKey: .observations)
        controlBindings = try values.decode(
            [NormalizedControlBinding].self,
            forKey: .controlBindings
        )
        coordinatorSources = try values.decodeIfPresent(
            [NormalizedCoordinatorSource].self,
            forKey: .coordinatorSources
        ) ?? []
        dockerEngines = try values.decodeIfPresent(
            [NormalizedDockerEngine].self,
            forKey: .dockerEngines
        ) ?? []
        leases = try values.decodeIfPresent([NormalizedLease].self, forKey: .leases) ?? []
        portAssignments = try values.decodeIfPresent(
            [NormalizedPortAssignment].self,
            forKey: .portAssignments
        ) ?? []
        backupEvidence = try values.decodeIfPresent(
            [NormalizedBackupEvidence].self,
            forKey: .backupEvidence
        ) ?? []
        databaseBackups = try values.decodeIfPresent(
            [NormalizedDatabaseBackup].self,
            forKey: .databaseBackups
        ) ?? []
        databaseRestoreEvents = try values.decodeIfPresent(
            [NormalizedDatabaseRestoreEvent].self,
            forKey: .databaseRestoreEvents
        ) ?? []
        events = try values.decodeIfPresent([NormalizedEvent].self, forKey: .events) ?? []
        lifecycleViolations = try values.decodeIfPresent(
            [NormalizedUnassignedResource].self,
            forKey: .lifecycleViolations
        ) ?? []
    }
}

struct NormalizedStoreMetadata: Decodable, Sendable {
    let databaseGeneration: String?
    let stateRevision: Int
    let observationRevision: Int
    let authorityMode: String
    let migrationState: String
    let updatedAt: String?

    enum CodingKeys: String, CodingKey {
        case databaseGeneration = "database_generation"
        case stateRevision = "state_revision"
        case observationRevision = "observation_revision"
        case authorityMode = "authority_mode"
        case migrationState = "migration_state"
        case updatedAt = "updated_at"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        databaseGeneration = try values.decodeIfPresent(String.self, forKey: .databaseGeneration)
        stateRevision = try values.decodeIfPresent(Int.self, forKey: .stateRevision) ?? 0
        observationRevision = try values.decodeIfPresent(Int.self, forKey: .observationRevision) ?? 0
        authorityMode = try values.decodeIfPresent(String.self, forKey: .authorityMode) ?? "sqlite"
        migrationState = try values.decodeIfPresent(String.self, forKey: .migrationState) ?? "unknown"
        updatedAt = try values.decodeIfPresent(String.self, forKey: .updatedAt)
    }
}

struct NormalizedRepository: Decodable, Sendable {
    let repoID: String
    let hostID: String
    let canonicalRoot: String
    let displayName: String
    let state: String
    let generation: Int
    let installationStatus: String
    let startupFenced: Bool
    let installationGeneration: Int

    enum CodingKeys: String, CodingKey {
        case repoID = "repo_id"
        case hostID = "host_id"
        case canonicalRoot = "canonical_root"
        case displayName = "display_name"
        case state, generation
        case installationStatus = "installation_status"
        case startupFenced = "startup_fenced"
        case installationGeneration = "installation_generation"
    }
}

struct NormalizedCoordinatorSource: Decodable, Sendable {
    let sourceID: String
    let canonicalHome: String
    let effectiveUID: Int
    let status: String

    enum CodingKeys: String, CodingKey {
        case sourceID = "source_id"
        case canonicalHome = "canonical_home"
        case effectiveUID = "effective_uid"
        case status
    }
}

struct NormalizedDockerEngine: Decodable, Sendable {
    let engineID: String
    let hostID: String
    let capabilityState: String

    enum CodingKeys: String, CodingKey {
        case engineID = "engine_id"
        case hostID = "host_id"
        case capabilityState = "capability_state"
    }
}

struct NormalizedMembership: Decodable, Sendable {
    let membershipID: String
    let repoID: String
    let resourceKind: String
    let hostResourceID: String
    let immutableFingerprint: String
    let controlBindingID: String?

    enum CodingKeys: String, CodingKey {
        case membershipID = "membership_id"
        case repoID = "repo_id"
        case resourceKind = "resource_kind"
        case hostResourceID = "host_resource_id"
        case immutableFingerprint = "immutable_fingerprint"
        case controlBindingID = "control_binding_id"
    }
}

struct NormalizedControlBinding: Decodable, Sendable {
    let bindingID: String
    let repoID: String?
    let sourceResourceID: String?
    let resourceKind: String
    let resourceID: String
    let sourceID: String
    let capability: String
    let provenance: String
    let authorityState: String
    let priority: Int
    let generation: Int

    enum CodingKeys: String, CodingKey {
        case bindingID = "binding_id"
        case repoID = "repo_id"
        case sourceResourceID = "source_resource_id"
        case resourceKind = "resource_kind"
        case resourceID = "resource_id"
        case sourceID = "source_id"
        case capability, provenance
        case authorityState = "authority_state"
        case priority, generation
    }
}

struct NormalizedResources: Decodable, Sendable {
    let servers: [NormalizedServerDefinition]
    let docker: [NormalizedDockerResource]
    let dockerPorts: [NormalizedDockerPort]
    let databases: [NormalizedDatabaseBinding]

    enum CodingKeys: String, CodingKey {
        case servers, docker, databases
        case dockerPorts = "docker_ports"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        servers = try values.decode([NormalizedServerDefinition].self, forKey: .servers)
        docker = try values.decode([NormalizedDockerResource].self, forKey: .docker)
        dockerPorts = try values.decodeIfPresent([NormalizedDockerPort].self, forKey: .dockerPorts) ?? []
        databases = try values.decodeIfPresent([NormalizedDatabaseBinding].self, forKey: .databases) ?? []
    }
}

struct NormalizedServerDefinition: Decodable, Sendable {
    let serverDefinitionID: String
    let repoID: String
    let name: String
    let role: String?
    let cwd: String
    let healthURLTemplate: String?
    let logPath: String?
    let definitionFingerprint: String
    let generation: Int
    let arguments: [String]

    enum CodingKeys: String, CodingKey {
        case serverDefinitionID = "server_definition_id"
        case repoID = "repo_id"
        case name, role, cwd, generation, arguments
        case healthURLTemplate = "health_url_template"
        case logPath = "log_path"
        case definitionFingerprint = "definition_fingerprint"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        serverDefinitionID = try values.decode(String.self, forKey: .serverDefinitionID)
        repoID = try values.decode(String.self, forKey: .repoID)
        name = try values.decode(String.self, forKey: .name)
        role = try values.decodeIfPresent(String.self, forKey: .role)
        cwd = try values.decode(String.self, forKey: .cwd)
        healthURLTemplate = try values.decodeIfPresent(String.self, forKey: .healthURLTemplate)
        logPath = try values.decodeIfPresent(String.self, forKey: .logPath)
        definitionFingerprint = try values.decode(String.self, forKey: .definitionFingerprint)
        generation = try values.decodeIfPresent(Int.self, forKey: .generation) ?? 0
        arguments = try values.decodeIfPresent([String].self, forKey: .arguments) ?? []
    }
}

struct NormalizedDockerResource: Decodable, Sendable {
    let dockerResourceID: String
    let engineID: String
    let fullContainerID: String
    let currentName: String
    let image: String?
    let createdAt: String
    let updatedAt: String

    enum CodingKeys: String, CodingKey {
        case dockerResourceID = "docker_resource_id"
        case engineID = "engine_id"
        case fullContainerID = "full_container_id"
        case currentName = "current_name"
        case image
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

struct NormalizedDockerPort: Decodable, Sendable {
    let dockerResourceID: String
    let ordinal: Int
    let hostAddress: String?
    let hostPort: Int?
    let containerPort: Int
    let `protocol`: String

    enum CodingKeys: String, CodingKey {
        case dockerResourceID = "docker_resource_id"
        case ordinal
        case hostAddress = "host_address"
        case hostPort = "host_port"
        case containerPort = "container_port"
        case `protocol`
    }
}

struct NormalizedDatabaseBinding: Decodable, Sendable {
    let databaseBindingID: String
    let dockerResourceID: String
    let repoID: String?
    let databaseName: String
    let engineKind: String
    let createdAt: String
    let updatedAt: String

    enum CodingKeys: String, CodingKey {
        case databaseBindingID = "database_binding_id"
        case dockerResourceID = "docker_resource_id"
        case repoID = "repo_id"
        case databaseName = "database_name"
        case engineKind = "engine_kind"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

struct NormalizedObservations: Decodable, Sendable {
    let servers: [NormalizedServerObservation]
    let docker: [NormalizedDockerObservation]
    let databases: [NormalizedDatabaseObservation]
    let telemetry: [NormalizedTelemetrySample]
    let snapshots: [NormalizedObservationSnapshot]

    enum CodingKeys: String, CodingKey { case servers, docker, databases, telemetry, snapshots }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        servers = try values.decode([NormalizedServerObservation].self, forKey: .servers)
        docker = try values.decode([NormalizedDockerObservation].self, forKey: .docker)
        databases = try values.decodeIfPresent(
            [NormalizedDatabaseObservation].self,
            forKey: .databases
        ) ?? []
        telemetry = try values.decodeIfPresent([NormalizedTelemetrySample].self, forKey: .telemetry) ?? []
        snapshots = try values.decode([NormalizedObservationSnapshot].self, forKey: .snapshots)
    }
}

struct NormalizedDatabaseObservation: Decodable, Sendable {
    let databaseBindingID: String
    let dockerResourceID: String
    let available: Int
    let sizeBytes: Int64?
    let errorCode: String?
    let errorMessage: String?
    let sampledAt: String
    let observationFingerprint: String

    enum CodingKeys: String, CodingKey {
        case databaseBindingID = "database_binding_id"
        case dockerResourceID = "docker_resource_id"
        case available
        case sizeBytes = "size_bytes"
        case errorCode = "error_code"
        case errorMessage = "error_message"
        case sampledAt = "sampled_at"
        case observationFingerprint = "observation_fingerprint"
    }
}

struct NormalizedServerObservation: Decodable, Sendable {
    let serverDefinitionID: String
    let sourceResourceID: String?
    let lifecycle: String
    let pid: Int?
    let processStartTime: String?
    let processFingerprint: String?
    let listenerHost: String?
    let listenerPort: Int?
    let listenerObservable: Int?
    let healthClassification: String?
    let healthOK: Int?
    let stoppedAt: String?
    let stoppedReason: String?
    let sampledAt: String

    enum CodingKeys: String, CodingKey {
        case serverDefinitionID = "server_definition_id"
        case sourceResourceID = "source_resource_id"
        case lifecycle, pid
        case processStartTime = "process_start_time"
        case processFingerprint = "process_fingerprint"
        case listenerHost = "listener_host"
        case listenerPort = "listener_port"
        case listenerObservable = "listener_observable"
        case healthClassification = "health_classification"
        case healthOK = "health_ok"
        case stoppedAt = "stopped_at"
        case stoppedReason = "stopped_reason"
        case sampledAt = "sampled_at"
    }
}

struct NormalizedDockerObservation: Decodable, Sendable {
    let dockerResourceID: String
    let lifecycle: String
    let health: String?
    let restartPolicy: String?
    let sampledAt: String

    enum CodingKeys: String, CodingKey {
        case dockerResourceID = "docker_resource_id"
        case lifecycle, health
        case restartPolicy = "restart_policy"
        case sampledAt = "sampled_at"
    }
}

struct NormalizedTelemetrySample: Decodable, Sendable {
    let sampleID: String
    let hostResourceKind: String
    let hostResourceID: String
    let sampledAt: String
    let cpuPercent: Double?
    let memoryBytes: Int64?
    let networkRxBytes: Int64?
    let networkTxBytes: Int64?
    let blockReadBytes: Int64?
    let blockWriteBytes: Int64?

    enum CodingKeys: String, CodingKey {
        case sampleID = "sample_id"
        case hostResourceKind = "host_resource_kind"
        case hostResourceID = "host_resource_id"
        case sampledAt = "sampled_at"
        case cpuPercent = "cpu_percent"
        case memoryBytes = "memory_bytes"
        case networkRxBytes = "network_rx_bytes"
        case networkTxBytes = "network_tx_bytes"
        case blockReadBytes = "block_read_bytes"
        case blockWriteBytes = "block_write_bytes"
    }
}

struct NormalizedObservationSnapshot: Decodable, Sendable {
    let snapshotID: String
    let hostID: String
    let observerDomain: String
    let status: String
    let startedAt: String
    let completedAt: String?
    let errorCode: String?
    let errorMessage: String?

    enum CodingKeys: String, CodingKey {
        case snapshotID = "snapshot_id"
        case hostID = "host_id"
        case observerDomain = "observer_domain"
        case status
        case startedAt = "started_at"
        case completedAt = "completed_at"
        case errorCode = "error_code"
        case errorMessage = "error_message"
    }
}

struct NormalizedLease: Decodable, Sendable {
    let leaseID: String
    let repoID: String
    let serverDefinitionID: String?
    let sourceID: String?
    let port: Int
    let owner: String?
    let agent: String?
    let purpose: String?
    let status: String
    let expiresAt: String?

    enum CodingKeys: String, CodingKey {
        case leaseID = "lease_id"
        case repoID = "repo_id"
        case serverDefinitionID = "server_definition_id"
        case sourceID = "source_id"
        case port, owner, agent, purpose, status
        case expiresAt = "expires_at"
    }
}

struct NormalizedPortAssignment: Decodable, Sendable {
    let assignmentID: String
    let repoID: String
    let serverName: String
    let port: Int
    let status: String

    enum CodingKeys: String, CodingKey {
        case assignmentID = "assignment_id"
        case repoID = "repo_id"
        case serverName = "server_name"
        case port, status
    }
}

struct NormalizedBackupEvidence: Decodable, Sendable {
    let backupID: String
    let repoID: String?
    let sourceID: String?
    let manifestPath: String
    let manifestSHA256: String
    let verificationStatus: String
    let createdAt: String
    let verifiedAt: String?

    enum CodingKeys: String, CodingKey {
        case backupID = "backup_id"
        case repoID = "repo_id"
        case sourceID = "source_id"
        case manifestPath = "manifest_path"
        case manifestSHA256 = "manifest_sha256"
        case verificationStatus = "verification_status"
        case createdAt = "created_at"
        case verifiedAt = "verified_at"
    }
}

/// Durable, actionable backup registry. `backup_evidence` above is migration
/// diagnostics and must never be projected as a restore choice.
struct NormalizedDatabaseBackup: Decodable, Sendable {
    let databaseBackupID: String
    let databaseBindingID: String?
    let dockerResourceID: String?
    let repoID: String?
    let sourceID: String?
    let scope: String
    let sourceContainerID: String
    let sourceDatabaseName: String?
    let sourceIdentityFingerprint: String
    let artifactPath: String
    let artifactSizeBytes: Int64
    let artifactSHA256: String
    let manifestPath: String
    let manifestSHA256: String
    let backupFormat: String
    let verificationStatus: String
    let verificationMode: String?
    let createdAt: String
    let verifiedAt: String?
    let status: String
    let lastRestoredAt: String?
    let restoreCount: Int
    let updatedAt: String

    enum CodingKeys: String, CodingKey {
        case databaseBackupID = "database_backup_id"
        case databaseBindingID = "database_binding_id"
        case dockerResourceID = "docker_resource_id"
        case repoID = "repo_id"
        case sourceID = "source_id"
        case scope
        case sourceContainerID = "source_container_id"
        case sourceDatabaseName = "source_database_name"
        case sourceIdentityFingerprint = "source_identity_fingerprint"
        case artifactPath = "artifact_path"
        case artifactSizeBytes = "artifact_size_bytes"
        case artifactSHA256 = "artifact_sha256"
        case manifestPath = "manifest_path"
        case manifestSHA256 = "manifest_sha256"
        case backupFormat = "backup_format"
        case verificationStatus = "verification_status"
        case verificationMode = "verification_mode"
        case createdAt = "created_at"
        case verifiedAt = "verified_at"
        case status
        case lastRestoredAt = "last_restored_at"
        case restoreCount = "restore_count"
        case updatedAt = "updated_at"
    }
}

struct NormalizedDatabaseRestoreEvent: Decodable, Sendable {
    let restoreEventID: String
    let databaseBackupID: String
    let targetDatabaseBindingID: String?
    let targetDockerResourceID: String?
    let targetContainerID: String
    let targetDatabaseName: String
    let artifactSHA256: String
    let safetyDatabaseBackupID: String?
    let resultFingerprint: String
    let restoredAt: String

    enum CodingKeys: String, CodingKey {
        case restoreEventID = "restore_event_id"
        case databaseBackupID = "database_backup_id"
        case targetDatabaseBindingID = "target_database_binding_id"
        case targetDockerResourceID = "target_docker_resource_id"
        case targetContainerID = "target_container_id"
        case targetDatabaseName = "target_database_name"
        case artifactSHA256 = "artifact_sha256"
        case safetyDatabaseBackupID = "safety_database_backup_id"
        case resultFingerprint = "result_fingerprint"
        case restoredAt = "restored_at"
    }
}

struct NormalizedEvent: Decodable, Sendable {
    let eventID: String
    let repoID: String?
    let sourceID: String?
    let eventKind: String
    let code: String?
    let message: String?
    let occurredAt: String

    enum CodingKeys: String, CodingKey {
        case eventID = "event_id"
        case repoID = "repo_id"
        case sourceID = "source_id"
        case eventKind = "event_kind"
        case code, message
        case occurredAt = "occurred_at"
    }
}

struct NormalizedUnassignedResource: Decodable, Sendable {
    let unassignedID: String
    let resourceKind: String
    let resourceID: String
    let displayName: String
    let reasonCode: AttributionReasonCode
    let explanation: String
    let observedBy: [String]
    let controller: String?
    let hostResourceID: String?
    let immutableFingerprint: String?
    let controlBindingID: String?
    let ownershipFingerprint: String?
    let canAttach: Bool
    let canRetire: Bool
    let lifecycleViolation: Bool
    let recommendedNextStep: String?

    enum CodingKeys: String, CodingKey {
        case unassignedID = "unassigned_id"
        case resourceKind = "resource_kind"
        case resourceID = "resource_id"
        case displayName = "display_name"
        case reasonCode = "reason_code"
        case explanation
        case observedBy = "observed_by"
        case controller
        case hostResourceID = "host_resource_id"
        case immutableFingerprint = "immutable_fingerprint"
        case controlBindingID = "control_binding_id"
        case ownershipFingerprint = "ownership_fingerprint"
        case canAttach = "can_attach"
        case canRetire = "can_retire"
        case lifecycleViolation = "lifecycle_violation"
        case recommendedNextStep = "recommended_next_step"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        unassignedID = try values.decode(String.self, forKey: .unassignedID)
        resourceKind = try values.decode(String.self, forKey: .resourceKind)
        resourceID = try values.decode(String.self, forKey: .resourceID)
        displayName = try values.decode(String.self, forKey: .displayName)
        reasonCode = try values.decodeIfPresent(AttributionReasonCode.self, forKey: .reasonCode) ?? .unknown
        explanation = try values.decodeIfPresent(String.self, forKey: .explanation) ?? reasonCode.title
        observedBy = try values.decodeIfPresent([String].self, forKey: .observedBy) ?? []
        controller = try values.decodeIfPresent(String.self, forKey: .controller)
        hostResourceID = try values.decodeIfPresent(String.self, forKey: .hostResourceID)
        immutableFingerprint = try values.decodeIfPresent(String.self, forKey: .immutableFingerprint)
        controlBindingID = try values.decodeIfPresent(String.self, forKey: .controlBindingID)
        ownershipFingerprint = try values.decodeIfPresent(String.self, forKey: .ownershipFingerprint)
        canAttach = try values.decodeIfPresent(Bool.self, forKey: .canAttach) ?? false
        canRetire = try values.decodeIfPresent(Bool.self, forKey: .canRetire) ?? false
        lifecycleViolation = try values.decodeIfPresent(Bool.self, forKey: .lifecycleViolation) ?? false
        recommendedNextStep = try values.decodeIfPresent(String.self, forKey: .recommendedNextStep)
    }

    var attribution: ResourceAttribution {
        ResourceAttribution(
            reasonCode: reasonCode,
            explanation: explanation,
            observedBy: observedBy,
            controller: controller,
            hostResourceID: hostResourceID ?? resourceID,
            immutableFingerprint: immutableFingerprint,
            controlBindingID: controlBindingID,
            ownershipFingerprint: ownershipFingerprint,
            canAttach: canAttach,
            canRetire: canRetire,
            lifecycleViolation: lifecycleViolation,
            recommendedNextStep: recommendedNextStep
        )
    }
}

struct NormalizedBoardProjection: Sendable {
    let inventory: Inventory
    let catalog: RepositoryCatalog
}

extension NormalizedInventoryGraph {
    func boardProjection(origin: CoordinatorOrigin) throws -> NormalizedBoardProjection {
        let repositoriesByID = try validatedRepositories()
        let bindingsByID = Dictionary(uniqueKeysWithValues: controlBindings.map { ($0.bindingID, $0) })
        let membershipsByRepository = Dictionary(grouping: memberships) { $0.repoID }
        let serverObservations = Dictionary(uniqueKeysWithValues: observations.servers.map {
            ($0.serverDefinitionID, $0)
        })
        let dockerObservations = Dictionary(uniqueKeysWithValues: observations.docker.map {
            ($0.dockerResourceID, $0)
        })
        let databaseObservations = Dictionary(uniqueKeysWithValues: observations.databases.map {
            ($0.databaseBindingID, $0)
        })
        let telemetryByResource = Dictionary(grouping: observations.telemetry) { sample in
            "\(sample.hostResourceKind)|\(sample.hostResourceID)"
        }
        let assignmentsByServer = Dictionary(
            uniqueKeysWithValues: portAssignments.filter { $0.status == "active" }.map {
                ("\($0.repoID)|\($0.serverName)", $0)
            }
        )
        let leasesByServer = Dictionary(
            grouping: leases.compactMap { lease in
                lease.serverDefinitionID.map { ($0, lease) }
            },
            by: { $0.0 }
        )
        let portsByDocker = Dictionary(grouping: resources.dockerPorts) { $0.dockerResourceID }
        var violations: [String: NormalizedUnassignedResource] = [:]
        for item in unassignedResources + lifecycleViolations {
            violations["\(item.resourceKind)|\(item.resourceID)"] = item
        }

        func authoritative(_ membership: NormalizedMembership) -> Bool {
            guard let bindingID = membership.controlBindingID,
                  let binding = bindingsByID[bindingID]
            else { return false }
            return binding.repoID == membership.repoID
                && binding.resourceKind == membership.resourceKind
                && binding.resourceID == membership.hostResourceID
                && binding.authorityState == "authoritative"
                && coordinatorSources.contains { $0.sourceID == binding.sourceID }
        }

        var serversByRepository: [String: [RepositoryManagedServer]] = [:]
        var serverPresentations: [ManagedServer] = []
        for definition in resources.servers {
            guard let repository = repositoriesByID[definition.repoID] else { continue }
            let membership = memberships.first {
                $0.repoID == definition.repoID
                    && $0.resourceKind == "server"
                    && $0.hostResourceID == definition.serverDefinitionID
            }
            let actionable = membership.map(authoritative) == true
            let observation = serverObservations[definition.serverDefinitionID]
            let violation = violations["server|\(definition.serverDefinitionID)"]
            let server = normalizedServerPresentation(
                definition: definition,
                observation: observation,
                telemetry: telemetryByResource["server|\(definition.serverDefinitionID)"] ?? [],
                assignment: assignmentsByServer["\(definition.repoID)|\(definition.name)"],
                lease: leasesByServer[definition.serverDefinitionID]?
                    .map(\.1)
                    .first(where: { $0.status == "active" }),
                repository: repository,
                origin: origin,
                actionable: actionable,
                attribution: violation?.attribution
            )
            serverPresentations.append(server)
            let sourceIdentity = ResourceIdentity(
                origin: origin,
                kind: .server,
                nativeID: definition.serverDefinitionID
            )
            let logical = RepositoryLogicalServerIdentity(
                repository: RepositoryIdentity(
                    repoID: repository.repoID,
                    canonicalRoot: repository.canonicalRoot,
                    displayName: repository.displayName
                ),
                serviceName: definition.name
            )
            serversByRepository[definition.repoID, default: []].append(
                RepositoryManagedServer(
                    identity: logical,
                    representative: server,
                    observations: [RepositoryServerObservation(sourceIdentity: sourceIdentity, server: server)],
                    conflict: nil,
                    membershipConflicts: [],
                    controlCandidates: actionable ? [origin] : [],
                    actionOrigin: actionable ? origin : nil
                )
            )
        }

        var dockerByRepository: [String: [RepositoryDockerResource]] = [:]
        var dockerPresentations: [String: DockerContainer] = [:]
        for resource in resources.docker {
            let membership = memberships.first {
                $0.resourceKind == "container" && $0.hostResourceID == resource.dockerResourceID
            }
            let repository = membership.flatMap { repositoriesByID[$0.repoID] }
            let actionable = membership.map(authoritative) == true
            let violation = violations["container|\(resource.dockerResourceID)"]
            let container = normalizedDockerPresentation(
                resource: resource,
                observation: dockerObservations[resource.dockerResourceID],
                ports: portsByDocker[resource.dockerResourceID] ?? [],
                telemetry: telemetryByResource["docker|\(resource.dockerResourceID)"] ?? [],
                repository: repository,
                origin: origin,
                actionable: actionable,
                metadataSource: membership?.controlBindingID
                    .flatMap { bindingsByID[$0]?.provenance },
                attribution: violation?.attribution
            )
            dockerPresentations[resource.dockerResourceID] = container
            guard let membership, let repository else { continue }
            let identity = RepositoryIdentity(
                repoID: repository.repoID,
                canonicalRoot: repository.canonicalRoot,
                displayName: repository.displayName
            )
            let physicalIdentity = RepositoryDockerIdentity(
                rawValue: resource.dockerResourceID,
                isImmutable: true
            )
            dockerByRepository[membership.repoID, default: []].append(
                RepositoryDockerResource(
                    identity: physicalIdentity,
                    representative: container,
                    observations: [
                        RepositoryDockerObservation(
                            sourceIdentity: ResourceIdentity(
                                origin: origin,
                                kind: .docker,
                                nativeID: resource.dockerResourceID
                            ),
                            container: container
                        )
                    ],
                    repositoryCandidates: [identity],
                    membershipError: actionable ? nil : container.ownershipError,
                    controlCandidates: actionable ? [origin] : []
                )
            )
        }

        var databasePresentations: [DockerContainer] = []
        for database in resources.databases {
            guard var container = dockerPresentations[database.dockerResourceID] else { continue }
            let observation = databaseObservations[database.databaseBindingID]
            container.database = database.databaseName
            container.databaseSizeBytes = observation?.available == 1 ? observation?.sizeBytes : nil
            if let observation, observation.available != 1 {
                container.databaseDiscoveryError = observation.errorMessage
                    ?? observation.errorCode
                    ?? "The normalized database observer reported this database unavailable."
            } else if observation == nil {
                container.databaseDiscoveryError = "No normalized database observation is available."
            } else {
                container.databaseDiscoveryError = nil
            }
            if let repository = database.repoID.flatMap({ repositoriesByID[$0] }) {
                container.project = repository.canonicalRoot
            }
            databasePresentations.append(container)
        }

        let databaseBindingsByID = Dictionary(uniqueKeysWithValues: resources.databases.map {
            ($0.databaseBindingID, $0)
        })
        let dockerResourcesByID = Dictionary(uniqueKeysWithValues: resources.docker.map {
            ($0.dockerResourceID, $0)
        })
        let backups = databaseBackups.compactMap { backup -> DatabaseBackup? in
            guard backup.scope == "database",
                  let databaseBindingID = backup.databaseBindingID,
                  let dockerResourceID = backup.dockerResourceID,
                  let sourceDatabaseName = backup.sourceDatabaseName,
                  let binding = databaseBindingsByID[databaseBindingID],
                  binding.dockerResourceID == dockerResourceID,
                  binding.databaseName == sourceDatabaseName,
                  let docker = dockerResourcesByID[dockerResourceID]
            else { return nil }
            var projected = DatabaseBackup(
                path: backup.artifactPath,
                size: Int(exactly: backup.artifactSizeBytes),
                modifiedAt: backup.updatedAt,
                manifest: backup.manifestPath,
                database: sourceDatabaseName,
                container: docker.currentName,
                format: backup.backupFormat,
                sha256: backup.artifactSHA256,
                normalizedBackupID: backup.databaseBackupID,
                immutableContainerID: backup.sourceContainerID,
                normalizedScope: backup.scope,
                normalizedVerificationStatus: backup.verificationStatus,
                normalizedVerificationMode: backup.verificationMode,
                normalizedRegistryStatus: backup.status,
                normalizedCreatedAt: backup.createdAt,
                databaseBindingID: databaseBindingID,
                dockerResourceID: dockerResourceID
            )
            projected.origin = origin
            return projected
        }

        var aggregates: [RepositoryAggregate] = []
        for repository in repositories.sorted(by: {
            ($0.displayName.lowercased(), $0.canonicalRoot) < ($1.displayName.lowercased(), $1.canonicalRoot)
        }) {
            let identity = RepositoryIdentity(
                repoID: repository.repoID,
                canonicalRoot: repository.canonicalRoot,
                displayName: repository.displayName
            )
            let servers = (serversByRepository[repository.repoID] ?? []).sorted { $0.id < $1.id }
            let docker = (dockerByRepository[repository.repoID] ?? []).sorted { $0.id < $1.id }
            let repoMemberships = membershipsByRepository[repository.repoID] ?? []
            let repositoryDockerResourceIDs = resources.docker.compactMap { resource -> String? in
                let hasRepositoryControlBinding = controlBindings.contains {
                    $0.repoID == repository.repoID
                        && $0.resourceKind == "container"
                        && $0.resourceID == resource.dockerResourceID
                }
                let hasRepositoryDatabaseBinding = resources.databases.contains {
                    $0.repoID == repository.repoID
                        && $0.dockerResourceID == resource.dockerResourceID
                }
                return hasRepositoryControlBinding || hasRepositoryDatabaseBinding
                    ? resource.dockerResourceID
                    : nil
            }
            let requiredMembershipKeys = Set(
                resources.servers
                    .filter { $0.repoID == repository.repoID }
                    .map { "server|\($0.serverDefinitionID)" }
                + repositoryDockerResourceIDs.map { "container|\($0)" }
            )
            let presentMembershipKeys = Set(
                repoMemberships.map { "\($0.resourceKind)|\($0.hostResourceID)" }
            )
            // allSatisfy alone is vacuously true when a definition's
            // membership is absent. Whole-project control requires both a
            // complete definition-to-membership mapping and authoritative
            // control for every membership in the repository.
            let fullyControlled = requiredMembershipKeys.isSubset(of: presentMembershipKeys)
                && repoMemberships.allSatisfy(authoritative)
            let usage = normalizedRepositoryUsage(
                serverIDs: servers.map { $0.representative.coordinatorID ?? $0.representative.id },
                docker: docker.map(\.representative),
                serverTelemetry: servers.flatMap { server in
                    telemetryByResource["server|\(server.representative.coordinatorID ?? server.representative.id)"] ?? []
                }
            )
            var usageRow = ProjectUsage(
                usageKey: "repo:\(repository.repoID)",
                project: repository.canonicalRoot,
                projectKey: repository.repoID,
                name: repository.displayName,
                serverIDs: servers.map { $0.representative.coordinatorID ?? $0.representative.id },
                containerNames: docker.compactMap { $0.representative.name },
                serverCount: usage.serverCount,
                containerCount: usage.containerCount,
                processCount: usage.processCount,
                cpuPercent: usage.cpuPercent,
                memoryBytes: usage.memoryBytes,
                processCPUPercent: nil,
                processMemoryBytes: nil,
                dockerCPUPercent: nil,
                dockerMemoryBytes: nil,
                processes: nil,
                hotProcesses: usage.hotProcesses
            )
            usageRow.origin = origin
            aggregates.append(
                RepositoryAggregate(
                    identity: identity,
                    observedLabels: [repository.displayName],
                    sourceObservations: [
                        RepositorySourceObservation(
                            repository: identity,
                            origin: origin,
                            displayLabels: [repository.displayName],
                            usageRows: [usageRow],
                            serverIdentities: servers.map { $0.observations[0].sourceIdentity },
                            dockerIdentities: docker.map { $0.observations[0].sourceIdentity }
                        )
                    ],
                    servers: servers,
                    docker: docker,
                    usage: usage,
                    controlOrigin: fullyControlled ? origin : nil,
                    serverMembershipConflicts: [],
                    dockerMembershipConflicts: []
                )
            )
        }

        let assignedDockerIDs = Set(memberships.filter { $0.resourceKind == "container" }.map(\.hostResourceID))
        var unassignedServers: [RepositoryServerObservation] = []
        var unassignedDocker: [RepositoryDockerResource] = []
        var seenUnassigned = Set<String>()
        for item in unassignedResources + lifecycleViolations
            where seenUnassigned.insert("\(item.resourceKind)|\(item.resourceID)|\(item.reasonCode.rawValue)").inserted {
            if item.resourceKind == "server" {
                let definition = resources.servers.first { $0.serverDefinitionID == item.resourceID }
                let server = normalizedUnassignedServer(item, definition: definition, origin: origin)
                unassignedServers.append(
                    RepositoryServerObservation(
                        sourceIdentity: ResourceIdentity(origin: origin, kind: .server, nativeID: item.resourceID),
                        server: server
                    )
                )
                serverPresentations.append(server)
            } else if item.resourceKind == "container",
                      let resource = resources.docker.first(where: { $0.dockerResourceID == item.resourceID }),
                      var container = dockerPresentations[item.resourceID] {
                container.project = nil
                container.origin = origin
                container.attribution = item.attribution
                container.ownershipError = "Use the exact Attach or Retire action; repository ownership is not established."
                unassignedDocker.append(
                    RepositoryDockerResource(
                        identity: RepositoryDockerIdentity(rawValue: resource.dockerResourceID, isImmutable: true),
                        representative: container,
                        observations: [
                            RepositoryDockerObservation(
                                sourceIdentity: ResourceIdentity(
                                    origin: origin,
                                    kind: .docker,
                                    nativeID: resource.dockerResourceID
                                ),
                                container: container
                            )
                        ],
                        repositoryCandidates: [],
                        membershipError: nil,
                        controlCandidates: item.canAttach || item.canRetire ? [origin] : []
                    )
                )
            }
        }
        // A normalized resource without membership must never disappear merely
        // because an attribution diagnostic is temporarily absent.
        for resource in resources.docker
            where !assignedDockerIDs.contains(resource.dockerResourceID)
                && !unassignedDocker.contains(where: { $0.id == resource.dockerResourceID }) {
            guard var container = dockerPresentations[resource.dockerResourceID] else { continue }
            container.project = nil
            container.origin = nil
            container.ownershipError = "Normalized inventory has no repository membership or exact attribution record."
            unassignedDocker.append(
                RepositoryDockerResource(
                    identity: RepositoryDockerIdentity(rawValue: resource.dockerResourceID, isImmutable: true),
                    representative: container,
                    observations: [],
                    repositoryCandidates: [],
                    membershipError: container.ownershipError,
                    controlCandidates: []
                )
            )
        }

        let catalog = RepositoryCatalog(
            repositories: aggregates,
            unassigned: UnassignedResources(
                servers: unassignedServers,
                docker: unassignedDocker,
                usageObservations: []
            )
        )
        let allContainers = dockerPresentations.values.sorted { ($0.name ?? $0.stableID) < ($1.name ?? $1.stableID) }
        let urls = serverPresentations.compactMap { server -> ManagedURL? in
            guard let url = server.currentURL else { return nil }
            return ManagedURL(
                origin: origin,
                name: server.name,
                project: server.project,
                url: url,
                healthURL: server.healthURL,
                status: server.status
            )
        }
        let leases = self.leases.compactMap { lease -> PortLease? in
            guard lease.status == "active" else { return nil }
            guard let repository = repositoriesByID[lease.repoID] else { return nil }
            return PortLease(
                id: lease.leaseID,
                coordinatorID: lease.leaseID,
                origin: origin,
                port: lease.port,
                agent: lease.agent,
                project: repository.canonicalRoot,
                purpose: lease.purpose,
                status: lease.status,
                expiresAtISO: lease.expiresAt,
                serverID: lease.serverDefinitionID,
                pendingOperationID: nil
            )
        }
        let recentEvents = events.map {
            RecentEvent(origin: origin, at: $0.occurredAt, type: $0.eventKind)
        }
        let dockerAvailability: Bool? = dockerEngines.isEmpty
            ? nil
            : dockerEngines.contains { $0.capabilityState == "available" }
        var inventory = Inventory(
            origin: origin,
            coordinatorHome: origin.home,
            statePath: origin.statePath ?? "\(origin.home)/coordinator.sqlite3",
            project: nil,
            urls: urls,
            servers: serverPresentations,
            leases: leases,
            recentEvents: recentEvents,
            docker: DockerSummary(
                available: dockerAvailability,
                error: dockerAvailability == false ? "Docker observer is unavailable" : nil,
                statsError: nil,
                containers: allContainers,
                postgres: databasePresentations
            ),
            postgres: databasePresentations,
            backups: backups,
            projectUsage: aggregates.map { $0.sourceObservations[0].usageRows[0] }
        )
        inventory.origin = origin
        return NormalizedBoardProjection(inventory: inventory, catalog: catalog)
    }

    private func validatedRepositories() throws -> [String: NormalizedRepository] {
        var byID: [String: NormalizedRepository] = [:]
        var roots = Set<String>()
        for repository in repositories {
            guard !repository.repoID.isEmpty,
                  repository.canonicalRoot.hasPrefix("/"),
                  roots.insert(repository.canonicalRoot).inserted,
                  byID.updateValue(repository, forKey: repository.repoID) == nil
            else {
                throw RuntimeError("Normalized inventory contains a duplicate or invalid repository identity")
            }
        }
        return byID
    }
}

private func normalizedServerPresentation(
    definition: NormalizedServerDefinition,
    observation: NormalizedServerObservation?,
    telemetry: [NormalizedTelemetrySample],
    assignment: NormalizedPortAssignment?,
    lease: NormalizedLease?,
    repository: NormalizedRepository,
    origin: CoordinatorOrigin,
    actionable: Bool,
    attribution: ResourceAttribution?
) -> ManagedServer {
    let active = ["running", "starting", "unhealthy"].contains(observation?.lifecycle ?? "")
    let port = observation?.listenerPort ?? assignment?.port ?? lease?.port
    let url = active ? observation?.listenerPort.map {
        "http://\(observation?.listenerHost ?? "127.0.0.1"):\($0)"
    } : nil
    let latest = telemetry.sorted { $0.sampledAt > $1.sampledAt }.first
    let processUsage = latest.map {
        ProcessUsage(
            source: "normalized_store",
            pid: observation?.pid,
            ppid: nil,
            rootPIDs: observation?.pid.map { [$0] },
            pids: observation?.pid.map { [$0] },
            processCount: observation?.pid == nil ? 0 : 1,
            cpuPercent: $0.cpuPercent,
            rssBytes: $0.memoryBytes.map(Double.init),
            memoryBytes: $0.memoryBytes.map(Double.init),
            command: definition.arguments.joined(separator: " "),
            sampledAt: $0.sampledAt,
            project: repository.canonicalRoot,
            serverID: definition.serverDefinitionID,
            serverName: definition.name,
            processes: nil,
            hotProcesses: nil,
            origin: origin
        )
    }
    return ManagedServer(
        id: definition.serverDefinitionID,
        coordinatorID: definition.serverDefinitionID,
        origin: origin,
        name: definition.name,
        agent: nil,
        project: repository.canonicalRoot,
        cwd: definition.cwd,
        command: definition.arguments.joined(separator: " "),
        commandTemplate: nil,
        port: port,
        host: observation?.listenerHost,
        url: url,
        healthURL: definition.healthURLTemplate,
        leaseID: lease?.leaseID,
        pid: observation?.pid,
        logPath: definition.logPath,
        status: observation?.lifecycle ?? "unobserved",
        health: Health(
            ok: observation?.healthOK.map { $0 != 0 },
            pidAlive: observation?.pid.map { _ in active }
        ),
        stoppedAt: observation?.stoppedAt,
        stoppedReason: observation?.stoppedReason,
        adopted: nil,
        missingCommand: definition.arguments.isEmpty,
        metadataSource: "normalized_store",
        updatedAt: observation?.sampledAt,
        createdAt: nil,
        createdTs: nil,
        duplicateCount: nil,
        duplicateServerIDs: nil,
        urlIsCurrent: url != nil,
        portReused: nil,
        portReusedBy: nil,
        processUsage: processUsage,
        attribution: attribution,
        ownershipError: actionable ? nil : "No authoritative normalized control binding matches this server membership.",
        ownershipCandidates: actionable ? [origin] : [],
        observationOrigins: [origin]
    )
}

private func normalizedUnassignedServer(
    _ item: NormalizedUnassignedResource,
    definition: NormalizedServerDefinition?,
    origin: CoordinatorOrigin
) -> ManagedServer {
    ManagedServer(
        id: item.resourceID,
        coordinatorID: item.resourceID,
        origin: origin,
        name: item.displayName,
        agent: nil,
        project: nil,
        cwd: definition?.cwd,
        command: definition?.arguments.joined(separator: " "),
        commandTemplate: nil,
        port: nil,
        host: nil,
        url: nil,
        healthURL: definition?.healthURLTemplate,
        leaseID: nil,
        pid: nil,
        logPath: definition?.logPath,
        status: item.lifecycleViolation ? "running" : "unassigned",
        health: nil,
        stoppedAt: nil,
        stoppedReason: nil,
        adopted: nil,
        missingCommand: nil,
        metadataSource: "normalized_store",
        updatedAt: nil,
        createdAt: nil,
        createdTs: nil,
        duplicateCount: nil,
        duplicateServerIDs: nil,
        urlIsCurrent: false,
        portReused: nil,
        portReusedBy: nil,
        processUsage: nil,
        attribution: item.attribution,
        ownershipError: "Use the exact Attach or Retire action; repository ownership is not established.",
        ownershipCandidates: [origin],
        observationOrigins: [origin]
    )
}

private func normalizedDockerPresentation(
    resource: NormalizedDockerResource,
    observation: NormalizedDockerObservation?,
    ports: [NormalizedDockerPort],
    telemetry: [NormalizedTelemetrySample],
    repository: NormalizedRepository?,
    origin: CoordinatorOrigin,
    actionable: Bool,
    metadataSource: String?,
    attribution: ResourceAttribution?
) -> DockerContainer {
    let sortedTelemetry = telemetry.sorted { $0.sampledAt < $1.sampledAt }
    let statsHistory = sortedTelemetry.map {
        DockerStats(
            containerShortID: String(resource.fullContainerID.prefix(12)),
            containerID: resource.fullContainerID,
            name: resource.currentName,
            timestamp: $0.sampledAt,
            timestampTs: parseISOTimestamp($0.sampledAt)?.timeIntervalSince1970,
            live: observation?.lifecycle == "running",
            cpuPercent: $0.cpuPercent,
            memoryPercent: nil,
            memoryUsageBytes: $0.memoryBytes.map(Double.init),
            memoryLimitBytes: nil,
            networkRxBytes: $0.networkRxBytes.map(Double.init),
            networkTxBytes: $0.networkTxBytes.map(Double.init),
            blockReadBytes: $0.blockReadBytes.map(Double.init),
            blockWriteBytes: $0.blockWriteBytes.map(Double.init),
            networkRxRateBytesPerSecond: nil,
            networkTxRateBytesPerSecond: nil,
            blockReadRateBytesPerSecond: nil,
            blockWriteRateBytesPerSecond: nil,
            pids: nil
        )
    }
    let portSummary = ports.sorted { $0.ordinal < $1.ordinal }.map { port in
        let destination = "\(port.containerPort)/\(port.protocol)"
        guard let hostPort = port.hostPort else { return destination }
        return "\(port.hostAddress ?? "0.0.0.0"):\(hostPort)->\(destination)"
    }.joined(separator: ", ")
    return DockerContainer(
        origin: origin,
        id: resource.fullContainerID,
        name: resource.currentName,
        image: resource.image,
        status: observation?.lifecycle ?? "unobserved",
        ports: portSummary.isEmpty ? nil : portSummary,
        project: repository?.canonicalRoot,
        agent: nil,
        role: nil,
        metadataSource: metadataSource ?? "normalized_store",
        adopted: nil,
        stats: statsHistory.last,
        statsHistory: statsHistory,
        database: nil,
        databaseSizeBytes: nil,
        databaseDiscoveryError: nil,
        startedAt: nil,
        ownershipError: actionable ? nil : "No authoritative normalized control binding matches this container membership.",
        ownershipCandidates: actionable ? [origin] : [],
        observationOrigins: [origin],
        attribution: attribution
    )
}

private func normalizedRepositoryUsage(
    serverIDs: [String],
    docker: [DockerContainer],
    serverTelemetry: [NormalizedTelemetrySample]
) -> RepositoryUsage {
    let latestServer = latestTelemetryByResource(serverTelemetry)
    let serverCPU = latestServer.reduce(0) { $0 + ($1.cpuPercent ?? 0) }
    let serverMemory = latestServer.reduce(0) { $0 + Double($1.memoryBytes ?? 0) }
    let dockerCPU = docker.reduce(0) { $0 + ($1.stats?.cpuPercent ?? 0) }
    let dockerMemory = docker.reduce(0) { $0 + ($1.stats?.memoryUsageBytes ?? 0) }
    let hot = latestServer.compactMap { sample -> ProcessUsage? in
        guard (sample.cpuPercent ?? 0) > 0 || (sample.memoryBytes ?? 0) > 0 else { return nil }
        return ProcessUsage(
            source: "normalized_store",
            pid: nil,
            ppid: nil,
            rootPIDs: nil,
            pids: nil,
            processCount: 1,
            cpuPercent: sample.cpuPercent,
            rssBytes: sample.memoryBytes.map(Double.init),
            memoryBytes: sample.memoryBytes.map(Double.init),
            command: sample.hostResourceID,
            sampledAt: sample.sampledAt,
            project: nil,
            serverID: sample.hostResourceID,
            serverName: nil,
            processes: nil,
            hotProcesses: nil,
            origin: nil
        )
    }.sorted { ($0.cpuPercent ?? 0) > ($1.cpuPercent ?? 0) }
    return RepositoryUsage(
        serverCount: serverIDs.count,
        containerCount: docker.count,
        processCount: latestServer.count,
        cpuPercent: serverCPU + dockerCPU,
        memoryBytes: serverMemory + dockerMemory,
        hotProcesses: Array(hot.prefix(5))
    )
}

private func latestTelemetryByResource(
    _ samples: [NormalizedTelemetrySample]
) -> [NormalizedTelemetrySample] {
    Dictionary(grouping: samples) { "\($0.hostResourceKind)|\($0.hostResourceID)" }
        .values
        .compactMap { $0.max { $0.sampledAt < $1.sampledAt } }
}

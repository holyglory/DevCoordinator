# Control-plane availability boundary

DevCoordinator has one server-wide control plane and many project data planes.
Their failure domains are intentionally asymmetric:

- `devops-console.service`, `dev-coordinator.service`, and
  `devcoordinator-broker.service` are control-plane services. Project lifecycle
  code cannot stop, restart, replace, or report progress through them. Their
  systemd units have maximum CPU/I/O weight and protected memory working sets.
- Project servers, Compose stacks, containers, databases, tests, captures, and
  publications are data-plane resources. Their failures are attributed to the
  exact repository/resource and remain local to that row and event stream.
- Inventory readers retain the last committed authority snapshot when a live
  observation cannot complete. A background refresh never clears an already
  usable Console or Board screen.
- The broker-independent maintenance fence is reserved for an offline
  server-wide authority/schema transaction. Its activation requires the exact
  `server-wide-authority-upgrade` scope. Its client text is fixed and cannot
  contain a project name or operator task.
- The Coordinator HTTP API preserves `code`, `classification`, operation ID,
  and retry interval. Console clients must pass the typed error object intact;
  flattening it to a message is a contract violation.
- The loopback API reserves four request slots for authenticated readiness and
  liveness remains outside the project-work admission gate. Saturated project
  work receives a bounded `control_plane_capacity` response instead of
  consuming the final control-plane threads.
- A project failure cannot become a global Console banner. With retained
  inventory, planned control-plane maintenance is silent; an attempted live
  mutation gets a bounded informational wait response and reconnects without
  user action.

This boundary must be enforced in executable guards and regression tests, not
only in agent instructions.

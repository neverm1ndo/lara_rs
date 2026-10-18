# AGENTS.md — Instructions for AI Agents

## 1. Project Context
* **Goal:** Migrating the backend server from **NestJS to Rust** (Hypervisor & Panel architecture for `omp-server`).
* **Stack:** 
  * Web Framework: `axum`
  * Realtime: `Socket.IO`
  * Process Management: `systemd` via D-Bus (no direct child process spawning)
  * System Monitoring & Logs: `journald` & `MongoDB`
  * IPC / Readiness: Unix Domain Sockets (UDS)
  * Authentication & Authorization: JWT with strict role-based access (`Developer`, `Admin`, `Challenger`)
  * API Documentation: `utoipa` and `utoipa-axum` (OpenAPI 3.1 generation)
* **Architectural Pattern:** Domain-Driven Design (DDD), strict Bounded Contexts, Feature-First file/directory structure, Event-Driven decoupling.
---

## 2. Repository Topology & Directory Structure
The project is divided into isolated domains. Each domain is fully autonomous and follows Clean Architecture / DDD principles.

```
src/
├── main.rs                 # Entry point: Axum router initialization, merged OpenAPI spec & DB connection
├── shared/                 # Shared utilities, common errors, middlewares (e.g., JWT extractor), base traits
├── auth/                   # Bounded Context: Authentication & Authorization
│   ├── domain/             # Entities, Value Objects, domain errors, repository ports/interfaces
│   ├── application/        # Application services, use cases, internal DTOs
│   ├── infrastructure/     # Repositories (port implementations), DB access, JWT generation/validation
│   └── presentation/       # Axum handlers, endpoint routes, HTTP DTOs, and utoipa definitions
├── user/                   # Bounded Context: User Management
│   ├── domain/             # User domain model, core business rules & entities
│   ├── application/        # User profile use cases & application logic
│   ├── infrastructure/     # User-specific repository implementations (SQL queries, etc.)
│   └── presentation/       # Axum handlers, routes, HTTP DTOs, and utoipa definitions for user domain
├── configuration/          # Bounded Context: SAMP/open.mp Server Configuration Management
│   ├── domain/             # Configuration domain models, validation rules, value objects
│   ├── application/        # Use cases for parsing, editing, and saving config files (server.cfg, etc.)
│   ├── infrastructure/     # File system operations, IO providers, parsing implementations
│   └── presentation/       # Axum handlers, routes, and utoipa annotations for configuration
├── maps/                   # Bounded Context: Server Mapping Management (XML files)
│   ├── domain/             # Map domain models & business rules
│   ├── application/        # Use cases for map processing and CRUD operations
│   ├── infrastructure/     # Uses shared/file_storage for XML file management
│   └── presentation/       # Axum handlers, routes, and utoipa annotations for maps
├── backups/                # Bounded Context: Versioning & Snapshot Management
│   ├── domain/             # Backup retention policy, snapshot metadata models
│   ├── application/        # Use cases for listing, restoring, and managing historical snapshots
│   ├── infrastructure/     # File system snapshot storage, pre-calculated diff/patch generation
│   └── presentation/       # Axum handlers, routes, and utoipa annotations for backups
└── server_instances/       # Bounded Context: Hypervisor & Process Management
    ├── domain/             # ServerInstance model, capabilities, lifecycle, operation, observation, incidents, access, events
    ├── application/        # Ports, manifests, lifecycle_service, observer, incident_service, notification_policy
    ├── infrastructure/     # systemd_runtime (D-Bus), systemd_observer, journal_reader, uds_readiness, mongo_* (operations, incidents, outbox)
    └── presentation/       # Authorization, DTOs, handlers, routes, realtime (Socket.IO), OpenAPI
```

## 3. Architectural Rules & DDD (CRITICAL)

### Strict Bounded Context Rules & Inter-Domain Ports
1. **Domain Isolation:** `server_instances`, `configuration`, `maps`, and `backups` are independent contexts. 
2. **The `configuration` to `server_instances` Boundary:** 
   * `configuration` **must not** directly import or reference `server_instances::infrastructure`. 
   * Instead, `configuration`'s application layer must define a **port** (interface) for resolving configuration targets, which is bound/wired together during bootstrap (`main.rs`).
3. **Process Execution Rule:** 
   * **Never** use raw process spawning (`std::process::Command::spawn`) inside the application code. 
   * All `omp-server` instances are managed strictly via **systemd units** through **D-Bus** calls (`server_instances::infrastructure::systemd_runtime`).

### Access Control & Permissions (`server_instances` & panels)
1. **Role Hierarchies:** 
   * Only **`Developer`** (determined via `main_group` or explicit permissions) can manage the lifecycle of *any* instance (Primary or Auxiliary). 
   * **`Admin`** does *not* get Developer rights automatically.
   * **`Configurator`** works exclusively with the primary server configuration. **`Mapper`** and **`Backuper`** work only with the primary server.
   * Auxiliary configurations and instances are strictly restricted to `Developer`.
2. **Backend Validation:** The backend must always re-verify permissions; UI manifests are only for interface rendering.

---

## 4. Rust, Axum & Hypervisor Guidelines

### Systemd & Runtime (`server_instances`)
* **D-Bus Communication:** Use async D-Bus crates to interact with `systemd` for starting, stopping, and monitoring unit states.
* **Readiness & Logs:** Monitor primary server readiness via Unix Domain Sockets (UDS) and recover missed system states using `journald`. Historical audit logs and operations must be persisted in MongoDB.

### Realtime & Notification Policy (Socket.IO)
* Implement role-aware notification dispatching:
  * `Developer` receives events from all instances.
  * The actor executing an operation receives state updates but **not** a toast notification for their own action.
  * `Challenger` and `Admin` receive only general notifications regarding primary server restarts (auxiliary details are masked).

### OpenAPI 3.1 Documentation (`utoipa`)
* **Annotations:** All public HTTP endpoints in the `presentation` layer across all domains must use `utoipa` macros (`#[utoipa::path(...)]`).
* **Schemas:** DTOs and payloads must derive `utoipa::ToSchema`. Aggregate specs via `utoipa-axum`.

---

## 5. Checklist for Code Modifications
When generating or refactoring code, the AI agent must ensure:
1. [ ] Code respects domain boundaries (e.g., `configuration` uses ports to resolve targets rather than touching `server_instances::infrastructure`).
2. [ ] No direct process spawning; systemctl/systemd actions go through D-Bus (`server_instances::infrastructure::systemd_runtime`).
3. [ ] File IO operations reuse `shared::file_storage`.
4. [ ] Side effects like backup creation use decoupled event-driven triggers.
5. [ ] Role validation is enforced on the backend for sensitive actions (especially `Developer` constraints on auxiliary instances).
6. [ ] New endpoints feature correct `utoipa` documentation and schema derivations.
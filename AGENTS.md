# AGENTS.md — Instructions for AI Agents

## 1. Project Context
* **Goal:** Migrating the backend server from **NestJS to Rust**.
* **Stack:** 
  * Web Framework: `axum`
  * Authentication: JWT (JSON Web Tokens)
  * OpenAPI Documentation: `utoipa` & `utoipa-axum` (OpenAPI 3.0 generation)
  * Database / ORM: (e.g., `sqlx`, `sea-orm`, or `diesel`)
* **Architectural Pattern:** Domain-Driven Design (DDD), strict Bounded Contexts, Feature-First file/directory structure.

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
└── user/                   # Bounded Context: User Management
    ├── domain/             # User domain model, core business rules & entities
    ├── application/        # User profile use cases & application logic
    ├── infrastructure/     # User-specific repository implementations (SQL queries, etc.)
    └── presentation/       # Axum handlers, routes, HTTP DTOs, and utoipa definitions for user domain
```

---

## 3. Architectural Rules & DDD (CRITICAL)

### Strict Bounded Context Rules
1. **Domain Isolation:** The `auth` and `user` domains **must not** have circular dependencies. 
   * `auth` handles authentication, authorization, tokens, and sessions.
   * `user` handles user profile state and domain logic.
2. **Dependency Rule:**
   * `domain` is the core. It **must not** depend on `application`, `infrastructure`, or `presentation`.
   * `application` depends only on `domain`.
   * `infrastructure` and `presentation` depend on `application` and `domain`.
3. **Cross-Domain Interaction:** If `user` requires data or verification from `auth` (or vice versa), interaction must occur via traits/interfaces in the `domain`/`application` layer or well-defined contracts. Directly querying or accessing another domain's infrastructure or database tables is strictly forbidden.

---

## 4. Rust, Axum & OpenAPI Guidelines

### OpenAPI 3.0 Generation via `utoipa`
1. **Code-First Documentation:** Use `utoipa` and `utoipa-axum` to automatically generate OpenAPI 3.0 specifications directly from code annotations.
2. **Per-Domain Documentation:** 
   * Every domain's `presentation` layer must annotate its DTOs/models with `#[derive(utoipa::ToSchema)]`.
   * Axum handlers must be documented using `#[utoipa::path]` macros (or integrated via `utoipa-axum`'s `OpenApiRouter`).
   * Each domain should aggregate its own OpenAPI definitions (e.g., exposing a modular router/spec component) so that domains remain fully decoupled.
3. **Global Spec Aggregation:** The root `main.rs` must combine the OpenAPI specs from all domains (`auth`, `user`) into a single global specification (e.g., serving Swagger UI at `/swagger-ui` and the raw OpenAPI JSON spec).

### Error Handling
* Use custom domain errors (preferably using the `thiserror` crate).
* Map infrastructure and application errors to domain/presentation errors implementing `axum::response::IntoResponse` to return proper HTTP response codes and document them in `utoipa` responses.

### Axum & Application State
* Pass application state using `axum::extract::State`.
* Keep routes modular: every domain (`auth`, `user`) should expose its own route builder function (e.g., `pub fn router() -> Router<AppState>`) to be attached to the root router in `main.rs`.

### Async & Type Safety
* Write idiomatic asynchronous Rust code targeting `tokio`.
* Avoid unnecessary `Arc<Mutex<T>>` inside domain logic; favor immutable structures and Rust's ownership/borrowing semantics.
* Use strongly typed domain wrappers (Newtype pattern, e.g., `pub struct UserId(Uuid);`) to avoid primitive obsession.

---

## 5. Checklist for Code Modifications
When generating or refactoring code, the AI agent must ensure:
1. [ ] The code is placed in the correct domain (`auth` or `user`) and layer (`domain`, `application`, `infrastructure`, `presentation`).
2. [ ] No boundary violations occur (e.g., no imports from `auth::infrastructure` inside `user`).
3. [ ] Protected endpoints correctly apply Axum extractors for JWT validation.
4. [ ] **OpenAPI Docs (`utoipa`):** All new or modified HTTP DTOs have `#[derive(ToSchema)]`, all endpoints include `#[utoipa::path]` documentation, and they are registered in the domain's OpenAPI configuration.
5. [ ] Unit tests cover domain logic and integration tests cover HTTP handlers.
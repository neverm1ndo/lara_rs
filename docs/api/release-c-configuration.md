# Release C configuration API contract

Status: accepted design contract. The accompanying
[OpenAPI 3.1 document](release-c-configuration.openapi.json) is a contract
fixture for implementation and client development. The production `/openapi.json`
contains only mounted endpoints. The Release C routes appear there when the
instance-scoped service is wired in step 6.

## Routing and access

All routes begin with `/server-instances/{instance_id}/configuration`.
`instance_id` must come from the authenticated instance manifest; the backend
resolves its storage root from trusted configuration. `/configuration/...` is
removed and returns `404`. Unknown instances, instances without the
`Configuration` capability and auxiliary instances hidden from the caller
return `404`. A known primary instance with insufficient role returns `403`.

Developer can use text operations on primary and auxiliary instances that have
the capability. Configurator can use text operations only within the primary
configurator subtree. Only Developer can inspect or replace an allowlisted
artifact. The manifest is a navigation hint; each endpoint verifies the role,
instance and action again.

| Method and relative route | Purpose | Success |
| --- | --- | --- |
| `GET /tree` | List visible paths and text/binary kinds | `200` JSON |
| `GET /files?path=…` | Stream exact text bytes | `200` text bytes and `ETag` |
| `POST /files?path=…` | Create one text file; multipart field `file` | `201` mutation |
| `PUT /files?path=…` | Replace one text file | `200` mutation and new `ETag` |
| `DELETE /files?path=…` | Delete one text file | `200` mutation |
| `PATCH /files/rename` | Rename one text file, JSON `source` and `destination` | `200` mutation and destination `ETag` |
| `HEAD /artifacts?path=…` | Read allowlisted artifact size and `ETag` | `200` headers, empty body |
| `PUT /artifacts?path=…` | Replace one existing allowlisted artifact; `application/octet-stream` | `200` mutation and new `ETag` |

Paths are slash-separated and relative to the caller's scoped configuration
root. Binary files are shown in the tree but cannot be modified through text
routes. Artifact update does not create a missing artifact. Replacement is
allowed while the game server is running: it changes the file on disk but does
not reload or restart the process. The effect on an already loaded mod depends
on the game server; Developer initiates a separate lifecycle operation when
needed. Every response containing file data or private metadata uses
`Cache-Control: no-store`.

## Conditional writes and retries

`GET /files` and `HEAD /artifacts` return a strong, opaque, double-quoted
`ETag` derived from file content. Overwrite, delete, rename and artifact update
require exactly one strong `If-Match` tag for the current source file. Missing
header returns `428 PRECONDITION_REQUIRED`; a malformed or weak tag returns
`400 BAD_REQUEST`; a tag that does not match the current content returns
`412 PRECONDITION_FAILED`. A competing destination returns `409 CONFLICT`.
Create requires no `If-Match` and returns `409 CONFLICT` when the path exists.

Every mutating request requires `Idempotency-Key` containing 1–128 visible ASCII
characters. A key is scoped to the authenticated actor. Its fingerprint
includes method, instance, canonical source/destination paths, `If-Match` (when
present) and payload hash. Repeating the exact request returns the original
status and body, with `Idempotency-Replayed: true`. Reusing a key for another
request returns `409 CONFLICT`. Missing or malformed key returns `400
BAD_REQUEST`. A retry of an in-flight attempt with unresolved state returns
`503 SERVICE_UNAVAILABLE` and its `mutationId` when available; it never applies
the file operation a second time on uncertain evidence.

The server records a durable intent before changing a file. Its states are
`Requested`, `Applying`, `Succeeded`, `Failed` and
`ReconciliationRequired`. An ambiguous external change after a crash is kept
for review in `ReconciliationRequired`. An HTTP success response is returned
only after the mutation reaches `Succeeded` and its audit event is persisted.

## Bodies, errors and events

Text uploads contain exactly one multipart part named `file`. Bytes are
validated against the selected instance's encoding and stored without
transcoding. Artifact upload accepts raw opaque bytes. Size limits are
instance-specific. `GET /files` emits `Content-Type: text/plain; charset=<encoding>`;
`HEAD /artifacts` emits `ETag` and `Content-Length` without downloading bytes.

Successful mutations return `mutationId`, `instanceId`, `status: "succeeded"`,
`eventId`, `eventType: "configuration.file-changed.v1"` and `occurredAt`.
Errors return `{ "code": "..." }` and can include `mutationId` when a durable
intent exists. The stable error codes are:

| HTTP | Code | Meaning |
| ---: | --- | --- |
| 400 | `BAD_REQUEST` | Invalid relative path, key, precondition syntax or body |
| 401 | `UNAUTHENTICATED` | Invalid or missing bearer session |
| 403 | `FORBIDDEN` | Role or action denied for visible instance |
| 404 | `NOT_FOUND` | Hidden, unknown or missing target/path |
| 409 | `CONFLICT` | Existing destination or idempotency fingerprint mismatch |
| 412 | `PRECONDITION_FAILED` | Stale source `ETag` |
| 413 | `CONTENT_TOO_LARGE` | Instance upload limit exceeded |
| 415 | `BINARY_FILE` | Text endpoint used for a binary file |
| 422 | `INVALID_ENCODING` | Text upload invalid for instance encoding |
| 428 | `PRECONDITION_REQUIRED` | Missing `If-Match` |
| 503 | `SERVICE_UNAVAILABLE` | Storage, backup or durable mutation dependency failed |

`configuration.file-changed.v1` is published at least once after its durable
success record. The event envelope contains `eventId`, `mutationId`,
`instanceId`, `actorUserId`, `occurredAt`, operation kind, canonical server
paths, previous/current content hashes and optional primary backup receipt.
Consumers deduplicate by `eventId`. Developer receives authorized detailed
events for all instances. Configurator receives only the permitted primary
projection; the actor receives the state update without a toast for their own
action.

## Migration

The client has not adopted `/configuration/...`, so no compatibility alias is
provided. Release C clients should build links from the manifest's instance
ID and feature actions. The old route is removed from the production router and
OpenAPI immediately. The existing primary configuration settings remain a
configuration-file input until per-instance target policy is introduced in
step 2; they are not an HTTP compatibility route.

# Webex connector — architecture and implementation plan

## Objective

Add a **read-only Webex connector** to Asset Client for both:
- Webex Calling phone devices and their available user/workspace assignments.
- RoomOS devices used in meeting rooms, including supported Cisco Room Bars and room systems.

The connector imports a normalized snapshot for comparison only. It must not create, modify, deactivate, move, or delete devices in Webex Control Hub, and it must not silently overwrite Asset Client inventory records.

## Proposed user experience

Add **Amministrazione → Connettori → Webex** with:
- Connection status and tenant/organization identifier (never expose secrets).
- “Verifica connessione” and “Sincronizza ora” actions.
- Last successful sync, sync duration, records read, warnings, and API errors.
- A comparison view: Webex-only, Asset Client-only, matched, and possible duplicates.
- Per-row source details and a clear distinction between confirmed values and suggestions.
- A run history; record administrative sync actions in the existing audit log.

Only administrators can configure or run a sync. Operators do not get access to credentials or connector configuration.

## Architecture

1. **Connector service (server-side only)** — handles OAuth credentials, token refresh, pagination, retries, rate limits, timeouts and API error handling. No Webex secret or access token is sent to the browser.
2. **Webex API client** — use Cisco's documented Webex REST APIs for organization devices, workspace details and Webex Calling device/assignment information as applicable to the organization and granted scopes. Keep endpoint-specific adapters separate because device types and fields differ.
3. **Read-only snapshot store** — save normalized external records and sync metadata separately from the operational inventory. Store external IDs, source, device type, model, MAC where exposed, display name, workspace/user assignment where exposed, reported status where available, and last-seen/sync timestamps. Avoid persisting unnecessary personal data.
4. **Matcher/diff engine** — match first by stable identifiers (Webex device ID and MAC where available), then present weaker name/model matches as suggestions only. Never auto-merge ambiguous matches.
5. **Admin UI** — display differences and allow export/review. Phase one has no “apply to inventory” or “manage in Webex” operation.

## Authentication and security

- Prefer an administrator-authorized OAuth integration with the minimum read scopes supported by the selected Webex APIs and the organization’s deployment model.
- Confirm whether the deployment should use a Webex Integration (interactive authorization) or an administrator-approved integration/service app; do not assume a token type or scope before checking the actual API endpoints and Cisco documentation.
- Store client secrets and refresh/access tokens only in server-side environment secrets or an approved secret store; never in browser storage, logs, source control, or audit details.
- Validate OAuth state during authorization, use HTTPS, restrict configuration and sync endpoints to administrators, and redact credentials from errors.
- Make the connection test verify authorization and required API access without changing remote state.
- Do not request write scopes for this read-only phase.

## Asset Client data rules

- The NETWORK source remains authoritative for branch identity and branch mapping. Do not infer or create branches from Webex names.
- Do not create duplicate inventory devices automatically. Missing or uncertain mappings are comparison findings for an administrator to review.
- Keep Webex-reported status separate from Asset Client lifecycle status; offline/unregistered does not by itself mean hardware failure.
- Keep Asset Client SKU, manufacturer serial, MAC, and external Webex ID as distinct fields. Never treat a SKU as a serial or generate identifiers.
- A sync updates only the connector snapshot and sync metadata. Existing asset, contract, branch, activation, financial, and lifecycle data remain unchanged.
- Preserve source timestamps and last successful sync. API omissions/errors must not be interpreted as remote deletion.

## Comparison categories

- **Matched** — stable identifiers support a confident match.
- **Webex only** — seen in the Webex snapshot but no confident Asset Client match.
- **Asset Client only** — Asset Client record has no confident match in the latest successful comparable snapshot.
- **Review required** — possible match, duplicate identifier, missing MAC/ID, unsupported device type, or incomplete API permissions.
- **Stale/unknown** — sync failed, API pagination incomplete, or data is too old to make a reliable absence claim.

Only label records “Asset Client only” after a complete successful sync for the relevant endpoint; never infer removals from a partial/failed run.

## Implementation plan

### Phase 0 — verify API contract
- Confirm the Webex organization and expected authorization owner.
- Map each required data field to an official Cisco endpoint and exact read scope.
- Verify support for phone/Calling devices and RoomOS devices separately, including pagination, status fields and workspace/user assignments.
- Document API limits and any fields that are not available.

### Phase 1 — secure connection and read-only sync
- Add server-side connector configuration and connection-test endpoint.
- Add an explicit sync-run record and separate normalized snapshot tables.
- Implement paginated fetch, bounded retries/backoff, rate-limit handling, timeouts and safe error reporting.
- Do not write to inventory tables or call Webex mutation APIs.

### Phase 2 — matching and review UI
- Add the admin connector page and sync status.
- Implement stable-ID/MAC matching and clearly labeled weaker suggestions.
- Show diff categories and source values; add CSV export if useful.
- Audit configuration changes, connection tests and sync runs without recording secrets.

### Phase 3 — verification and rollout readiness
- Unit-test field normalization, pagination, retries, redaction, matching and incomplete-sync handling.
- Test authorization failures, revoked credentials, rate limiting and partial endpoint failures.
- Add API integration tests with mocked responses, then validate in a dedicated Webex test organization.
- Confirm no mutation API is called and no inventory data changes during sync.
- Review data retention for connector snapshots separately; the existing audit-log retention setting does not automatically define snapshot retention.
- Only after acceptance, plan a separate explicitly approved deployment.

## Acceptance criteria

- Read-only access to both Calling phones and RoomOS devices is demonstrated against the target Webex organization.
- No credentials/tokens are exposed to the browser or written to logs/audit.
- A failed or partial sync never causes records to be reported as deleted or silently changes inventory.
- Match decisions are explainable and uncertain matches require human review.
- Branch truth continues to come from NETWORK.
- Admin can see sync history, errors, and comparison results.
- Automated tests verify that the connector never invokes Webex write operations.

## Out of scope for phase one

- Provisioning, deleting, renaming, moving or reconfiguring Webex devices.
- Automatically creating inventory records or changing branch assignments.
- Treating registration/online status as an authoritative hardware fault.
- Automatic write-back from Asset Client to Control Hub.

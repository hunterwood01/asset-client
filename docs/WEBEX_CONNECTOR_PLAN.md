# Webex connector — architecture and implementation plan

## Objective

Add a **read-only Webex connector** to Asset Client for both:
- Webex Calling phone devices and their available user/workspace assignments.
- RoomOS devices used in meeting rooms, including supported Cisco Room Bars and room systems.

The connector imports a normalized snapshot for comparison only. It must not create, modify, deactivate, move, or delete devices in Webex Control Hub, and it must not silently overwrite Asset Client inventory records. It must create an actionable Asset Client alert whenever a device observed in Webex has a usable serial number that cannot be matched to an existing Asset Client device.

## Proposed user experience

Add **Amministrazione → Connettori → Webex** with:
- Connection status and tenant/organization identifier (never expose secrets).
- “Verifica connessione” and “Sincronizza ora” actions.
- Last successful sync, sync duration, records read, warnings, and API errors.
- A comparison view: Webex-only, Asset Client-only, matched, possible duplicates, assignment mismatches (Webex person/workspace versus Asset Client assignment), and suggested/confirmed branch association.
- A persistent alert when Webex reports a device serial that is not present in Asset Client; show serial, model, Webex device ID, source/type, first-seen time, last-seen time and a link to review.
- Alert lifecycle: new, acknowledged, resolved; prevent duplicate active alerts for the same normalized serial/device identity, but retain alert history.
- A lifecycle view for End-of-Life dates and other available milestones, with source and last-verified date.
- A Dashboard entry **Device da gestire** with a live count and direct access to devices whose Asset Client records are incomplete or require a decision.
- Per-row source details and a clear distinction between confirmed values and suggestions.
- A run history; record administrative sync actions in the existing audit log.

Only administrators can configure or run a sync. Operators do not get access to credentials or connector configuration.

## Architecture

1. **Connector service (server-side only)** — handles OAuth credentials, token refresh, pagination, retries, rate limits, timeouts and API error handling. No Webex secret or access token is sent to the browser.
2. **Webex API client** — use Cisco's documented Webex REST APIs for organization devices, workspace details and Webex Calling device/assignment information as applicable to the organization and granted scopes. Keep endpoint-specific adapters separate because device types and fields differ.
3. **Read-only snapshot store** — save normalized external records and sync metadata separately from the operational inventory. Store external IDs, source, device type, model/product ID where exposed, serial number where exposed, MAC where exposed, display name, workspace/user assignment where exposed (including stable person/workspace IDs plus display name/email or workspace name when permitted), reported status where available, and last-seen/sync timestamps. Avoid persisting unnecessary personal data.
4. **Unknown-serial detector and alert store** — after a complete successful sync, compare normalized Webex serials against Asset Client manufacturer serials. Create a persistent alert when a serial is not found; deduplicate repeat observations, update last-seen, and reopen a resolved alert only under an explicit rule. Devices without a serial are not silently ignored: classify them as “serial unavailable / review required”, using Webex ID and MAC for tracking but do not claim they have an unknown serial.
5. **Branch resolver** — derive a candidate branch from available Webex location/workspace metadata and device display name, then resolve it only against the authoritative NETWORK branch list using explicit configured mappings or unambiguous identifiers. Do not create branches or guess from free text; uncertain matches require administrator review.
6. **Product lifecycle service** — retrieve Cisco End-of-Life (EoX) information using exact product identifiers (PID/SKU/model, and serial when supported) via the official Cisco Support APIs. Store announcement, End-of-Sale, End-of-Support/Last Date of Support, and other returned milestones separately, along with source and checked-at date. For RoomOS devices, also verify whether Control Hub lifecycle data is exposed through an official API for the target device types; do not scrape the UI or assume all models expose these milestones.
7. **Matcher/diff engine** — match first by normalized manufacturer serial, then stable external ID/MAC where useful; present weaker name/model matches as suggestions only. Never auto-merge ambiguous matches.
8. **Admin UI** — display differences and allow export/review. Phase one has no “apply to inventory” or “manage in Webex” operation.

## Authentication and security

- Prefer an administrator-authorized OAuth integration with the minimum read scopes supported by the selected Webex APIs and the organization’s deployment model.
- Confirm whether the deployment should use a Webex Integration (interactive authorization) or an administrator-approved integration/service app; do not assume a token type or scope before checking the actual API endpoints and Cisco documentation.
- Store client secrets and refresh/access tokens only in server-side environment secrets or an approved secret store; never in browser storage, logs, source control, or audit details.
- Validate OAuth state during authorization, use HTTPS, restrict configuration and sync endpoints to administrators, and redact credentials from errors.
- Make the connection test verify authorization and required API access without changing remote state.
- Do not request write scopes for this read-only phase.

## Asset Client data rules

- The NETWORK source remains authoritative for branch identity and branch mapping. Do not infer or create branches from Webex names.
- Webex device name and location/workspace metadata may be used to suggest a branch association, but must not override NETWORK or be treated as authoritative by themselves. Automatically associate a device to a branch only when a deterministic, configured mapping to a known NETWORK branch is available; otherwise present a suggested branch with the evidence and require administrator confirmation.
- Do not create duplicate inventory devices automatically. Missing or uncertain mappings are comparison findings for an administrator to review.
- Manufacturer serial matching is case/whitespace normalized but the original serial is retained for display. Never substitute SKU/model or Webex device ID for a serial. If serial is absent in the API response, report that separately from a serial that is present but not found in Asset Client.
- Alerts must only be created from complete successful Webex syncs; partial/failed syncs must not create false “new device” alerts or resolve existing ones.
- Keep Webex-reported status separate from Asset Client lifecycle status; offline/unregistered does not by itself mean hardware failure.
- Keep Asset Client SKU, manufacturer serial, MAC, and external Webex ID as distinct fields. Never treat a SKU as a serial or generate identifiers.
- A sync updates only the connector snapshot and sync metadata. Existing asset, contract, branch, activation, financial, and lifecycle data remain unchanged.
- Preserve source timestamps and last successful sync. API omissions/errors must not be interpreted as remote deletion.

## Dashboard — Device da gestire

Add a dedicated **Device da gestire** item to the Dashboard, with a count of unresolved items and a filtered work queue. The queue should include:
- Asset Client devices with required fields missing (for example serial, product/SKU, branch, assignment, activation or contract fields where applicable).
- Devices observed in Webex whose serial is not found in Asset Client.
- Devices matched by serial but missing a reliable branch association or with a Webex-versus-Asset Client assignment mismatch.
- Devices with missing Webex serials, ambiguous matches, duplicate identifiers, or lifecycle data requiring review.

Each row should show the device/serial, model, Webex identity and assigned person/workspace where available, candidate branch, missing fields/reason, source and last-seen/sync date. Provide filters by issue type, branch and source, plus a direct action to open the device record and complete the missing information. Where confidence is high, show suggested values from Webex as prefilled proposals; require explicit confirmation before changing authoritative Asset Client fields. Never fill branch from free text unless it resolves through a configured mapping to a known NETWORK branch. Mark an item complete only when its required fields/issues are resolved; retain audit history for changes. Avoid duplicate queue entries by grouping multiple findings for the same asset into one actionable row.

The Dashboard count must reflect unresolved actionable items, not all devices in Webex. A failed or partial sync must be clearly marked stale and must not automatically close work items.

## Serial mismatch alerts

- Create an alert when a complete successful Webex sync returns a device with a non-empty manufacturer serial that does not match any Asset Client device serial.
- Deduplicate by normalized serial and Webex device identity, so repeated syncs update the same active alert rather than creating a flood of duplicates.
- Display serial, product/model, device type (Calling or RoomOS), Webex ID, MAC if available, assigned person or workspace (with stable Webex ID and available display details), first seen, last seen, and the latest sync result.
- Provide acknowledge and resolve actions for administrators. Keep the audit trail and alert history; resolution does not delete the record.
- If the serial later matches a device added to Asset Client, mark the alert resolved with the reason “serial matched in Asset Client”; do not create or modify the asset automatically.
- Devices with no serial exposed by Webex get a separate review finding, not a false unknown-serial alert.

## End-of-life and lifecycle data

- Use the official Cisco Support APIs EoX service to look up lifecycle information for exact Cisco product IDs/model identifiers and serials where supported. Verify API registration, credentials, quotas and licensing/entitlement requirements before implementation.
- Prefer exact product ID/SKU for product-level milestones; use serial-number lookup only where useful and supported. If model-to-PID mapping is ambiguous, flag it for review rather than choosing an approximate product.
- Keep distinct milestones: End-of-Life announcement, End-of-Sale, End of software maintenance (when available), Last Date of Support / End-of-Support, and other fields returned by the authoritative source. Do not collapse them into one date.
- Store source, lookup key, last checked timestamp, response status and raw relevant milestone fields. Cache results and refresh periodically or on administrator request, with bounded retries and rate-limit handling.
- Show lifecycle dates in Catalogo prodotti and on device detail; use product-level data as the default for all devices with the matching PID, but allow SKU-specific overrides when the vendor data differs.
- For RoomOS devices, investigate Control Hub lifecycle milestones as a separate source; if no supported API provides the data, use Cisco's official lifecycle/EoX source and label the provenance clearly.
- Alert on upcoming milestones using configurable windows, but do not mark devices as faulty or remove them automatically when a milestone passes.

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
- Verify support for phone/Calling devices and RoomOS devices separately, including pagination, status fields, serial-number availability by device type, user/workspace assignment fields, and any official location metadata. Where supported, retrieve the associated person or workspace through the official device and Calling APIs; record assignment as unknown rather than guessing when the API does not expose it.
- Define deterministic mappings from Webex location/workspace/name metadata to known NETWORK branch identifiers; confirm what is reliable in the target tenant before enabling automatic branch association.
- Document API limits and any fields that are not available.

### Phase 1 — secure connection and read-only sync
- Add server-side connector configuration and connection-test endpoint.
- Add an explicit sync-run record, separate normalized snapshot tables, persistent serial-alert storage, and cached product lifecycle records.
- Implement paginated fetch, bounded retries/backoff, rate-limit handling, timeouts and safe error reporting.
- Implement unknown-serial detection and alert deduplication only after complete successful syncs.
- Add Cisco EoX lookup/caching for exact product IDs and define a lifecycle refresh strategy.
- Do not write to inventory tables or call Webex mutation APIs.

### Phase 2 — matching and review UI
- Add the admin connector page and sync status.
- Implement stable-ID/MAC matching and clearly labeled weaker suggestions.
- Show diff categories and source values; add CSV export if useful.
- Add an alert queue for Webex serials absent from Asset Client, with acknowledge/resolve and full history.
- Add the Dashboard **Device da gestire** count and work queue, combining incomplete Asset Client records with unresolved Webex matching, assignment, branch and lifecycle findings.
- Show product lifecycle milestones and their provenance, last-checked time, and upcoming lifecycle warnings.
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
- A failed or partial sync never causes records to be reported as deleted, creates false unknown-serial alerts, or silently changes inventory.
- A device serial observed in Webex but absent from Asset Client creates one persistent, deduplicated alert after a complete successful sync.
- Where Webex exposes it, each snapshot includes the device's assigned person or workspace and stable Webex identifier; differences from Asset Client assignment are shown for administrator review.
- A device can be associated to a branch automatically only when available Webex metadata resolves through an explicit, unambiguous mapping to a branch already present in NETWORK. Otherwise Asset Client shows a suggested branch and asks an administrator to confirm.
- Cisco lifecycle milestones are sourced from an official endpoint, preserve distinct date types, and display source plus last verification time.
- Match decisions are explainable and uncertain matches require human review.
- Branch truth continues to come from NETWORK.
- Admin can see sync history, errors, and comparison results.
- Dashboard **Device da gestire** lists unresolved incomplete records/findings with reasons and safe, reviewable completion actions.
- Automated tests verify that the connector never invokes Webex write operations.

## Out of scope for phase one

- Provisioning, deleting, renaming, moving or reconfiguring Webex devices.
- Automatically creating inventory records or changing branch assignments.
- Treating registration/online status as an authoritative hardware fault.
- Automatic write-back from Asset Client to Control Hub.

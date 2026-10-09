# Admin system health and Webex connector foundation

## Included in this pull request

- Admin-only **Amministrazione → Stato sistema** checks for API availability, PostgreSQL query, disk usage when exposed by the runtime, last Webex sync, and recent sync runs.
- Admin-only **Connettore Webex** view with connection configuration status, last run, record counts, read-only sync action, and serial alert queue.
- Server-side Webex Devices API pagination using `WEBEX_ACCESS_TOKEN`. The token is never returned to the browser or written to the sync snapshot.
- Separate snapshot, sync-run and alert tables created idempotently at application startup.
- Persistent, deduplicated alerts for Webex devices whose serial is not in the shared Asset Client inventory; a separate alert type is used when a serial is not exposed.
- Best-effort enrichment from Webex workspace, people and location directory APIs. Optional directory reads that are not authorized do not invalidate the device inventory sync; missing assignment/location details remain blank.
- A suggested branch only when a normalized location/workspace/device name exactly matches one known branch field. Suggestions never modify the asset or branch automatically.
- **Device da gestire** Dashboard entry and queue for incomplete Asset Client device data plus unresolved Webex alerts for administrators.
- A **Checklist** tab inside each branch detail page. It intentionally remains empty until the user supplies the technician checklist.
- Administrative actions flow through the existing audit middleware.

## Configuration

Set `WEBEX_ACCESS_TOKEN` in the server's secret store/environment. Do not commit a real token to `.env`, source control, browser storage or screenshots. Use a token authorized for the target organization and the minimum read scopes needed for the Devices API. To enrich assignment and location data, the token may also need read scopes for workspaces, people and locations. The connector does not request or use Webex write operations.

The token is currently supplied out-of-band by the administrator. Interactive OAuth authorization/refresh management is not part of this foundation and must be implemented before production rollout if a static token is not an acceptable operational model.

## Important limitations / follow-up

- Cisco EoX lifecycle lookup and its product-catalog UI are not implemented in this code change. The official API requires separate Cisco Support API credentials and must be added as a separate, verified integration. Do not interpret an empty lifecycle value as “not end-of-life”.
- Directory enrichment is best-effort; if the token lacks the relevant scopes, person/workspace/location names may not be available.
- Branch association is a suggestion only. Asset Client's NETWORK branch list remains authoritative, and this change does not write suggested assignments into inventory.
- Disk usage measures the filesystem visible from the API process working directory. If the application runs in a container, this may be the container filesystem rather than the host's total disk.
- The checklist tab is a placeholder only; no sample tasks or assumed procedures are seeded.

## Validation performed

JavaScript syntax parsing was run against `server/index.js` and `app/inventory.js`. No live Webex tenant, PostgreSQL deployment, browser, integration or end-to-end tests were available for this change. The token and scopes must be verified in the target tenant before relying on the sync.

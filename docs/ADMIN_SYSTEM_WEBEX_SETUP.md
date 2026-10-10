# Admin system health and Webex connector foundation

## Included in this pull request

- Admin-only **Amministrazione → Stato sistema** checks for API availability, PostgreSQL query, disk usage when exposed by the runtime, last Webex sync, and recent sync runs.
- Admin-only **Connettore Webex** view with connection configuration status, last run, record counts, read-only sync action, and serial alert queue.
- Server-side Webex Devices API pagination using `WEBEX_ACCESS_TOKEN`. The token is never returned to the browser or written to the sync snapshot.
- Separate snapshot, sync-run and alert tables created idempotently at application startup.
- Persistent, deduplicated alerts for Webex devices whose serial is not in the shared Asset Client inventory; a separate alert type is used when a serial is not exposed.
- Best-effort enrichment from Webex workspace, people and location directory APIs. Optional directory reads that are not authorized do not invalidate the device inventory sync; missing assignment/location details remain blank.
- A suggested branch only when a normalized location/workspace/device name exactly matches one known branch field. Suggestions never modify the asset or branch automatically.
- Cisco EoX lookup by exact PID using the official Cisco Support API, OAuth client-credentials token flow, cached lifecycle milestones and an administrator UI table.
- **Device da gestire** Dashboard entry and queue for incomplete Asset Client device data plus unresolved Webex alerts for administrators.
- A **Checklist** tab inside each branch detail page. It intentionally remains empty until the user supplies the technician checklist.
- Administrative actions flow through the existing audit middleware.

## Role test mode

An administrator can select **Amministratore** or **Operatore** from the account menu to test role-based navigation and server permissions without changing the stored account role or creating another user. The effective role is applied server-side for the current session, the UI shows a persistent **MODALITÀ TEST** banner, and the user can exit with **Termina test e torna admin**. Starting and stopping the mode is recorded by the existing audit middleware. Only the original authenticated administrator can start or stop this mode; it is not a way for an operator to gain administrator access. Use a non-production environment for destructive workflow testing, because actions allowed by the simulated role still affect the connected environment.

## Configuration

Set `WEBEX_ACCESS_TOKEN` in the server's secret store/environment. Do not commit a real token to `.env`, source control, browser storage or screenshots. Use a token authorized for the target organization and the minimum read scopes needed for the Devices API. To enrich assignment and location data, the token may also need read scopes for workspaces, people and locations. The connector does not request or use Webex write operations.

For Cisco lifecycle lookups, register an application in the Cisco API Console with Support APIs / EoX access and set `CISCO_EOX_CLIENT_ID` and `CISCO_EOX_CLIENT_SECRET` in the server secret store. The server obtains a short-lived access token from `https://id.cisco.com/oauth2/default/v1/token`; credentials and tokens are never sent to the browser. The admin UI accepts an exact PID and stores the returned EoX milestones with source and verification time.

The token is currently supplied out-of-band by the administrator. Interactive OAuth authorization/refresh management is not part of this foundation and must be implemented before production rollout if a static token is not an acceptable operational model.

## Important limitations / follow-up

- Cisco EoX lookup is available as an administrator-entered exact PID search in the Webex/admin area. Automatic scheduled refresh and integration of cached milestones directly into every product/device detail view are not implemented yet. An empty lifecycle value must not be interpreted as “not end-of-life”.
- Directory enrichment is best-effort; if the token lacks the relevant scopes, person/workspace/location names may not be available.
- Branch association is a suggestion only. Asset Client's NETWORK branch list remains authoritative, and this change does not write suggested assignments into inventory.
- Disk usage measures the filesystem visible from the API process working directory. If the application runs in a container, this may be the container filesystem rather than the host's total disk.
- The checklist tab is a placeholder only; no sample tasks or assumed procedures are seeded.

## Validation performed

JavaScript syntax parsing was run against `server/index.js` and `app/inventory.js`. No live Webex tenant, PostgreSQL deployment, browser, integration or end-to-end tests were available for this change. The token and scopes must be verified in the target tenant before relying on the sync.

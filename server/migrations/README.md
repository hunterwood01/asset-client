# Database migrations

Migrations are numbered SQL files and must be applied in order. The shared inventory schema in `001_shared_inventory.sql` is a design/migration artifact for the next API integration step; the current API startup does not automatically execute SQL files yet.

Before enabling it in production, add a migration runner with a `schema_migrations` table, run each migration transactionally, and verify the schema against an empty database and a restored test backup.

## Data rules represented

- `branches` represent customer sites.
- `warehouses` separate physical location from ownership. The seeded locations default to Molo STC (company-owned stock) and Magazzino Clerici (customer-owned stock).
- A device may be assigned to a branch or located in a warehouse, but not both at once.
- `owner_type` remains explicit on each device; warehouse defaults are not a substitute for the device's actual ownership.
- `stock_movements` records transfers and assignments without implying a new purchase.
- `license_purchases` records Webex and router license packages once; `license_allocations` links portions to branches without duplicating the purchase cost.
- `audit_log` provides the structure for traceable changes.

The migration references `app_users`, which is created by the authentication API in the preceding PR. Apply the authentication foundation before this migration.

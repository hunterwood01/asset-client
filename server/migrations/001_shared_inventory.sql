-- 001: Shared inventory, warehouse and audit data model.
-- Apply through the versioned migration runner introduced in the API integration step.
BEGIN;

CREATE TABLE IF NOT EXISTS branches (
  id BIGSERIAL PRIMARY KEY,
  company_name TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  code TEXT UNIQUE,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  phone_prefix TEXT NOT NULL DEFAULT '',
  network_lan TEXT NOT NULL DEFAULT '',
  network_services TEXT NOT NULL DEFAULT '',
  network_guest TEXT NOT NULL DEFAULT '',
  wlc TEXT NOT NULL DEFAULT '',
  voice TEXT NOT NULL DEFAULT '',
  old_name TEXT NOT NULL DEFAULT '',
  new_name TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (company_name, name)
);

CREATE TABLE IF NOT EXISTS warehouses (
  id BIGSERIAL PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  location_description TEXT NOT NULL DEFAULT '',
  default_owner TEXT NOT NULL CHECK (default_owner IN ('company', 'customer')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The two known stock locations have different default ownership:
-- Molo STC is company-owned stock; Magazzino Clerici is customer-owned stock.
INSERT INTO warehouses(code, name, location_description, default_owner)
VALUES
 ('MOLO_STC', 'Molo STC', 'Personal Data', 'company'),
 ('CLERICI', 'Magazzino Clerici', 'Clerici Canovetti', 'customer')
ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS devices (
  id BIGSERIAL PRIMARY KEY,
  serial TEXT NOT NULL UNIQUE,
  asset_tag TEXT UNIQUE,
  type TEXT NOT NULL,
  brand TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Disponibile',
  branch_id BIGINT REFERENCES branches(id) ON DELETE SET NULL,
  warehouse_id BIGINT REFERENCES warehouses(id) ON DELETE SET NULL,
  owner_type TEXT NOT NULL CHECK (owner_type IN ('company', 'customer', 'unknown')),
  assigned_to TEXT NOT NULL DEFAULT '',
  purchase_cost NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (purchase_cost >= 0),
  purchase_date DATE,
  activation_date DATE,
  monthly_fee NUMERIC(12,2) NOT NULL DEFAULT 0,
  useful_life_months INTEGER NOT NULL DEFAULT 36 CHECK (useful_life_months > 0),
  replaced_from BIGINT REFERENCES devices(id) ON DELETE SET NULL,
  notes TEXT NOT NULL DEFAULT '',
  lot_id TEXT,
  source_legacy_id TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (branch_id IS NULL OR warehouse_id IS NULL)
);
CREATE INDEX IF NOT EXISTS devices_branch_idx ON devices(branch_id);
CREATE INDEX IF NOT EXISTS devices_warehouse_idx ON devices(warehouse_id);
CREATE INDEX IF NOT EXISTS devices_type_status_idx ON devices(type, status);

CREATE TABLE IF NOT EXISTS stock_movements (
  id BIGSERIAL PRIMARY KEY,
  device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  movement_type TEXT NOT NULL CHECK (movement_type IN
    ('purchase', 'transfer', 'branch_assignment', 'return_to_stock', 'repair_out', 'repair_in', 'retirement', 'ownership_change')),
  from_warehouse_id BIGINT REFERENCES warehouses(id) ON DELETE RESTRICT,
  to_warehouse_id BIGINT REFERENCES warehouses(id) ON DELETE RESTRICT,
  from_branch_id BIGINT REFERENCES branches(id) ON DELETE RESTRICT,
  to_branch_id BIGINT REFERENCES branches(id) ON DELETE RESTRICT,
  owner_before TEXT CHECK (owner_before IN ('company', 'customer', 'unknown')),
  owner_after TEXT CHECK (owner_after IN ('company', 'customer', 'unknown')),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  performed_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  reference TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS stock_movements_device_date_idx ON stock_movements(device_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS license_purchases (
  id BIGSERIAL PRIMARY KEY,
  category TEXT NOT NULL CHECK (category IN ('webex', 'router')),
  supplier TEXT NOT NULL DEFAULT '',
  package_name TEXT NOT NULL,
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  unit_cost NUMERIC(12,2) NOT NULL CHECK (unit_cost >= 0),
  currency CHAR(3) NOT NULL DEFAULT 'EUR',
  purchase_date DATE NOT NULL,
  start_date DATE NOT NULL,
  expiry_date DATE NOT NULL,
  reference TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (expiry_date >= start_date)
);

CREATE TABLE IF NOT EXISTS license_allocations (
  id BIGSERIAL PRIMARY KEY,
  purchase_id BIGINT NOT NULL REFERENCES license_purchases(id) ON DELETE RESTRICT,
  branch_id BIGINT NOT NULL REFERENCES branches(id) ON DELETE RESTRICT,
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  assigned_at DATE NOT NULL DEFAULT CURRENT_DATE,
  released_at DATE,
  notes TEXT NOT NULL DEFAULT '',
  CHECK (released_at IS NULL OR released_at >= assigned_at)
);
CREATE INDEX IF NOT EXISTS license_allocations_active_idx ON license_allocations(purchase_id, released_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  actor_user_id BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  before_data JSONB,
  after_data JSONB,
  request_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS audit_log_entity_idx ON audit_log(entity_type, entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit_log(actor_user_id, created_at DESC);

COMMIT;

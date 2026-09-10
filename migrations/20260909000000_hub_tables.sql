-- Hub tables: agents, app events, key identity binding.
-- `system_metrics` and `log_entries` already exist in the initial schema and
-- are reused by the hub's ingestion paths.

-- Tracks connected agents. Identity originates from api_keys (the key row
-- carries the trusted agent_id/hostname); the wire protocol carries none.
CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- App events forwarded from web applications.
CREATE TABLE app_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id TEXT,
    payload JSONB NOT NULL DEFAULT '{}',
    timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_event_type CHECK (event_type ~ '^[a-z0-9_.:-]{1,64}$'),
    CONSTRAINT chk_user_id_len CHECK (user_id IS NULL OR length(user_id) <= 128),
    CONSTRAINT chk_app_name CHECK (app_name ~ '^[a-z0-9._-]{1,64}$')
);

CREATE INDEX idx_app_events_app_type ON app_events(app_name, event_type);
CREATE INDEX idx_app_events_timestamp ON app_events(timestamp DESC);
CREATE INDEX idx_app_events_user ON app_events(user_id, timestamp DESC);

-- Track which agent forwarded a log entry (value comes from the key row).
ALTER TABLE log_entries ADD COLUMN source_host TEXT;
CREATE INDEX idx_log_entries_source_host
    ON log_entries(source_host) WHERE source_host IS NOT NULL;

-- Attribute metrics to the reporting agent (value comes from the key row).
ALTER TABLE system_metrics ADD COLUMN host TEXT;
CREATE INDEX idx_system_metrics_host
    ON system_metrics(host, timestamp DESC) WHERE host IS NOT NULL;

-- API key identity binding: the key row is the single source of truth for
-- identity + permissions. `key_id` is a public, indexed lookup prefix that
-- avoids argon2-hashing against every row on each request.
ALTER TABLE api_keys ADD COLUMN key_id TEXT NOT NULL UNIQUE;
ALTER TABLE api_keys ADD COLUMN agent_id TEXT;
ALTER TABLE api_keys ADD COLUMN hostname TEXT;
ALTER TABLE api_keys ADD COLUMN app_name TEXT;
ALTER TABLE api_keys ADD COLUMN revoked_at TIMESTAMPTZ;

CREATE INDEX idx_api_keys_key_id ON api_keys(key_id) WHERE revoked_at IS NULL;

-- Bind each key to exactly one role: agent, app, or (both NULL) dashboard.
ALTER TABLE api_keys ADD CONSTRAINT chk_api_key_role CHECK (
    (agent_id IS NOT NULL AND app_name IS NULL)
    OR (agent_id IS NULL AND app_name IS NOT NULL)
    OR (agent_id IS NULL AND app_name IS NULL)
);

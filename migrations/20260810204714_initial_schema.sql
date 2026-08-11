-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Services table (vhosts, systemd services, etc.)
CREATE TABLE services (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL UNIQUE,
    unit_type TEXT NOT NULL,
    log_paths TEXT[],
    virtual_host TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Log entries table
CREATE TABLE log_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_id UUID REFERENCES services(id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    raw_line TEXT,
    client_ip INET,
    request_path TEXT,
    status_code SMALLINT,
    response_time_ms BIGINT,
    is_noise BOOLEAN NOT NULL DEFAULT FALSE,
    noise_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_log_entries_service_id ON log_entries(service_id);
CREATE INDEX idx_log_entries_timestamp ON log_entries(timestamp DESC);
CREATE INDEX idx_log_entries_level ON log_entries(level);
CREATE INDEX idx_log_entries_is_noise ON log_entries(is_noise) WHERE is_noise = FALSE;

-- System metrics table
CREATE TABLE system_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL,
    cpu_usage_percent DOUBLE PRECISION NOT NULL,
    memory_used_bytes BIGINT NOT NULL,
    memory_total_bytes BIGINT NOT NULL,
    disk_used_bytes BIGINT NOT NULL,
    disk_total_bytes BIGINT NOT NULL,
    load_avg_1m DOUBLE PRECISION NOT NULL,
    load_avg_5m DOUBLE PRECISION NOT NULL,
    network_rx_bytes BIGINT NOT NULL,
    network_tx_bytes BIGINT NOT NULL
);

CREATE INDEX idx_system_metrics_timestamp ON system_metrics(timestamp DESC);

-- Active sessions table
CREATE TABLE active_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user TEXT NOT NULL,
    terminal TEXT NOT NULL,
    source_ip INET,
    login_time TIMESTAMPTZ NOT NULL,
    idle_seconds BIGINT NOT NULL,
    pid INTEGER
);

-- Alerts table
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_id UUID REFERENCES services(id) ON DELETE SET NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_alerts_service_id ON alerts(service_id);
CREATE INDEX idx_alerts_resolved ON alerts(resolved) WHERE resolved = FALSE;

-- API keys table
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

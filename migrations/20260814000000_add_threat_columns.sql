-- Threat classification results, stored per entry so the TUI can display
-- them without re-running the classifier.
ALTER TABLE log_entries ADD COLUMN threat_level TEXT NOT NULL DEFAULT 'none';
ALTER TABLE log_entries ADD COLUMN threat_categories TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX idx_log_entries_threat_level ON log_entries(threat_level) WHERE threat_level <> 'none';

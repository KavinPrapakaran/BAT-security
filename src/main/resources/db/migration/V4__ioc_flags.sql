-- v1.1.1: persistent threat-intel IOC flags (survive restart)
CREATE TABLE ioc_flag (
    domain TEXT PRIMARY KEY,
    flag_count BIGINT NOT NULL DEFAULT 1,
    first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

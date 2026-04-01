CREATE TABLE IF NOT EXISTS submissions (
    id               TEXT PRIMARY KEY,
    hostname         TEXT NOT NULL,
    username         TEXT NOT NULL,
    submitted_at     TEXT NOT NULL,
    scan_timestamp   TEXT NOT NULL,
    duration         TEXT,
    verdict          TEXT NOT NULL,
    projects_scanned INTEGER,
    vulnerable_count INTEGER,
    critical_count   INTEGER,
    paths_scanned    TEXT,
    brief_key        TEXT NOT NULL,
    report_key       TEXT NOT NULL
);

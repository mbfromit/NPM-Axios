CREATE TABLE IF NOT EXISTS finding_ai_verdicts (
    id TEXT PRIMARY KEY,
    submission_id TEXT NOT NULL,
    finding_index INTEGER NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    verdict TEXT NOT NULL,
    reason TEXT,
    verified_at TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_faiv_submission ON finding_ai_verdicts(submission_id);

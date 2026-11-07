-- Existing installations with migration 003 applied: run this ONCE as schema owner.
USE cyberguard_db;
CREATE TABLE community_reports (
  report_id INT UNSIGNED NOT NULL PRIMARY KEY,
  submitted_url VARCHAR(2048) NULL,
  url_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  review_note VARCHAR(1000) NOT NULL DEFAULT '',
  reviewed_at DATETIME NULL,
  expires_at DATETIME NULL,
  INDEX community_lookup (url_hash,status,expires_at),
  CONSTRAINT community_report_fk FOREIGN KEY (report_id) REFERENCES reports(report_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- Earlier user reports remain available for review; they have no structured URL.
INSERT INTO community_reports (report_id) SELECT report_id FROM reports WHERE source='user';

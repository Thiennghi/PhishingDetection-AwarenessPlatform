-- Existing installations: run ONCE as schema owner (after 003/004). Back up first.
USE cyberguard_db;
-- scan_summaries: one stored summary per scan (id, result, recommendation, cited detection sources).
CREATE TABLE scan_summaries (
  summary_id     INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  scan_id        INT UNSIGNED NOT NULL,
  report_id      INT UNSIGNED NULL,
  classification VARCHAR(50)  NOT NULL,
  risk_score     TINYINT UNSIGNED NOT NULL,
  recommendation VARCHAR(255) NOT NULL,
  source_ids     VARCHAR(255) NOT NULL DEFAULT '',
  created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_summary_scan (scan_id),
  KEY idx_summary_created (created_at),
  CONSTRAINT fk_summary_scan   FOREIGN KEY (scan_id)   REFERENCES scans(scan_id)     ON DELETE CASCADE,
  CONSTRAINT fk_summary_report FOREIGN KEY (report_id) REFERENCES reports(report_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Backfill a summary for scans that already exist (same wording as scanSummary.php).
INSERT INTO scan_summaries (scan_id, report_id, classification, risk_score, recommendation, source_ids)
SELECT s.scan_id,
       (SELECT MAX(r.report_id) FROM reports r WHERE r.scan_id = s.scan_id),
       s.classification, s.risk_score,
       CASE s.classification
         WHEN 'HIGH RISK'  THEN 'Do not click links, open attachments or share information. Report it.'
         WHEN 'SUSPICIOUS' THEN 'Verify the sender and destination independently before acting.'
         ELSE 'Low risk is not proof of safety. Verify unexpected requests independently.'
       END,
       ''
  FROM scans s;

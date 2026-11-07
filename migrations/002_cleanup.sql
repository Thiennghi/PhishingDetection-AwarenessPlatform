-- Migration for an EXISTING cyberguard_db created from the old "cyberguard_db (1).sql".
-- BACK UP FIRST:  mysqldump -u root -p cyberguard_db > backup.sql
-- Run once:       mysql -u root -p cyberguard_db < migrations/002_cleanup.sql

USE `cyberguard_db`;

-- 1. Drop foreign keys so the column types can be changed
ALTER TABLE `reports` DROP FOREIGN KEY `reports_ibfk_1`;
ALTER TABLE `scans`   DROP FOREIGN KEY `scans_ibfk_1`;

-- 2. users table + scans.user_id were never used (nothing creates users)
ALTER TABLE `scans` DROP COLUMN `user_id`;
DROP TABLE IF EXISTS `users`;

-- 3. Proper types (int(50) display widths are meaningless) + new columns/indexes
ALTER TABLE `scans`
  MODIFY `scan_id`        INT UNSIGNED NOT NULL AUTO_INCREMENT,
  MODIFY `input_type`     VARCHAR(50)  NOT NULL DEFAULT 'text',
  MODIFY `classification` VARCHAR(50)  NOT NULL,
  MODIFY `risk_score`     TINYINT UNSIGNED NOT NULL,
  ADD COLUMN `input_length` INT UNSIGNED NOT NULL DEFAULT 0 AFTER `risk_score`,
  ADD KEY `idx_scans_created_at` (`created_at`);

ALTER TABLE `reports`
  MODIFY `report_id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  MODIFY `scan_id`   INT UNSIGNED DEFAULT NULL,
  ADD COLUMN `source` ENUM('scan','user') NOT NULL DEFAULT 'scan' AFTER `scan_id`,
  ADD KEY `idx_reports_created_at` (`created_at`);

ALTER TABLE `reports`
  ADD CONSTRAINT `fk_reports_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`scan_id`) ON DELETE SET NULL;

-- 4. Privacy: old descriptions contained the first 35 characters of the user's pasted message.
UPDATE `reports` r
  JOIN `scans` s ON s.scan_id = r.scan_id
   SET r.description = CONCAT('Scan classified ', s.classification, ' with a risk score of ', s.risk_score, '/100.')
 WHERE r.source = 'scan';

-- 5. Collation
ALTER TABLE `scans`   CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE `reports` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. Rate limiting table
CREATE TABLE IF NOT EXISTS `rate_limits` (
  `ip`           VARCHAR(45)  NOT NULL,
  `bucket`       VARCHAR(50)  NOT NULL,
  `window_start` INT UNSIGNED NOT NULL,
  `hits`         INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (`ip`, `bucket`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

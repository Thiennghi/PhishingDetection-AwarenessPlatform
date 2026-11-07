-- Run ONCE after 002_cleanup.sql, with a schema owner. Back up first.
USE cyberguard_db;
ALTER TABLE scans ADD detector_version VARCHAR(40) NULL,
  ADD evidence_json TEXT NULL;
CREATE TABLE detection_sources (
  source_id VARCHAR(50) NOT NULL PRIMARY KEY,
  publisher VARCHAR(100) NOT NULL,
  title VARCHAR(255) NOT NULL,
  url VARCHAR(1000) NOT NULL,
  reviewed_on DATE NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE detection_rules (
  rule_id VARCHAR(60) NOT NULL PRIMARY KEY,
  dataset_version VARCHAR(40) NOT NULL,
  rule_json TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE threat_indicators (
  url_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_id VARCHAR(50) NOT NULL,
  imported_at DATETIME NOT NULL,
  expires_at DATETIME NOT NULL,
  PRIMARY KEY (url_hash,source_id),
  INDEX indicators_expiry (expires_at),
  CONSTRAINT indicator_source FOREIGN KEY (source_id) REFERENCES detection_sources(source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- Next import data/detection_seed.sql.

# CyberGuard — Message and URL Checker

Updated from the supplied **Team-2-Phishing-Detection-and-Awareness-Platform-main (2).zip**. Keeps PHP 8.0+, vanilla JavaScript, existing database rate limits, session handling and CSP-compatible button events.

## Use the link checker

1. Open the Analyze tab.
2. Select **Links / URLs only**.
3. Paste an HTTP(S) URL, a domain such as `example.com/login`, or up to 20 URLs separated by whitespace/newlines.
4. Click Analyze. Each link has a hostname, risk score, assessment, reasons and reputation status.

Pasting a message in Message mode also produces individual results for detected links. The Deceptive Link and Dangerous Download samples use reserved `.test` hosts, not live attack sites.

- **HIGH RISK**: strong phishing/scam/download indicators, or an active phishing-feed match.
- **SUSPICIOUS**: URL characteristics warrant independent checking.
- **UNVERIFIED**: no strong URL indicator was found. This does not mean the site is safe.

A feed match is labeled REPORTED PHISHING; heuristic findings use POSSIBLE PHISHING, POSSIBLE SCAM, or DANGEROUS DOWNLOAD INDICATORS. HTTPS, a known brand domain, a low score or a feed miss is never a safe-link certification. Shortened links are not expanded; their final destination remains unverified.

Submitted links are never opened, fetched, resolved or executed. Results display defanged, non-clickable text. Scans store fixed indicator metadata, detector version, score and input length—not the original pasted URLs or messages. User-submitted threat reports still retain descriptions under the existing report behavior.

## Setup / database update

Requirements: PHP 8.0+ with mysqli, mbstring and sessions; MariaDB 10.4+ or MySQL 8.0; optional Node/Python for tests and data maintenance. Use a supported PHP release for public hosting.

**Fresh database:** import `cyberguard_db.sql`. It includes the existing scans/reports/rate_limits tables plus detection data. Do not import it over existing tables.

**Database matching the ZIP you just uploaded:** back up first, import `migrations/003_detection.sql` once, then `data/detection_seed.sql`. Migration 002 was already reflected in that ZIP's schema; do not rerun it. If detection_sources/detection_rules/threat_indicators and scans.detector_version/evidence_json already exist, import only the current seed.

For XAMPP, place the extracted folder inside `htdocs`, start Apache/MySQL, and use the supplied `config_local_live.php` (live block = placeholders until you deploy). Confirm these local settings:

```php
<?php
return [
    'env' => 'development',
    'db' => ['host' => '127.0.0.1', 'user' => 'root', 'pass' => '', 'name' => 'cyberguard_db'],
];
```

Visit `http://localhost/<folder>/index.html`. Alternatively, from the folder run `APP_ENV=development php -S localhost:8000` and visit `http://localhost:8000/index.html`. PHP cannot run by double-clicking index.html or on the existing Cloudflare Workers static demo as written.


## Database connection (live + XAMPP)

Every request tries the live database first (`db.live` in `config_local_live.php`, or `DB_HOST`/`DB_USER`/`DB_PASS`/`DB_NAME`), then local XAMPP (`127.0.0.1`, `root`), then returns "Database connection failed". Admin login, sessions and CSRF are unchanged.

- XAMPP: import `cyberguard_db.sql`, then `data/detection_seed.sql`.
- InfinityFree / shared host: create the database in the panel, select it in phpMyAdmin, import `cyberguard_db_infinityfree.sql` (drops and recreates the tables; no DROP DATABASE).
- `cyberguard_db.sql` and `migrations/` are unchanged (used by the rule generator and for upgrading an existing database).

## Scan History (Dashboard)

Dashboard > **Scan History** opens a panel (Close button or click again to hide) that reads `cyberguard_db` through `history.php`: scans, reports and threat indicators, plus database totals. Private user-report text is never shown.

The panel opens with a live summary: scan classification counts, community-report statuses (they change as soon as an administrator approves or rejects a report), the detection sources with how many scans cited each, the latest recommendation, and a **Summary history** table. Each scan stores one summary row (`scan_summaries`: id, scan ID, report ID, result, score, recommendation, cited source IDs) through `scanSummary.php`; scoring is unchanged and a missing table never breaks a scan. Existing databases: import `migrations/005_scan_summaries.sql` once (it also backfills old scans). Runtime database users need SELECT/INSERT on `scan_summaries`.

**Reset session & go home** permanently deletes every row in `scans`, `reports`, `community_reports` and `scan_summaries` (including pending and approved community reports), clears all text, results and the assistant chat on the page, and returns to the home tab. Detection sources, rules and threat indicators are kept. This endpoint has no admin check, so for a public deployment remove the `reset-all` button or protect `history.php` reset.

## Configuration / deployment

The latest upload's configuration remains: APP_ENV (production by default), DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS, ADMIN_USERNAME, ADMIN_PASSWORD_HASH, ADMIN_SECRET_TOKEN and TRUST_PROXY. Production requires database and admin secrets. Local overrides use the `env` key. `.env` files are ignored but not automatically loaded. Do not commit config_local_live.php or actual secrets.

Generate an admin hash with `php -r "echo password_hash('yourpass', PASSWORD_DEFAULT);"`. Existing admin/report endpoints remain; the public Clear button only clears the screen. Rate limits remain database-backed. The frontend preserves one CSRF refresh/retry after a 403.

Database permissions: runtime scanning needs SELECT/INSERT/DELETE on scans/reports, SELECT on detection_sources/detection_rules/threat_indicators, and SELECT/INSERT/UPDATE/DELETE on rate_limits. Use a separate owner for imports/migrations. The uploaded admin-clear endpoint retains its AUTO_INCREMENT resets and therefore requires ALTER on scans/reports if you use it; do not expose its credentials publicly. Feed operators need INSERT/DELETE on threat_indicators. Apply security headers to static index.html through your production web server; PHP response headers alone do not protect the HTML document. Block public access to SQL, local config, tests and scripts. Keep display_errors off.

## Detection data and known-phishing records

`data/detection-knowledge.json` is the canonical release: **78 rules, including 18 dedicated URL checks**, plus 15 source records. It draws on FTC, FBI/IC3 and Microsoft guidance. Rule weights are project choices, not agency-endorsed scores. The database and browser copy must match the same release, `2026.10.07-v3`.

Checks include deceptive brand subdomains, brand-like login hosts, user information before @, limited mixed-script lookalikes, encoded authority, executable/double-extension paths, secret query parameters, scam-style URL lures and visible embedded redirect targets. Redirect targets can be inspected up to two nested levels without following them. Brand reference lists and lookalike coverage are incomplete. No whole-site or download malware verdict is possible from a URL string alone.

No live feed is bundled. To enable known-phishing URL matching, obtain a recent authorized community snapshot from [OpenPhish's official feed page](https://www.openphish.com/phishing_feeds.html), under its terms. Then run:

```bash
php scripts/import_openphish.php /absolute/path/feed.txt ACTUAL_UTC_DOWNLOAD_TIME
# Timestamp format: 2026-10-07T23:00:00Z. Use the real download time, not this example.
```

The timestamp must be within 12 hours. The importer stores exact normalized URL hashes, expires them 24 hours after the supplied download time, and atomically replaces that source's previous snapshot. It does not fetch any feed or submitted website. A source miss is not a safety guarantee. Refresh snapshots when operating the app; no scheduler is installed. Direct and visible embedded URLs are checked individually; a hit on one link does not falsely mark other links as feed matches.

The URL normalization is deliberately limited; this is not Google Safe Browsing, VirusTotal, an antivirus engine or a complete browser URL parser. Redirects, URL aliases, punycode variants and new threats may be missed. No DNS, WHOIS/domain-age query, QR decoding, website screenshot, email-header authentication or attachment sandbox is included. Unknown links remain unverified.

For rule updates: edit JSON, bump its version, run `python3 scripts/build_detection_data.py`, test, import the generated seed as owner, and deploy matching assets. The generator updates phishingData.js, data/detection_seed.sql and the seed portion of cyberguard_db.sql. User reports are not automatically promoted to detection rules or feed records.

## Tests

```bash
python3 scripts/build_detection_data.py --check
node tests/detection.test.cjs
node tests/urls.test.cjs
node tests/frontend.test.cjs
node tests/parity.test.cjs
# On a host with PHP installed:
php tests/detection.test.php
php tests/urls.test.php
```

86 message cases and 34 URL cases pass in JavaScript, plus mocked frontend behavior checks. These authored synthetic cases were used during development and are not real-world accuracy measurements. PHP lint/execution, database import and end-to-end behavior remain unverified here because PHP/MariaDB are unavailable. The PHP test and parity runner are supplied for your host.

This project uses explainable rules, not a trained model or calibrated probabilities.

## October 12 update: interface, awareness, and community reporting

The interface uses a responsive charcoal/mint design inspired by the supplied reference.
The Awareness tab now contains ten searchable educational topics and source links. It
works without a database and no longer attempts to show scan history as education.

**Upgrade from the previous URL-checker ZIP:** back up your database, replace the app
files while keeping your own `config_local_live.php`, then import
`migrations/004_community_reports.sql` ONCE. Migration 003 and the detection seed must
already be installed. A fresh installation needs only `cyberguard_db.sql`, which now
includes the community table. Do not import the fresh schema over an existing database.
Use PHP 8.1+ with mysqli/mysqlnd and mbstring, and MySQL/MariaDB. Static hosting alone
can display the guide and local analysis but cannot save or review reports.

### Reporting and review

1. Analyze a link or message. Choose **Report this link** or **Report this content**.
2. Review the prefilled URL, choose phishing/scam/malicious URL, and optionally explain
   the concern. You can also enter a URL directly in the Report tab.
3. Submit. A successful server response displays a report number and pending status.
   A failed request preserves the form and never claims it was saved.
4. Open `admin.html` from the footer and sign in with the configured administrator
   username/password. Set `admin.password_hash` in `config_local_live.php` to the result of
   PHP `password_hash()` for a strong password (or use `ADMIN_PASSWORD_HASH`). No
   default password is shipped. Existing production configuration checks still apply.
5. Independently investigate the evidence, enter a review note, and approve or reject.
   Approvals participate in exact canonical URL matching for 30 days. Re-approval
   renews the period. Reject/revoke removes that report from future matches. Other
   approved reports for the same URL can still apply; revoke each when correcting it.

Reports are private to authenticated administrators, not published in scan history.
The report form stores the submitted URL and description; remove personal information
first. Ordinary scans continue to store summaries without the original input. A
redacted URL may not match its original address. Reports are not sent to the FTC,
OpenPhish, or any external service. Reports do not retrain a model or change rule weights.
Message-only reports are reviewable but cannot be approved as URL indicators.

Approved matches score at least 95 and retain the reviewer-selected threat category.
Only the submitted URL and visible embedded destinations are checked. No page is
visited, redirect followed, or download executed. Unknown links remain unverified.
The admin queue displays up to 100 reports, pending first. Older records remain in SQL.
The last review decision/note is retained; this is not a full immutable audit system.

### Verification for this update

`node tests/frontend.test.cjs` covers the awareness table/search, report prefill,
URL-only submission, server success/failure, CSRF header, safe rendering, and existing
scan workflows with mocked DOM/HTTP. Detection regression tests contain 86 message
and 34 URL fixtures; these are synthetic regressions, not measured real-world accuracy.
See `tests/community.integration.php` for database-backed approval/revocation
checks on a configured local development server.

`node tests/admin.test.cjs` also passes mocked administrator login, safe rendering,
review-note validation, approval/rejection requests, and logout tests. PHP execution,
SQL imports, live API integration, and browser visual QA were not verified in the
build environment: PHP/MySQL were unavailable and the Chromium download failed.
Run the supplied PHP tests and integration test on a disposable local database before
production use.

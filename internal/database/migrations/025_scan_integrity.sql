-- 025_scan_integrity.sql
-- ADR-015: synchronous plaintext malware scanning.
--
-- Adds error_code to partial_uploads for machine-readable chunked-upload
-- assembly failure reasons (e.g. MALWARE_DETECTED, SCAN_UNAVAILABLE).
--
-- Relabels legacy files.scan_status values that predate ADR-015. Under the
-- old asynchronous design the scanner ran against the file as stored on
-- disk, which is ciphertext whenever ENCRYPTION_KEY is set — so a "clean"
-- verdict from that era may never have inspected real content. "pending"
-- means a scan was in-flight or never completed (the old worker could die
-- mid-scan), and "error" means the scan itself failed. None of those three
-- are trustworthy under the new fail-closed download gate (claim.go's
-- scanGate), so they are relabelled "not_scanned" rather than either newly
-- blocking downloads that were previously permitted (pending/error) or
-- trusting a verdict that may have been computed against the wrong bytes
-- (clean). "infected" rows are left as-is: that verdict is meaningful
-- regardless of which bytes were scanned.
ALTER TABLE partial_uploads ADD COLUMN error_code TEXT DEFAULT NULL;

UPDATE files
SET scan_status = 'not_scanned',
    scan_result = 'legacy: pre-ADR-015 scan not trusted'
WHERE scan_status IN ('clean', 'pending', 'error');

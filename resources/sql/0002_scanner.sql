-- Multi-scanner readiness (spec §5.6). Nullable columns only, so identities
-- do not renumber when Grype/SBOM ingestion lands.
ALTER TABLE scan    ADD COLUMN IF NOT EXISTS scanner         VARCHAR DEFAULT 'trivy';
ALTER TABLE finding ADD COLUMN IF NOT EXISTS scanner_native  JSON;

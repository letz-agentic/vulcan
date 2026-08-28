-- Vulcan V — initial schema (spec §5.2)
-- Append-only with idempotent upsert; identity is content-derived.

CREATE TABLE IF NOT EXISTS schema_migration (
  version        INTEGER PRIMARY KEY,
  name           VARCHAR NOT NULL,
  applied_at     TIMESTAMP NOT NULL,
  duckdb_version VARCHAR NOT NULL
);

-- One row per ingested report file
CREATE TABLE IF NOT EXISTS scan (
  scan_id          VARCHAR PRIMARY KEY,   -- sha256 of report bytes
  schema_version   INTEGER NOT NULL,      -- Trivy SchemaVersion (2)
  created_at       TIMESTAMP NOT NULL,    -- report CreatedAt
  ingested_at      TIMESTAMP NOT NULL,
  artifact_name    VARCHAR NOT NULL,      -- e.g. registry/app:1.2.3
  artifact_type    VARCHAR NOT NULL,      -- container_image | filesystem | repository | ...
  image_id         VARCHAR,               -- Metadata.ImageID
  repo_digests     VARCHAR[],             -- Metadata.RepoDigests
  os_family        VARCHAR,
  os_name          VARCHAR,
  os_eosl          BOOLEAN,
  trivy_version    VARCHAR,
  source_file      VARCHAR NOT NULL,
  raw              JSON
);

-- One row per Results[] entry
CREATE TABLE IF NOT EXISTS target (
  target_id   VARCHAR PRIMARY KEY,        -- hash(scan_id, target, class, type)
  scan_id     VARCHAR NOT NULL REFERENCES scan(scan_id),
  target      VARCHAR NOT NULL,
  class       VARCHAR NOT NULL,           -- os-pkgs | lang-pkgs | config | secret | license
  type        VARCHAR
);

-- One row per Vulnerabilities[] entry (the fact table)
CREATE TABLE IF NOT EXISTS finding (
  finding_id         VARCHAR PRIMARY KEY,
  scan_id            VARCHAR NOT NULL REFERENCES scan(scan_id),
  target_id          VARCHAR NOT NULL REFERENCES target(target_id),
  vulnerability_id   VARCHAR NOT NULL,
  pkg_id             VARCHAR,
  pkg_name           VARCHAR NOT NULL,
  purl               VARCHAR,
  installed_version  VARCHAR NOT NULL,
  fixed_version      VARCHAR,
  status             VARCHAR NOT NULL,
  severity           VARCHAR NOT NULL,
  severity_source    VARCHAR,
  cvss               JSON,
  cvss_v3_score      DOUBLE,
  cvss_v3_vector     VARCHAR,
  cwe_ids            VARCHAR[],
  published_date     TIMESTAMP,
  last_modified_date TIMESTAMP,
  layer_digest       VARCHAR,
  layer_diff_id      VARCHAR,
  data_source        JSON,
  title              VARCHAR,
  refs               VARCHAR[]
);

-- Packages from --list-all-pkgs (spec §13 open question 3: included in 0001,
-- because it is cheap at ingest and painful to backfill).
CREATE TABLE IF NOT EXISTS package (
  package_row_id VARCHAR PRIMARY KEY,     -- hash(target_id, pkg_id|name, version)
  scan_id        VARCHAR NOT NULL REFERENCES scan(scan_id),
  target_id      VARCHAR NOT NULL REFERENCES target(target_id),
  pkg_id         VARCHAR,
  pkg_name       VARCHAR NOT NULL,
  version        VARCHAR NOT NULL,
  release        VARCHAR,
  epoch          INTEGER,
  arch           VARCHAR,
  purl           VARCHAR,
  licenses       VARCHAR[],
  indirect       BOOLEAN,
  layer_digest   VARCHAR
);

-- Vulnerability dimension (one row per ID, enriched; independent of scans)
CREATE TABLE IF NOT EXISTS vulnerability (
  vulnerability_id  VARCHAR PRIMARY KEY,
  description       VARCHAR,
  epss_score        DOUBLE,
  epss_percentile   DOUBLE,
  epss_date         DATE,
  kev               BOOLEAN DEFAULT FALSE,
  kev_date_added    DATE,
  kev_ransomware    BOOLEAN,
  sightings_count   INTEGER,
  circl_fetched_at  TIMESTAMP,
  circl_raw         JSON
);

-- Human decisions: VEX-like statements and time-boxed exceptions
CREATE TABLE IF NOT EXISTS decision (
  decision_id       VARCHAR PRIMARY KEY,
  vulnerability_id  VARCHAR NOT NULL,
  scope             VARCHAR NOT NULL,     -- purl | artifact_name | '*' pattern
  status            VARCHAR NOT NULL,     -- OpenVEX status
  justification     VARCHAR,
  note              VARCHAR,
  decided_by        VARCHAR,
  decided_at        TIMESTAMP,
  expires_at        TIMESTAMP,
  source            VARCHAR
);

CREATE TABLE IF NOT EXISTS ingest_log (
  scan_id     VARCHAR,
  source_file VARCHAR,
  ingested_at TIMESTAMP,
  outcome     VARCHAR,  -- inserted | duplicate | rejected
  message     VARCHAR
);

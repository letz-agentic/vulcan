-- Views are the contract between store and analysis (spec §5.4).
-- Notebooks query views (via the analysis layer), never base tables.

CREATE OR REPLACE VIEW v_finding_enriched AS
SELECT
  f.finding_id,
  f.scan_id,
  f.target_id,
  f.vulnerability_id,
  f.pkg_id,
  f.pkg_name,
  f.purl,
  f.installed_version,
  f.fixed_version,
  f.status,
  f.severity,
  f.severity_source,
  f.cvss_v3_score,
  f.cvss_v3_vector,
  f.cwe_ids,
  f.published_date,
  f.last_modified_date,
  f.layer_digest,
  f.title,
  t.target,
  t.class      AS target_class,
  t.type       AS target_type,
  s.artifact_name,
  s.artifact_type,
  s.os_family,
  s.os_name,
  s.os_eosl,
  s.created_at AS scan_created_at,
  s.trivy_version,
  v.epss_score,
  v.epss_percentile,
  v.kev,
  v.kev_ransomware,
  v.sightings_count,
  v.description,
  v.circl_fetched_at,
  -- derived
  (f.status = 'fixed' AND f.fixed_version IS NOT NULL AND f.fixed_version <> '')
                                                            AS is_fixable,
  CASE WHEN f.published_date IS NULL THEN NULL
       ELSE date_diff('day', f.published_date, s.created_at) END
                                                            AS age_days,
  (COALESCE(v.kev, FALSE) OR COALESCE(v.sightings_count, 0) > 0)
                                                            AS exploited,
  d.decision_id,
  d.status        AS decision_status,
  d.justification AS decision_justification,
  d.expires_at    AS decision_expires_at
FROM finding f
JOIN scan   s ON s.scan_id   = f.scan_id
JOIN target t ON t.target_id = f.target_id
LEFT JOIN vulnerability v ON v.vulnerability_id = f.vulnerability_id
LEFT JOIN decision d
       ON d.vulnerability_id = f.vulnerability_id
      AND (d.expires_at IS NULL OR d.expires_at > s.created_at)
      AND (d.scope = '*'
           OR d.scope = s.artifact_name
           OR d.scope = f.purl
           OR s.artifact_name LIKE replace(d.scope, '*', '%')
           OR COALESCE(f.purl, '') LIKE replace(d.scope, '*', '%'));

CREATE OR REPLACE VIEW v_latest_scan_per_artifact AS
SELECT * EXCLUDE (rn)
FROM (SELECT s.*,
             row_number() OVER (PARTITION BY s.artifact_name
                                ORDER BY s.created_at DESC, s.scan_id) AS rn
      FROM scan s)
WHERE rn = 1;

CREATE OR REPLACE VIEW v_scan_summary AS
SELECT
  s.scan_id,
  s.artifact_name,
  s.artifact_type,
  s.created_at,
  count(f.finding_id)                                              AS n_findings,
  count(*) FILTER (f.severity = 'CRITICAL')                        AS n_critical,
  count(*) FILTER (f.severity = 'HIGH')                            AS n_high,
  count(*) FILTER (f.severity = 'MEDIUM')                          AS n_medium,
  count(*) FILTER (f.severity = 'LOW')                             AS n_low,
  count(*) FILTER (f.severity = 'UNKNOWN')                         AS n_unknown,
  count(*) FILTER (f.status = 'fixed'   AND f.fixed_version IS NOT NULL) AS n_fixable,
  count(*) FILTER (f.status IN ('will_not_fix','end_of_life'))     AS n_vendor_declined,
  count(DISTINCT f.vulnerability_id)                               AS n_distinct_vulns,
  count(DISTINCT f.pkg_name)                                       AS n_affected_pkgs
FROM scan s
LEFT JOIN finding f ON f.scan_id = s.scan_id
GROUP BY ALL;

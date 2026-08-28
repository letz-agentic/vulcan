(ns vulcan.ingest.trivy
  "Trivy report -> row maps (spec section 6.2).

  `report->rows` is a *pure* function from a parsed report to
  `{:scan m :targets [..] :findings [..] :packages [..]}`. It touches no
  database and no clock beyond the `ingested-at` passed in, which is what
  makes it the unit under test and what makes ingestion reproducible.

  Identity (spec section 5.1) is content-derived so that two stores built
  independently can be merged with `INSERT ... ON CONFLICT DO NOTHING`:

    scan_id    = sha256(report bytes)                      -- caller supplies
    target_id  = sha256(scan_id, target, class, type)
    finding_id = sha256(scan_id, target, vuln_id, pkg_id, installed_version)"
  (:require [clojure.string :as str]
            [vulcan.ingest.json :as vj])
  (:import (java.time Instant OffsetDateTime)
           (java.time.format DateTimeParseException)))

;; ---------------------------------------------------------------------------
;; identity

(defn hash-id
  "Content-derived id: SHA-256 over the parts.

  The parts are hashed as a *printed vector*, not a joined string: every
  plausible separator can legitimately occur inside a Trivy target or PURL,
  and [\"ab\" \"c\"] must not collide with [\"a\" \"bc\"]. `pr-str` quotes and
  escapes each part, so the encoding is unambiguous; it is stable across
  platforms because the structure it adds is pure ASCII."
  [& parts]
  (vj/sha256 (.getBytes (pr-str (mapv #(or % "") parts)) "UTF-8")))

;; ---------------------------------------------------------------------------
;; coercions

(defn ->instant
  "Trivy emits RFC-3339 with an offset and sometimes with a `Z`. Anything
  unparseable becomes nil rather than failing the whole report: a missing date
  is a gap in analysis, not a corrupt file."
  [s]
  (when-not (str/blank? s)
    (try
      (.toInstant (OffsetDateTime/parse s))
      (catch DateTimeParseException _
        (try (Instant/parse s) (catch DateTimeParseException _ nil))))))

(defn- non-blank [s] (when-not (str/blank? s) s))

(defn- str-vec
  "A `VARCHAR[]` column as a plain Clojure vector; nil for an empty list, so
  the column stays NULL rather than becoming an empty array.

  Deliberately *not* a Java array here. Row maps are values: they are compared
  in tests, round-tripped through golden EDN, and printed at the REPL, none of
  which survive a `String[]` (arrays compare by identity). The conversion to a
  JDBC array happens once, at bind time, in `vulcan.store.write`."
  [xs]
  (when (seq xs)
    (mapv str xs)))

(defn- dedupe-by
  "Last-wins dedupe preserving first-seen order. Trivy can list the same CVE
  for the same package twice across advisories; collapsing here rather than
  leaning on `ON CONFLICT` keeps the returned counts equal to what lands."
  [k rows]
  (->> rows (reduce (fn [acc r] (assoc acc (k r) r)) (array-map)) vals vec))

;; ---------------------------------------------------------------------------
;; CVSS

(defn best-cvss-v3
  "Best available V3 base score and vector, as `{:score :vector :source}`.
  Prefers NVD, then the source Trivy used to choose the severity, then the
  highest V3 score on offer (spec section 6.2)."
  [cvss severity-source]
  (let [entries (for [[k m] cvss
                      :let [score (:V3Score m)]
                      :when (number? score)]
                  {:source (name k) :score (double score) :vector (:V3Vector m)})
        by-src  (into {} (map (juxt :source identity)) entries)]
    (or (get by-src "nvd")
        (get by-src (some-> severity-source str/lower-case))
        (when (seq entries) (apply max-key :score entries)))))

;; ---------------------------------------------------------------------------
;; normalisation

(defn- scan-row
  [report {:keys [scan-id source-file ingested-at]}]
  (let [md (:Metadata report)
        os (:OS md)]
    {:scan_id        scan-id
     :schema_version (:SchemaVersion report)
     :created_at     (->instant (:CreatedAt report))
     :ingested_at    ingested-at
     :artifact_name  (or (non-blank (:ArtifactName report)) "unknown")
     :artifact_type  (or (non-blank (:ArtifactType report)) "unknown")
     :image_id       (non-blank (:ImageID md))
     :repo_digests   (str-vec (:RepoDigests md))
     :os_family      (non-blank (:Family os))
     :os_name        (non-blank (:Name os))
     :os_eosl        (boolean (:EOSL os))
     :trivy_version  (non-blank (get-in report [:Trivy :Version]))
     :source_file    source-file
     :raw            (vj/write-str report)
     :scanner        "trivy"}))

(defn- target-row
  [scan-id {:keys [Target Class Type]}]
  {:target_id (hash-id scan-id Target Class Type)
   :scan_id   scan-id
   :target    Target
   :class     (or (non-blank Class) "unknown")
   :type      (non-blank Type)})

(defn- finding-row
  [scan-id target-id target v]
  (let [cvss   (:CVSS v)
        best   (best-cvss-v3 cvss (:SeveritySource v))
        pkg-id (or (non-blank (:PkgID v)) (:PkgName v))]
    {:finding_id         (hash-id scan-id target (:VulnerabilityID v)
                                  pkg-id (:InstalledVersion v))
     :scan_id            scan-id
     :target_id          target-id
     :vulnerability_id   (:VulnerabilityID v)
     :pkg_id             (non-blank (:PkgID v))
     :pkg_name           (or (non-blank (:PkgName v)) "unknown")
     :purl               (non-blank (get-in v [:PkgIdentifier :PURL]))
     :installed_version  (or (non-blank (:InstalledVersion v)) "")
     :fixed_version      (non-blank (:FixedVersion v))
     ;; Trivy omits Status on some ecosystems; "unknown" is one of its own
     ;; eight values (spec section 5.3), so store and scanner still agree.
     :status             (or (non-blank (:Status v)) "unknown")
     :severity           (or (non-blank (:Severity v)) "UNKNOWN")
     :severity_source    (non-blank (:SeveritySource v))
     :cvss               (when (seq cvss) (vj/write-str cvss))
     :cvss_v3_score      (:score best)
     :cvss_v3_vector     (:vector best)
     :cwe_ids            (str-vec (:CweIDs v))
     :published_date     (->instant (:PublishedDate v))
     :last_modified_date (->instant (:LastModifiedDate v))
     :layer_digest       (non-blank (get-in v [:Layer :Digest]))
     :layer_diff_id      (non-blank (get-in v [:Layer :DiffID]))
     :data_source        (when-let [d (:DataSource v)] (vj/write-str d))
     :title              (non-blank (:Title v))
     :refs               (str-vec (:References v))
     :scanner_native     nil}))

(defn- package-row
  "One row per `Packages[]` entry. Present only when the scan was run with
  `--list-all-pkgs`; without it, \"fraction of packages affected\" is
  uncomputable (spec section 6.1), which is why we store them."
  [scan-id target-id p]
  (let [nm  (or (non-blank (:Name p)) "unknown")
        ver (or (non-blank (:Version p)) "")]
    {:package_row_id (hash-id target-id (or (:ID p) nm) ver)
     :scan_id        scan-id
     :target_id      target-id
     :pkg_id         (non-blank (:ID p))
     :pkg_name       nm
     :version        ver
     :release        (non-blank (:Release p))
     :epoch          (when (number? (:Epoch p)) (long (:Epoch p)))
     :arch           (non-blank (:Arch p))
     :purl           (non-blank (get-in p [:Identifier :PURL]))
     :licenses       (str-vec (:Licenses p))
     :indirect       (boolean (:Indirect p))
     :layer_digest   (non-blank (get-in p [:Layer :Digest]))}))

(defn report->rows
  "Pure normalisation of a parsed Trivy report into store row maps.

  `opts` must carry `:scan-id` (sha256 of the report bytes), `:source-file`
  and `:ingested-at`. A report with zero `Results` still yields a scan row:
  a clean image is evidence management asks for (spec section 6.3)."
  [report {:keys [scan-id ingested-at] :as opts}]
  {:pre [(string? scan-id) (some? ingested-at)]}
  (let [results (or (:Results report) [])
        targets (mapv #(target-row scan-id %) results)
        pairs   (map vector results targets)]
    {:scan     (scan-row report opts)
     :targets  (dedupe-by :target_id targets)
     :findings (->> pairs
                    (mapcat (fn [[r t]]
                              (map #(finding-row scan-id (:target_id t) (:Target r) %)
                                   (:Vulnerabilities r))))
                    (dedupe-by :finding_id))
     :packages (->> pairs
                    (mapcat (fn [[r t]]
                              (map #(package-row scan-id (:target_id t) %)
                                   (:Packages r))))
                    (dedupe-by :package_row_id))}))

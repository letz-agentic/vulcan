(ns fixtures
  "Regenerate `resources/fixtures/trivy/` from raw scans in `data/raw/`.

  Fixtures are the practical contract for the Trivy JSON schema (spec section
  6.1): there is no formal published schema, so the tests are written against
  real scanner output rather than against our reading of the docs.

  The reports here come from *public* images, so there is nothing to
  anonymise; what this namespace does instead is *shrink* them, because a
  900 KB report is not something to carry in git for every test run. Shrinking
  keeps every distinct shape (each Class/Type, each Status, each severity,
  each CVSS source) and drops only repetition.

  Run with: clojure -M:dev -e \"(require 'fixtures)(fixtures/regenerate!)\""
  (:require [clojure.java.io :as io]
            [jsonista.core :as j]
            [vulcan.ingest.json :as vj]))

(def raw-dir "data/raw")
(def fixture-dir "resources/fixtures/trivy")

(def ^:private pretty-mapper (j/object-mapper {:pretty true}))

(defn- write-json! [file value]
  (io/make-parents file)
  (spit file (str (j/write-value-as-string value pretty-mapper) "\n")))

(defn- shape-key
  "The characteristics we must not lose when shrinking: keeping one
  vulnerability per distinct combination preserves every code path the
  normaliser and the categoriser can take."
  [v]
  [(:Severity v)
   (:Status v)
   (some? (:FixedVersion v))
   (sort (map name (keys (or (:CVSS v) {}))))
   (some? (:PublishedDate v))])

(defn- shrink-result
  "Keep at most `n` vulnerabilities per distinct shape, and only the packages
  that survive as either affected or a small sample."
  [result n]
  (let [vulns (->> (:Vulnerabilities result)
                   (group-by shape-key)
                   (mapcat (fn [[_ vs]] (take n vs)))
                   (sort-by (juxt :PkgName :VulnerabilityID))
                   vec)
        keep-pkgs (into #{} (map :PkgName) vulns)
        pkgs  (->> (:Packages result)
                   ;; every affected package, plus a sample of clean ones so
                   ;; "fraction of packages affected" stays a real fraction
                   ((fn [ps] (concat (filter #(keep-pkgs (:Name %)) ps)
                                     (take 10 (remove #(keep-pkgs (:Name %)) ps)))))
                   (map #(dissoc % :InstalledFiles :DependsOn))
                   (sort-by :Name)
                   vec)]
    (assoc result :Vulnerabilities vulns :Packages pkgs)))

(defn shrink-report [report n]
  (update report :Results (fn [rs] (mapv #(shrink-result % n) rs))))

(defn upgrade-package
  "Simulate `pkg` having been upgraded to the version that fixes it: drop its
  vulnerabilities and bump its entry in the package inventory. This is what a
  real follow-up scan of a patched image looks like, and it is what makes the
  `fixed-by-upgrade` diff label reachable."
  [report pkg]
  (let [fixed-version (->> (:Results report)
                           (mapcat :Vulnerabilities)
                           (filter #(= pkg (:PkgName %)))
                           (keep :FixedVersion)
                           first)]
    (when-not fixed-version
      (throw (ex-info "No fixed version to upgrade to" {:pkg pkg})))
    (update report :Results
            (fn [rs]
              (mapv (fn [r]
                      (-> r
                          (update :Vulnerabilities
                                  (fn [vs] (vec (remove #(= pkg (:PkgName %)) vs))))
                          (update :Packages
                                  (fn [ps]
                                    (mapv #(if (= pkg (:Name %))
                                             (assoc % :Version fixed-version)
                                             %)
                                          ps)))))
                    rs)))))

(defn regenerate!
  "Rebuild every fixture. Returns a map of fixture name -> byte size."
  []
  (let [raw (fn [n] (j/read-value (io/file raw-dir n) vj/mapper))]
    (doseq [[in out n] [["alpine-3.19.json"      "image-alpine-os.json"     2]
                        ["node-18-alpine.json"   "image-node-os-lang.json"  1]
                        ["python-3.11-slim.json" "image-debian-os-lang.json" 1]]]
      (write-json! (io/file fixture-dir out) (shrink-report (raw in) n)))

    ;; A clean image. Management asks to see these, and the ingester must
    ;; record a scan row for one (spec section 6.3).
    (write-json! (io/file fixture-dir "image-empty-results.json")
                 (-> (raw "alpine-3.22.json")
                     (assoc :ArtifactName "registry.example/clean-app:1.0.0"
                            :Results [])))

    ;; A second scan of an artifact already present, one week later, with one
    ;; package genuinely upgraded past its findings. Without a real upgrade in
    ;; the corpus the `fixed-by-upgrade` branch of the diff is never taken by
    ;; any test, and an untaken branch is an untested one.
    (write-json! (io/file fixture-dir "image-alpine-os-later.json")
                 (-> (raw "alpine-3.19.json")
                     (shrink-report 1)
                     (assoc :CreatedAt "2026-09-04T08:11:41.754688+02:00")
                     (upgrade-package "musl")))

    ;; Rejection fixtures (spec section 6.3).
    (write-json! (io/file fixture-dir "reject-schema-v1.json")
                 {:SchemaVersion 1 :ArtifactName "old:1.0" :Results []})
    (spit (io/file fixture-dir "reject-malformed.json")
          "{\"SchemaVersion\": 2, \"Results\": [ this is not json ]}\n")

    (into (sorted-map)
          (for [f (.listFiles (io/file fixture-dir))]
            [(.getName f) (.length f)]))))

(defn -main [& _]
  (doseq [[n size] (regenerate!)]
    (println (format "%-34s %8d bytes" n size)))
  (println "total"
           (reduce + (map #(.length %) (.listFiles (io/file fixture-dir))))
           "bytes"))

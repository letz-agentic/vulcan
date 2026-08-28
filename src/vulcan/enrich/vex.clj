(ns vulcan.enrich.vex
  "OpenVEX import and export (spec section 7.3).

  A decision is a human statement about a finding: *this CVE does not affect
  us, here is why, and this judgement expires on that date*. Keeping them in
  OpenVEX rather than in a private format is what lets the same statements be
  fed back to the scanner with `trivy --vex`, so the scanner's output and the
  report agree instead of quietly diverging.

  Round-tripping matters more than completeness here: a document exported,
  re-imported and exported again must be the same set of statements, because
  the file is going to live in a git repository next to the code it describes.

  OpenVEX shape (https://github.com/openvex/spec):

      {\"@context\": \"https://openvex.dev/ns/v0.2.0\",
       \"@id\": \"https://.../vex/vulcan-export\",
       \"author\": \"...\", \"timestamp\": \"...\", \"version\": 1,
       \"statements\": [{\"vulnerability\": {\"name\": \"CVE-...\"},
                        \"products\": [{\"@id\": \"pkg:...\"}],
                        \"status\": \"not_affected\",
                        \"justification\": \"vulnerable_code_not_present\",
                        \"impact_statement\": \"...\",
                        \"timestamp\": \"...\"}]}"
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [vulcan.ingest.json :as vj]
            [vulcan.ingest.trivy :as trivy]
            [vulcan.store.db :as db]
            [vulcan.store.write :as write])
  (:import (java.time Instant)))

(def context-url "https://openvex.dev/ns/v0.2.0")

(def statuses
  "The four OpenVEX statuses. `finding.status` uses Trivy's eight-value
  vocabulary; these are the four a *human* may assert."
  #{"not_affected" "affected" "fixed" "under_investigation"})

(def justifications
  "OpenVEX justification enum. Required by the spec when status is
  `not_affected`, and meaningless otherwise."
  #{"component_not_present"
    "vulnerable_code_not_present"
    "vulnerable_code_not_in_execute_path"
    "vulnerable_code_cannot_be_controlled_by_adversary"
    "inline_mitigations_already_exist"})

;; ---------------------------------------------------------------------------
;; import

(defn- product-scope
  "OpenVEX addresses products by identifier; we scope by PURL or artifact
  name, with `*` meaning every artifact. A statement with several products
  becomes several decisions, one per product, because a decision row carries
  exactly one scope."
  [statement]
  ;; `@id` cannot be written as a keyword literal, only constructed.
  ;; Subcomponents win over products: a statement that names both is about the
  ;; package, and the product is only there to tell the scanner where to look.
  (let [at-id (keyword "@id")
        ids   (fn [xs] (seq (keep (fn [p] (or (get p at-id) (:id p))) xs)))]
    (or (ids (:subcomponents statement))
        (ids (:products statement))
        ["*"])))

(defn statement->decisions
  "One OpenVEX statement -> one decision row per product scope."
  [{:keys [source doc-timestamp author]} statement]
  (let [vuln-id (or (get-in statement [:vulnerability :name])
                    ;; v0.1.0 wrote a bare string here
                    (when (string? (:vulnerability statement))
                      (:vulnerability statement)))
        status  (:status statement)]
    (when (and vuln-id status)
      (when-not (statuses status)
        (log/warnf "unknown OpenVEX status %s for %s" (pr-str status) vuln-id))
      (for [scope (product-scope statement)]
        {:decision-id      (trivy/hash-id vuln-id scope status source)
         :vulnerability-id vuln-id
         :scope            scope
         :status           status
         :justification    (:justification statement)
         :note             (or (:impact_statement statement)
                               (:action_statement statement))
         :decided-by       (or (:author statement) author)
         :decided-at       (trivy/->instant (or (:timestamp statement) doc-timestamp))
         :expires-at       (trivy/->instant (:expires statement))
         :source           source}))))

(defn document->decisions
  "Every decision row implied by an OpenVEX document."
  [doc source]
  (let [ctx {:source        source
             :doc-timestamp (:timestamp doc)
             :author        (:author doc)}]
    (vec (mapcat #(statement->decisions ctx %) (:statements doc)))))

(defn import!
  "Import an OpenVEX document into the `decision` table.

  Returns `{:file f :statements n :decisions n}`. Import is idempotent: a
  decision's id is derived from its content, so re-importing the same document
  changes nothing."
  [connectable file]
  (let [path (.getPath (io/file file))
        doc  (vj/parse (vj/read-bytes file))
        _    (when-not (:statements doc)
               (throw (ex-info "Not an OpenVEX document: no statements array"
                               {:file path})))
        rows (document->decisions doc (str "openvex:" (.getName (io/file file))))]
    (write/upsert-decisions! connectable rows)
    (log/infof "imported %d decisions from %s" (count rows) path)
    {:file path :statements (count (:statements doc)) :decisions (count rows)}))

;; ---------------------------------------------------------------------------
;; addressing products the way the scanner does

(defn oci-purl
  "A repo digest (`alpine@sha256:...`) -> the OCI PURL Trivy matches against.

  Trivy only applies a VEX statement whose `products` name the artifact by its
  full OCI PURL: neither the tag (`alpine:3.19`), nor `*`, nor an omitted
  `products` key has any effect (verified against Trivy 0.74). So a document
  that is going to be handed back with `--vex` has to speak that dialect.

  The awkward part is Docker's own reference normalisation, which is implicit
  everywhere and written down almost nowhere:

    alpine@sha256:..            -> index.docker.io/library/alpine
    letz/app@sha256:..          -> index.docker.io/letz/app
    ghcr.io/letz/app@sha256:..  -> ghcr.io/letz/app

  A first segment containing a dot or a colon (or the literal `localhost`) is
  a registry host; otherwise the reference is Docker Hub, and a single-segment
  name lives under the implicit `library/` namespace."
  [repo-digest]
  (when-let [[_ repo digest] (re-matches #"^(.+?)@(sha256:[0-9a-f]+)$" (str repo-digest))]
    (let [segments (str/split repo #"/")
          registry? (and (> (count segments) 1)
                         (let [h (first segments)]
                           (or (str/includes? h ".")
                               (str/includes? h ":")
                               (= "localhost" h))))
          host (if registry? (first segments) "index.docker.io")
          path (if registry? (rest segments) segments)
          path (if (and (not registry?) (= 1 (count path)))
                 (cons "library" path)
                 path)
          nm   (last path)]
      (str "pkg:oci/" nm "@" digest
           "?repository_url=" (str/join "/" (cons host path))))))

(defn artifacts
  "Every artifact in the store, as `{:artifact-name :purl :purls #{package purls}}`.

  Export needs this because a package-scoped decision has to be expressed as a
  `subcomponent` *of* some product, and only the store knows which images
  actually contain that package."
  [connectable]
  (for [{:keys [artifact-name repo-digests]}
        (db/execute! connectable
                     ["SELECT DISTINCT artifact_name, repo_digests
                       FROM v_latest_scan_per_artifact"])]
    {:artifact-name artifact-name
     :purl          (some oci-purl repo-digests)
     :purls         (into #{}
                          (map :purl)
                          (db/execute! connectable
                                       ["SELECT DISTINCT p.purl
                                         FROM package p
                                         JOIN scan s ON s.scan_id = p.scan_id
                                         WHERE s.artifact_name = ? AND p.purl IS NOT NULL"
                                        artifact-name]))}))

(defn- package-scope?
  "Is this scope a package PURL rather than an artifact name?"
  [scope]
  (and (string? scope)
       (str/starts-with? scope "pkg:")
       (not (str/starts-with? scope "pkg:oci/"))))

(defn- products-for
  "Which products a decision's statement should name."
  [arts scope]
  (cond
    (= "*" scope)        (keep :purl arts)
    (package-scope? scope) (keep :purl (filter #(contains? (:purls %) scope) arts))
    :else                (or (seq (keep :purl (filter #(= scope (:artifact-name %)) arts)))
                             [scope])))

;; ---------------------------------------------------------------------------
;; export

(defn- ->iso [t]
  (cond
    (nil? t) nil
    (instance? Instant t) (str t)
    (instance? java.util.Date t) (str (.toInstant ^java.util.Date t))
    :else (str t)))

(defn decision->statement
  "One decision -> one OpenVEX statement.

  A package-scoped decision becomes a `subcomponent` of the products that
  contain it, because that is the only shape Trivy acts on. An
  artifact-scoped one names the product directly."
  ([decision] (decision->statement decision nil))
  ([{:keys [vulnerability-id scope status justification note decided-by
            decided-at expires-at]}
    arts]
   (let [at-id    (keyword "@id")
         products (when (seq arts) (products-for arts scope))]
     (cond-> {:vulnerability {:name vulnerability-id}
              :status        status}
       (seq products)         (assoc :products (mapv #(hash-map at-id %) products))
       (package-scope? scope) (assoc :subcomponents [{at-id scope}])
       (and (not (seq products))
            (not (package-scope? scope))
            (not= "*" scope))  (assoc :products [{at-id scope}])
       justification          (assoc :justification justification)
       note                   (assoc :impact_statement note)
       decided-by             (assoc :author decided-by)
       decided-at             (assoc :timestamp (->iso decided-at))
       expires-at             (assoc :expires (->iso expires-at))))))

(defn decisions
  "Every decision in the store, oldest first."
  [connectable]
  (db/execute! connectable
               ["SELECT * FROM decision ORDER BY vulnerability_id, scope"]))

(defn export
  "Build an OpenVEX document from the store's decisions.

  `now` is a parameter rather than a call to the clock so that the result is
  testable and two exports of the same decisions differ only in timestamp."
  ([connectable] (export connectable {}))
  ([connectable {:keys [author now id]
                 :or   {author "vulcan-v"
                        id     "https://openvex.dev/docs/vulcan-v/export"}}]
   (let [rows (decisions connectable)
         arts (vec (artifacts connectable))]
     {(keyword "@context") context-url
      (keyword "@id")      id
      :author              author
      :timestamp           (->iso (or now (Instant/now)))
      :version             1
      :statements          (mapv #(decision->statement % arts) rows)})))

(defn export!
  "Write the OpenVEX document to `file`. The result is directly usable as
  `trivy --vex <file>`, which is the point (spec section 7.3)."
  ([connectable file] (export! connectable file {}))
  ([connectable file opts]
   (let [doc (export connectable opts)]
     (io/make-parents (io/file file))
     (spit file (str (vj/write-str doc) "\n"))
     (log/infof "exported %d decisions to %s" (count (:statements doc)) (str file))
     {:file (str file) :decisions (count (:statements doc))})))

;; ---------------------------------------------------------------------------

(defn summary
  "What decisions are on file, for the CLI and the report appendix."
  [connectable]
  (let [rows (decisions connectable)]
    {:n-decisions (count rows)
     :by-status   (frequencies (map :status rows))
     :n-expired   (count (filter (fn [{:keys [expires-at]}]
                                   (and expires-at
                                        (.isBefore ^Instant (.toInstant ^java.util.Date expires-at)
                                                   (Instant/now))))
                                 rows))}))

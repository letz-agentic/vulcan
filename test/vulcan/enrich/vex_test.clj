(ns vulcan.enrich.vex-test
  "OpenVEX import and export (spec section 7.3)."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [tablecloth.api :as tc]
            [vulcan.enrich.vex :as vex]
            [vulcan.ingest.json :as vj]
            [vulcan.report.context :as ctx]
            [vulcan.store.db :as db]
            [vulcan.test-store :as ts])
  (:import (java.time Instant)))

(def fixture "resources/fixtures/vex/example.openvex.json")

(defn- by-vuln [rows]
  (into {} (map (juxt :vulnerability-id identity)) rows))

;; ---------------------------------------------------------------------------
;; import

(deftest import-reads-every-statement
  (ts/with-store [conn]
    (let [{:keys [statements decisions]} (vex/import! conn fixture)]
      (is (= 3 statements))
      (is (= 3 decisions))
      (is (= 3 (:n (db/execute-one! conn ["SELECT count(*) AS n FROM decision"])))))))

(deftest import-maps-the-openvex-fields
  (ts/with-store [conn]
    (vex/import! conn fixture)
    (let [rows (by-vuln (vex/decisions conn))]
      (testing "status, justification and impact statement"
        (let [d (rows "CVE-2026-40200")]
          (is (= "not_affected" (:status d)))
          (is (= "vulnerable_code_not_in_execute_path" (:justification d)))
          (is (re-find #"not reachable" (:note d)))
          (is (re-find #"pkg:apk/alpine/musl" (:scope d)))))

      (testing "an action_statement lands in the same note column"
        (is (re-find #"base-image refresh" (:note (rows "CVE-2026-31789")))))

      (testing "expiry is carried through"
        (is (some? (:expires-at (rows "CVE-2026-22184"))))
        (is (nil?  (:expires-at (rows "CVE-2026-40200")))))

      (testing "a statement with no products scopes to everything"
        (is (= "*" (:scope (rows "CVE-2026-31789")))))

      (testing "and provenance names the file"
        (is (every? #(re-find #"^openvex:" (:source %)) (vals rows)))))))

(deftest import-is-idempotent
  (testing "a decision id is derived from content, so re-import changes nothing"
    (ts/with-store [conn]
      (vex/import! conn fixture)
      (let [after-first (vex/decisions conn)]
        (vex/import! conn fixture)
        (is (= (count after-first) (count (vex/decisions conn))))))))

(deftest a-statement-with-several-products-becomes-several-decisions
  (let [rows (vex/statement->decisions
              {:source "t"}
              {:vulnerability {:name "CVE-1"}
               :status        "not_affected"
               :products      [{(keyword "@id") "pkg:a"} {(keyword "@id") "pkg:b"}]})]
    (is (= 2 (count rows)))
    (is (= #{"pkg:a" "pkg:b"} (set (map :scope rows))))
    (is (apply distinct? (map :decision-id rows)))))

(deftest a-v0-1-style-bare-vulnerability-string-still-imports
  (let [rows (vex/statement->decisions {:source "t"}
                                       {:vulnerability "CVE-9" :status "fixed"})]
    (is (= "CVE-9" (:vulnerability-id (first rows))))))

(deftest a-statement-without-a-status-is-skipped
  (is (empty? (vex/statement->decisions {:source "t"}
                                        {:vulnerability {:name "CVE-1"}}))))

(deftest a-non-vex-document-is-rejected-by-name
  (ts/with-store [conn]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Not an OpenVEX document"
                          (vex/import! conn "resources/fixtures/trivy/image-alpine-os.json")))))

;; ---------------------------------------------------------------------------
;; export

(deftest export-round-trips
  (testing "export, re-import, export again yields the same statements"
    (ts/with-store [conn]
      (vex/import! conn fixture)
      (let [now  (Instant/parse "2026-08-28T00:00:00Z")
            doc1 (vex/export conn {:now now})
            tmp  (java.io.File/createTempFile "vulcan-vex" ".json")]
        (try
          (spit tmp (vj/write-str doc1))
          (ts/with-store [conn2]
            (vex/import! conn2 (.getPath tmp))
            (let [doc2 (vex/export conn2 {:now now})]
              (is (= (set (map #(select-keys % [:vulnerability :status :justification])
                               (:statements doc1)))
                     (set (map #(select-keys % [:vulnerability :status :justification])
                               (:statements doc2)))))))
          (finally (.delete tmp)))))))

(deftest exported-document-is-valid-openvex
  (ts/with-store [conn]
    (vex/import! conn fixture)
    (let [doc (vex/export conn {:now (Instant/parse "2026-08-28T00:00:00Z")})]
      (is (= vex/context-url (get doc (keyword "@context"))))
      (is (some? (get doc (keyword "@id"))))
      (is (= 1 (:version doc)))
      (is (string? (:timestamp doc)))
      (testing "every statement names a vulnerability and a status"
        (doseq [s (:statements doc)]
          (is (some? (get-in s [:vulnerability :name])))
          (is (vex/statuses (:status s))))))))

(deftest exported-json-parses-back
  (ts/with-store [conn]
    (vex/import! conn fixture)
    (let [tmp (java.io.File/createTempFile "vulcan-vex" ".json")]
      (try
        (vex/export! conn (.getPath tmp))
        (let [parsed (vj/parse (vj/read-bytes tmp))]
          (is (= 3 (count (:statements parsed))))
          (is (= vex/context-url (get parsed (keyword "@context")))))
        (finally (.delete tmp))))))

;; ---------------------------------------------------------------------------
;; addressing products the way Trivy does (verified against Trivy 0.74)

(deftest oci-purl-normalisation
  (testing "Docker Hub official images gain the implicit library/ namespace"
    (is (= "pkg:oci/alpine@sha256:abc?repository_url=index.docker.io/library/alpine"
           (vex/oci-purl "alpine@sha256:abc"))))
  (testing "a Docker Hub namespaced repo keeps its namespace"
    (is (= "pkg:oci/app@sha256:abc?repository_url=index.docker.io/letz/app"
           (vex/oci-purl "letz/app@sha256:abc"))))
  (testing "a host with a dot is a registry, not a namespace"
    (is (= "pkg:oci/app@sha256:abc?repository_url=ghcr.io/letz/app"
           (vex/oci-purl "ghcr.io/letz/app@sha256:abc"))))
  (testing "and so is localhost with a port"
    (is (= "pkg:oci/x@sha256:abc?repository_url=localhost:5000/x"
           (vex/oci-purl "localhost:5000/x@sha256:abc"))))
  (testing "anything that is not a digest reference is not a PURL"
    (is (nil? (vex/oci-purl "alpine:3.19")))
    (is (nil? (vex/oci-purl nil)))))

(deftest a-package-scoped-decision-exports-as-a-subcomponent
  (testing "Trivy applies a package statement only as a subcomponent of a
            product it can match; products alone are ignored"
    (ts/with-store [conn]
      (vex/import! conn fixture)
      (let [doc (vex/export conn {:now (Instant/parse "2026-08-28T00:00:00Z")})
            st  (->> (:statements doc)
                     (filter #(= "CVE-2026-40200" (get-in % [:vulnerability :name])))
                     first)
            at-id (keyword "@id")]
        (is (some? st))
        (is (= ["pkg:apk/alpine/musl@1.2.4_git20230717-r5?arch=x86_64&distro=3.19.9"]
               (mapv #(get % at-id) (:subcomponents st)))
            "the package goes in subcomponents")
        (is (seq (:products st))
            "and products names the images that actually contain it")
        (is (every? #(str/starts-with? (get % at-id) "pkg:oci/") (:products st))
            "as an OCI PURL, which is the only form Trivy matches")))))

(deftest a-global-scope-names-every-artifact
  (ts/with-store [conn]
    (vex/import! conn fixture)
    (let [doc (vex/export conn {:now (Instant/parse "2026-08-28T00:00:00Z")})
          st  (->> (:statements doc)
                   (filter #(= "CVE-2026-31789" (get-in % [:vulnerability :name])))
                   first)]
      (is (< 1 (count (:products st)))
          "'*' means every artifact in the store, named individually"))))

(deftest scope-survives-the-round-trip-through-subcomponents
  (testing "import must read the subcomponent back as the scope, or a second
            export would lose the package it was about"
    (ts/with-store [conn]
      (vex/import! conn fixture)
      (let [tmp (java.io.File/createTempFile "vulcan-vex" ".json")]
        (try
          (vex/export! conn (.getPath tmp))
          (ts/with-store [conn2]
            (vex/import! conn2 (.getPath tmp))
            (let [scopes (into {} (map (juxt :vulnerability-id :scope))
                               (vex/decisions conn2))]
              (is (= "pkg:apk/alpine/musl@1.2.4_git20230717-r5?arch=x86_64&distro=3.19.9"
                     (scopes "CVE-2026-40200")))))
          (finally (.delete tmp)))))))

(deftest a-global-scope-is-never-emitted-as-a-literal-product-id
  (testing "'*' is our encoding of 'all products', not an OpenVEX product id"
    (let [s (vex/decision->statement {:vulnerability-id "CVE-1" :scope "*"
                                      :status "affected"}
                                     nil)]
      (is (not (contains? s :products))))))

;; ---------------------------------------------------------------------------
;; decisions reach the analysis layer (spec 5.4, 7.3)

(deftest imported-decisions-appear-on-findings
  (ts/with-store [conn]
    (vex/import! conn fixture)
    (let [rows    (tc/rows (:findings (ctx/build {:connectable conn :scope :latest}))
                           :as-maps)
          decided (filter :decision-status rows)]
      (is (seq decided) "at least one fixture finding matches a decision scope")
      (testing "the status reaches the analysis layer"
        (is (contains? (set (map :decision-status decided)) "affected"))))))

(deftest a-justification-reaches-the-analysis-layer
  (testing "asserted directly rather than via the fixture: whether a PURL-scoped
            statement happens to overlap a fixture finding is incidental"
    (ts/with-store [conn]
      (let [id (-> (db/execute-one! conn ["SELECT vulnerability_id FROM finding LIMIT 1"])
                   :vulnerability-id)]
        (db/execute! conn ["INSERT INTO decision
                            (decision_id, vulnerability_id, scope, status,
                             justification, source)
                            VALUES ('j1', ?, '*', 'not_affected',
                                    'vulnerable_code_not_present', 'test')" id])
        (let [rows (->> (ctx/build {:connectable conn :scope :latest})
                        :findings (#(tc/rows % :as-maps))
                        (filter #(= id (:vulnerability-id %))))]
          (is (seq rows))
          (is (every? #(= "vulnerable_code_not_present" (:decision-justification %))
                      rows)))))))

(deftest expired-decisions-are-not-applied
  (testing "spec 7.3: expiry is honoured at analysis time"
    (ts/with-store [conn]
      (let [id (-> (db/execute-one! conn ["SELECT vulnerability_id FROM finding LIMIT 1"])
                   :vulnerability-id)]
        ;; A decision that expired before any scan was taken.
        (db/execute! conn ["INSERT INTO decision
                            (decision_id, vulnerability_id, scope, status, expires_at, source)
                            VALUES ('expired', ?, '*', 'not_affected',
                                    TIMESTAMP '2000-01-01 00:00:00', 'test')" id])
        (let [c    (ctx/build {:connectable conn :scope :latest})
              rows (filter #(= id (:vulnerability-id %)) (tc/rows (:findings c) :as-maps))]
          (is (seq rows))
          (is (every? nil? (map :decision-status rows))
              "an expired decision must not suppress a finding"))))))

(deftest summary-counts-decisions
  (ts/with-store [conn]
    (vex/import! conn fixture)
    (let [s (vex/summary conn)]
      (is (= 3 (:n-decisions s)))
      (is (= 1 (get (:by-status s) "not_affected")))
      (is (zero? (:n-expired s)) "the fixture's expiry is in the future"))))

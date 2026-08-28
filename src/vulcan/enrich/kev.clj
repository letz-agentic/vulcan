(ns vulcan.enrich.kev
  "CISA's Known Exploited Vulnerabilities catalogue (spec section 7.1).

  KEV is the strongest single signal the exploitability axis has: it is not a
  prediction, it is a statement that exploitation has been *observed*. That is
  why `vulcan.analysis.score` lets it saturate the exploitability component
  outright rather than blending it with EPSS.

  The catalogue is fetched whole, from CISA directly, rather than one id at a
  time from an intermediary:

  * it is one request for the entire answer, so enriching 50 CVEs and 5000
    costs the same;
  * it is the authoritative source, not a mirror of one;
  * it can be primed before an offline run.

  The spec named CIRCL's `/api/cisa_kev/` for this. That path returns 404
  today; see doc/adr/0006-enrichment-sources.md."
  (:require [clojure.tools.logging :as log]
            [vulcan.enrich.http :as http]
            [vulcan.enrich.provider :as p])
  (:import (java.time LocalDate)))

(def catalog-url
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")

(defn- ->date [s]
  (when s (try (LocalDate/parse (str s)) (catch Exception _ nil))))

(defn- entry->map [{:keys [cveID dateAdded knownRansomwareCampaignUse]}]
  (when cveID
    {:vulnerability-id cveID
     :kev              true
     :kev-date-added   (->date dateAdded)
     ;; CISA writes "Known" / "Unknown", not a boolean.
     :kev-ransomware   (= "Known" knownRansomwareCampaignUse)}))

(defn fetch-catalog
  "The whole KEV catalogue as `{vulnerability-id row}`, or nil when
  unavailable."
  []
  (let [resp (p/with-retries
              {:label      "kev"
               :fallback   {:status nil :body nil}
               :retryable? http/rate-limited?}
              #(http/get-json* catalog-url {:timeout-ms 60000}))]
    (when-let [vulns (some-> resp :body :vulnerabilities)]
      (log/infof "KEV catalogue: %d entries" (count vulns))
      (into {} (comp (keep entry->map) (map (juxt :vulnerability-id identity))) vulns))))

(defrecord KevProvider [cache]
  p/Enricher
  (provider-name [_] :kev)
  (enrich [_ ids]
    (let [catalog (or @cache (reset! cache (or (fetch-catalog) {})))]
      (if (empty? catalog)
        ;; The catalogue could not be fetched. Say nothing rather than
        ;; asserting `kev false` for everything, which would look exactly like
        ;; a confident "none of these are exploited".
        nil
        (for [id ids]
          (or (get catalog id)
              ;; Present in the catalogue we successfully fetched? No. That is
              ;; a real negative and worth recording.
              {:vulnerability-id id :kev false :kev-ransomware false}))))))

(defn provider
  "Bulk provider holding the catalogue for its lifetime."
  []
  (->KevProvider (atom nil)))

(ns vulcan.enrich.epss
  "EPSS scores from FIRST (spec section 7.1).

  EPSS is the probability that a vulnerability will be exploited in the next
  30 days. The *percentile* matters more than the raw score for our purposes,
  because it is what makes two CVEs comparable, and it is what the fix-first
  score's exploitability component prefers.

  Two providers, one protocol:

  * `api-provider` — `api.first.org/data/v1/epss?cve=A,B,C`, batched. The
    right choice for a normal run, where the store holds a few hundred CVEs
    and only the stale ones need refreshing.
  * `csv-provider` — the daily bulk CSV. One download covering every CVE in
    existence, which is better when enriching a large store from cold, and
    the only option that can be primed ahead of an offline run.

  Both return the same rows, so the choice is operational rather than
  semantic."
  (:require [clojure.string :as str]
            [clojure.tools.logging :as log]
            [vulcan.enrich.http :as http]
            [vulcan.enrich.provider :as p])
  (:import (java.io ByteArrayInputStream)
           (java.time LocalDate)
           (java.util.zip GZIPInputStream)))

(def api-url "https://api.first.org/data/v1/epss")
(def csv-url "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")

(def batch-size
  "CVEs per API request. FIRST's default page limit is 100, and a longer
  comma-separated list also starts to strain the URL length."
  100)

(defn- ->double [s]
  (when-not (str/blank? (str s))
    (try (Double/parseDouble (str s)) (catch NumberFormatException _ nil))))

(defn- ->date [s]
  (when-not (str/blank? (str s))
    (try (LocalDate/parse (str s)) (catch Exception _ nil))))

(defn- row->map [{:keys [cve epss percentile date]}]
  (when cve
    {:vulnerability-id cve
     :epss-score       (->double epss)
     :epss-percentile  (->double percentile)
     :epss-date        (->date date)}))

;; ---------------------------------------------------------------------------
;; the batched API

(defn fetch-batch
  "One API call for up to `batch-size` ids. Returns rows for the ids FIRST
  knows about; ids with no EPSS score simply do not come back."
  [ids]
  (let [resp (p/with-retries
              {:label      "epss"
               :fallback   {:status nil :body nil}
               :retryable? http/rate-limited?}
              #(http/get-json* api-url {:query-params {"cve" (str/join "," ids)}}))]
    (some->> resp :body :data (keep row->map))))

(defrecord EpssApiProvider [concurrency]
  p/Enricher
  (provider-name [_] :epss)
  (enrich [_ ids]
    (->> (partition-all batch-size ids)
         (p/bounded-pmap (or concurrency 4) fetch-batch)
         (apply concat)
         (remove nil?))))

(defn api-provider
  ([] (api-provider 4))
  ([concurrency] (->EpssApiProvider concurrency)))

;; ---------------------------------------------------------------------------
;; the bulk CSV

(defn parse-csv
  "Parse FIRST's EPSS CSV. The first line is a `#`-prefixed comment carrying
  the model version and score date; the second is the header."
  [text]
  (when text
    (let [lines  (remove #(str/starts-with? % "#") (str/split-lines text))
          header (str/split (first lines) #",")
          idx    (into {} (map-indexed (fn [i h] [(str/trim h) i]) header))]
      (when (and (idx "cve") (idx "epss"))
        (for [line (rest lines)
              :when (not (str/blank? line))
              :let  [cols (str/split line #",")
                     cve  (get cols (idx "cve"))]
              :when cve]
          {:vulnerability-id cve
           :epss-score       (->double (get cols (idx "epss")))
           :epss-percentile  (->double (get cols (idx "percentile")))})))))

(defn fetch-csv
  "Download and decompress the current EPSS CSV. Returns a map of
  vulnerability id to row, or nil when unavailable."
  []
  (when-let [resp (http/get-json csv-url {:raw-response? true :timeout-ms 120000})]
    (when (= 200 (:status resp))
      ;; The body arrives as a string, so it must be read back as bytes with a
      ;; charset that maps 1:1 onto them before gunzipping.
      (let [bytes (.getBytes ^String (:body resp) "ISO-8859-1")
            text  (try
                    (with-open [in (GZIPInputStream. (ByteArrayInputStream. bytes))]
                      (slurp in))
                    (catch Exception e
                      (log/warnf "could not decompress the EPSS CSV: %s" (.getMessage e))
                      nil))]
        (some->> (parse-csv text)
                 (into {} (map (juxt :vulnerability-id identity))))))))

(defrecord EpssCsvProvider [cache]
  p/Enricher
  (provider-name [_] :epss-csv)
  (enrich [_ ids]
    (let [table (or @cache (reset! cache (or (fetch-csv) {})))]
      (keep table ids))))

(defn csv-provider
  "Bulk provider. The whole catalogue is downloaded once and held for the life
  of this provider, so it is cheap to ask it about many ids and pointless to
  construct a new one per batch."
  []
  (->EpssCsvProvider (atom nil)))

(ns vulcan.enrich.circl
  "CIRCL Vulnerability-Lookup (spec section 7.1).

  Two things come from here that no bulk feed provides:

  * a **description**, so a report can say what a CVE actually is rather than
    only that it is CRITICAL;
  * a **sightings count** — how many times exploitation has been observed in
    the wild — which feeds the `exploited` branch of the exploitability axis
    alongside KEV.

  Both are per-id lookups, so this is the one provider that needs bounded
  concurrency and back-off (spec §7.2). Credentials are optional and raise the
  rate limit when present; the endpoints we use are public.

  The raw CVE record is kept in `vulnerability.circl_raw` — the same instinct
  as `scan.raw`, so a question we have not thought of yet does not need a
  re-fetch of the whole catalogue."
  (:require [vulcan.enrich.http :as http]
            [vulcan.enrich.provider :as p]
            [vulcan.ingest.json :as vj]))

(def base-url "https://vulnerability.circl.lu")

(def default-concurrency
  "The instance's published limit is 20 requests per minute anonymous, 40 with
  an `X-API-KEY` (`/.well-known/api-policy.json`). Two in flight keeps a
  normal run near that budget; the bulk KEV and EPSS providers carry the load
  that actually matters, so there is nothing to gain by pushing harder.

  Set `CIRCL_API_KEY` to double the budget and to be bucketed by key rather
  than by IP. Even then the limit is a limit: on a store with hundreds of
  vulnerabilities, descriptions will still come back partial on a single run,
  and the circuit breaker is what makes that fast rather than slow."
  2)

(defn vulnerability-url [id] (str base-url "/api/vulnerability/" id))
(def sighting-url (str base-url "/api/sighting/"))

(defn description
  "Pull the English description out of a CVE 5.0 record.

  CIRCL serves the upstream CVE record verbatim, so the shape is CVE JSON 5.0
  (`containers.cna.descriptions`) rather than anything CIRCL-specific."
  [record]
  (let [descs (get-in record [:containers :cna :descriptions])]
    (or (->> descs (filter #(= "en" (:lang %))) first :value)
        (-> descs first :value))))

(def attempts
  "One retry, not three. With `Retry-After: 30` a second attempt already costs
  half a minute; a third and fourth buy nothing that the circuit breaker does
  not handle better."
  2)

(defn fetch-record
  "The CVE record for `id` as `{:status :body}`."
  [id]
  (p/with-retries
   {:label      (str "circl " id)
    :attempts   attempts
    :fallback   {:status nil :body nil}
    :retryable? http/rate-limited?}
   #(http/get-json* (vulnerability-url id)
                    {:headers (http/circl-headers)})))

(defn fetch-sightings-count
  "How many sightings CIRCL holds for `id`.

  The count comes from the response's `metadata.count` rather than from the
  length of `data`, which is one page of at most 1000 — a vulnerability with
  1780 sightings would otherwise be recorded as having 1000."
  [id]
  (p/with-retries
   {:label      (str "circl sightings " id)
    :attempts   attempts
    :fallback   {:status nil :body nil}
    :retryable? http/rate-limited?}
   #(http/get-json* sighting-url
                    {:query-params {"vuln_id" id}
                     :headers      (http/circl-headers)})))

(defn- rate-limited-out?
  "Did this response run out of retries against a rate limit, rather than
  simply not knowing the id? A 404 is an answer; a 429 is a refusal."
  [{:keys [status]}]
  (or (= 429 status) (nil? status)))

(defn- enrich-one [{:keys [sightings? breaker]} id]
  (when-not (p/open? breaker)
    (let [resp   (fetch-record id)
          record (:body resp)]
      (if (and (nil? record) (rate-limited-out? resp))
        (do (p/trip! breaker
                     (if (= 429 (:status resp))
                       "CIRCL is rate-limiting us; descriptions will be partial for this run"
                       "CIRCL is not responding; descriptions will be partial for this run"))
            nil)
        (let [sight (when (and sightings? (not (p/open? breaker)))
                      (get-in (fetch-sightings-count id) [:body :metadata :count]))]
          (when (or record sight)
            (cond-> {:vulnerability-id id
                     :circl-fetched-at (java.time.Instant/now)}
              record (assoc :description (description record)
                            :circl-raw   (vj/write-str record))
              sight  (assoc :sightings-count sight))))))))

(defrecord CirclProvider [concurrency sightings?]
  p/Enricher
  (provider-name [_] :circl)
  (enrich [_ ids]
    ;; One breaker per run, shared by every id in it.
    (let [b (p/breaker)]
      (->> ids
           (p/bounded-pmap (or concurrency default-concurrency)
                           #(enrich-one {:sightings? sightings? :breaker b} %))
           (remove nil?)))))

(defn provider
  "CIRCL provider. `:sightings?` doubles the request count — one extra lookup
  per id — so it is opt-in; `bb enrich --sightings` turns it on."
  ([] (provider {}))
  ([{:keys [concurrency sightings?] :or {concurrency default-concurrency sightings? false}}]
   (->CirclProvider concurrency sightings?)))

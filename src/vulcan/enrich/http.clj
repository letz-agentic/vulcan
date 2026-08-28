(ns vulcan.enrich.http
  "The one place Vulcan V talks to the network (spec section 7.1).

  Every enrichment provider goes through `get-json`, so timeouts, the User-
  Agent, optional CIRCL credentials, 429 handling and the `--offline` switch
  are decided once rather than four times.

  Offline is a hard gate, not a hint: when it is on, `get-json` returns nil
  without opening a socket. That is what makes `bb render --offline`
  trustworthy in an air-gapped CI job."
  (:require [clojure.string :as str]
            [clojure.tools.logging :as log]
            [hato.client :as http]
            [jsonista.core :as j]
            [vulcan.ingest.json :as vj]))

(def user-agent
  "Identify the client with a contact URL, which is what the instance policy
  asks for: a meaningful User-Agent including a contact URL or email.

  This is not politeness for its own sake. The access-patterns guidance says
  default SDK User-Agents such as python-requests or Go-http-client are
  treated as anonymous and may be rate-limited or blocked first, so an
  unidentified client is one that gets throttled sooner."
  "vulcan-v/0.1 (+https://github.com/letz-agentic/vulcan)")

(def ^:dynamic *offline*
  "When true, no request is made and every lookup returns nil (spec §7.2)."
  false)

(def default-timeout-ms 20000)

(defn circl-headers
  "Optional CIRCL Vulnerability-Lookup credentials from `CIRCL_API_KEY`.

  The header is `X-API-KEY`. The spec (section 7.1) named CVE-API-ORG,
  CVE-API-USER and CVE-API-KEY, which this instance ignores -- sending those
  is indistinguishable from sending nothing at all. The authoritative
  statement is the instance own machine-readable policy at
  `/.well-known/api-policy.json`, which reports that the rate-limit bucket key
  is X-API-KEY when present and the client IP otherwise, with limits of 20
  requests per minute anonymous and 40 authenticated.

  So a key is worth having -- it doubles the budget, and buckets by key rather
  than by IP, so a shared egress address is not punished for someone else
  traffic -- but it does not remove the limit, and the circuit breaker in
  `vulcan.enrich.provider` is still what keeps a large run honest."
  []
  (into {}
        (remove (comp nil? val))
        {"X-API-KEY" (System/getenv "CIRCL_API_KEY")}))

(defn rate-limited?
  "429, or a 5xx worth another attempt. A 404 is an answer, not a failure."
  [{:keys [status]}]
  (or (= 429 status) (and status (<= 500 status 599))))

(defn get-json
  "GET `url` and parse the body as JSON.

  Returns nil rather than throwing when offline, on a non-200, or on a
  transport error: a provider's job is to report what it learned, and 'nothing'
  is a valid thing to have learned. `:raw-response` returns the whole response
  map so a caller can inspect the status and back off."
  ([url] (get-json url {}))
  ([url {:keys [query-params headers timeout-ms raw-response?]}]
   (if *offline*
     (do (log/debugf "offline: skipping %s" url) nil)
     (let [resp (try
                  (http/get url {:query-params     query-params
                                 :headers          (merge {"User-Agent" user-agent
                                                           "Accept" "application/json"}
                                                          headers)
                                 :timeout          (or timeout-ms default-timeout-ms)
                                 :throw-exceptions false
                                 :as               :string})
                  (catch Exception e
                    (log/debugf "request failed %s: %s" url (.getMessage e))
                    {:status nil :error e}))]
       (cond
         raw-response? resp

         (= 200 (:status resp))
         (try
           (j/read-value (:body resp) vj/mapper)
           (catch Exception e
             (log/warnf "%s returned unparseable JSON: %s" url (.getMessage e))
             nil))

         :else
         (do (log/debugf "%s returned status %s" url (:status resp))
             nil))))))

(defn retry-after-ms
  "How long a server told us to wait, in milliseconds, or nil.

  CIRCL answers a 429 with `Retry-After: 30` and an `x-ratelimit-reset`
  epoch. Honouring the header is both better behaved and faster than guessing
  with exponential back-off, which would sleep either too little (and get
  refused again) or far too long."
  [headers]
  ;; Normalise the *map's* keys: HTTP header names are case-insensitive, and
  ;; a client that only handles the casing it happens to see is a client that
  ;; ignores Retry-After the first time a server capitalises it.
  (let [lower (into {} (map (fn [[k v]] [(str/lower-case (name k)) v])) headers)
        h     (fn [k] (get lower (str/lower-case k)))]
    (or (some-> (h "retry-after") str str/trim parse-long (* 1000))
        (when-let [reset (some-> (h "x-ratelimit-reset") str str/trim parse-long)]
          (let [now (quot (System/currentTimeMillis) 1000)]
            (when (> reset now) (* 1000 (- reset now))))))))

(defn get-json*
  "Like `get-json`, but returns `{:status s :body parsed-or-nil}` so a caller
  can tell a genuine absence from a rate-limited retry. This is what
  `with-retries` inspects."
  ([url] (get-json* url {}))
  ([url opts]
   (let [resp (get-json url (assoc opts :raw-response? true))]
     (if (nil? resp)
       {:status nil :body nil}
       {:status         (:status resp)
        :retry-after-ms (retry-after-ms (:headers resp))
        :body           (when (= 200 (:status resp))
                          (try (j/read-value (:body resp) vj/mapper)
                               (catch Exception e
                                 (log/warnf "%s returned unparseable JSON: %s"
                                            url (.getMessage e))
                                 nil)))}))))

(defn get-text
  "GET `url` as text, for the endpoints that serve CSV rather than JSON."
  ([url] (get-text url {}))
  ([url {:keys [timeout-ms headers]}]
   (when-not *offline*
     (try
       (let [resp (http/get url {:headers          (merge {"User-Agent" user-agent} headers)
                                 :timeout          (or timeout-ms default-timeout-ms)
                                 :throw-exceptions false
                                 :as               :string})]
         (when (= 200 (:status resp)) (:body resp)))
       (catch Exception e
         (log/debugf "request failed %s: %s" url (.getMessage e))
         nil)))))

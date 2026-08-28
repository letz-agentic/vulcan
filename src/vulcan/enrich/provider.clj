(ns vulcan.enrich.provider
  "The enrichment provider protocol (spec section 7.1).

  One method, deliberately: `(enrich this ids)` returns a seq of partial maps
  keyed by `:vulnerability-id`. Providers are therefore swappable, composable
  and — the point that matters for the tests — trivially mockable, so nothing
  in the suite ever touches a public API.

  A provider returns *partial* rows. `vulcan.enrich.cache` merges them by id
  and writes one row per vulnerability, so adding a source is adding a
  provider and nothing else.

  Providers must not throw on a single failed lookup. A vulnerability database
  being down is an ordinary Tuesday, and the whole design of §7.2 is that a
  report renders from whatever is cached rather than failing."
  (:require [clojure.tools.logging :as log]))

(defprotocol Enricher
  (provider-name [this]
    "Short keyword naming this provider, for logs and the report appendix.")
  (enrich [this ids]
    "Look up `ids`. Returns a seq of maps, each carrying `:vulnerability-id`
    and whatever columns this provider knows about."))

;; ---------------------------------------------------------------------------
;; shared helpers

(defn bounded-pmap
  "Map `f` over `coll` with at most `n` calls in flight (spec section 7.2's
  bounded concurrency, default 4).

  Not `pmap`: its parallelism is tied to the number of processors, which is
  the wrong bound entirely when the constraint is somebody else's rate limit."
  [n f coll]
  (->> coll
       (partition-all (max 1 n))
       (mapcat (fn [chunk] (doall (pmap f chunk))))))

;; ---------------------------------------------------------------------------
;; circuit breaker

(defn breaker
  "A one-shot circuit breaker, shared across one provider run.

  Without it, per-request retry costs multiply: a source that answers
  `Retry-After: 30` and a store of 53 vulnerabilities means 53 independent
  waits, and an enrichment run that should take seconds takes forty minutes.
  Being rate-limited is a fact about the *source*, not about one id, so the
  first id to exhaust its retries tells the rest not to bother."
  []
  (atom {:open? false :reason nil}))

(defn open?
  "Has this run already given up on the source?"
  [b]
  (and b (:open? @b)))

(defn trip!
  "Give up on the source for the rest of this run.

  `swap-vals!` rather than check-then-act: several requests are in flight when
  the limit is hit, and a plain `(when-not (:open? @b) ...)` lets each of them
  log the same message."
  [b reason]
  (when b
    (let [[old _] (swap-vals! b (fn [{:keys [open?] :as st}]
                                  (if open?
                                    st
                                    {:open? true :reason reason})))]
      (when-not (:open? old)
        (log/infof "backing off for the rest of this run: %s" reason)))))

(def max-backoff-ms
  "Cap on a single sleep. A server asking us to come back in an hour is not a
  reason to hold a report hostage for an hour; we give up and return what we
  have instead."
  60000)

(defn with-retries
  "Call `(f)`, retrying a retryable failure.

  `retryable?` decides from the returned value; a 429 or a 5xx is worth
  retrying, a 404 is not. When the response carries `:retry-after-ms` -- what
  the server itself asked for -- that wins over exponential back-off, which
  would otherwise sleep either too little and be refused again, or far too
  long for no reason.

  Returns `fallback` once attempts are exhausted, because a provider that
  gives up must degrade to 'no data' rather than take the run down with it."
  [{:keys [attempts base-delay-ms retryable? label fallback]
    :or   {attempts 4 base-delay-ms 500 retryable? (constantly true)}}
   f]
  (loop [attempt 1]
    (let [result (try
                   {:ok (f)}
                   (catch Exception e {:error e}))
          value  (:ok result)]
      (cond
        (and value (not (retryable? value)))
        value

        (>= attempt attempts)
        (do (log/debugf "%s: giving up after %d attempts%s"
                        (or label "request") attempts
                        (if-let [e (:error result)]
                          (str ": " (.getMessage ^Exception e))
                          (str " (last status " (:status value) ")")))
            fallback)

        :else
        (let [asked (:retry-after-ms value)
              delay (min max-backoff-ms
                         (or asked (* base-delay-ms (long (Math/pow 2 (dec attempt))))))]
          (log/debugf "%s: attempt %d got %s, waiting %dms%s"
                      (or label "request") attempt (:status value) delay
                      (if asked " (server asked)" ""))
          (Thread/sleep delay)
          (recur (inc attempt)))))))

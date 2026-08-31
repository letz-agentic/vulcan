(ns vulcan.common
  "Shared utilities used across layers.

  This namespace exists to break the circular dependency between ingest and
  enrich: both need JSON serialization and content-derived hashing, but enrich
  must not depend on ingest (spec section 2). Extract common utilities here
  and let both layers depend on this."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [jsonista.core :as j])
  (:import (java.security MessageDigest)
           (java.io ByteArrayOutputStream InputStream)
           (java.time Instant OffsetDateTime)
           (java.time.format DateTimeParseException)))

;; ---------------------------------------------------------------------------
;; JSON

(def mapper
  "Jackson mapper producing keyword keys. Trivy's JSON is PascalCase, so keys
  arrive as `:SchemaVersion`, `:Results` and so on; normalisation in
  `vulcan.ingest.trivy` is the only place that knows those names."
  (j/object-mapper {:decode-key-fn true}))

(defn parse-json
  "Parse JSON bytes or string into a Clojure map with keyword keys."
  [input]
  (j/read-value input mapper))

(defn write-json
  "Serialise a value to a JSON string."
  ^String [v]
  (j/write-value-as-string v))

;; ---------------------------------------------------------------------------
;; Hashing

(defn sha256
  "Lowercase hex SHA-256 of a byte array."
  [^bytes bs]
  (let [digest (.digest (MessageDigest/getInstance "SHA-256") bs)]
    (apply str (map #(format "%02x" %) digest))))

(defn hash-id
  "Content-derived id: SHA-256 over the parts.

  The parts are hashed as a *printed vector*, not a joined string: every
  plausible separator can legitimately occur inside a Trivy target or PURL,
  and [\"ab\" \"c\"] must not collide with [\"a\" \"bc\"]. `pr-str` quotes and
  escapes each part, so the encoding is unambiguous; it is stable across
  platforms because the structure it adds is pure ASCII."
  [& parts]
  (sha256 (.getBytes (pr-str (mapv #(or % "") parts)) "UTF-8")))

;; ---------------------------------------------------------------------------
;; IO

(defn read-bytes
  "Slurp a file, stream or reader-coercible source into a byte array."
  ^bytes [source]
  (with-open [in  (io/input-stream source)
              out (ByteArrayOutputStream.)]
    (io/copy ^InputStream in out)
    (.toByteArray out)))

;; ---------------------------------------------------------------------------
;; Time

(defn ->instant
  "Parse an RFC-3339 timestamp with offset or Z suffix to an Instant.
  Anything unparseable becomes nil rather than failing: a missing date
  is a gap in analysis, not a corrupt file."
  [s]
  (when-not (str/blank? s)
    (try
      (.toInstant (OffsetDateTime/parse s))
      (catch DateTimeParseException _
        (try (Instant/parse s) (catch DateTimeParseException _ nil))))))

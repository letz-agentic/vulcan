(ns vulcan.ingest.json
  "Byte-level entry point for report files (spec §6.2).

  Identity is content-derived: the scan id is the SHA-256 of the raw report
  bytes, so the same file found in two directories is the same scan and
  re-ingestion is a no-op. Hashing happens on bytes, never on a decoded
  string, so line endings and platform cannot shift the id."
  (:require [clojure.java.io :as io]
            [jsonista.core :as j])
  (:import (java.security MessageDigest)
           (java.io ByteArrayOutputStream InputStream)))

(def mapper
  "Jackson mapper producing keyword keys. Trivy's JSON is PascalCase, so keys
  arrive as `:SchemaVersion`, `:Results` and so on; normalisation in
  `vulcan.ingest.trivy` is the only place that knows those names."
  (j/object-mapper {:decode-key-fn true}))

(defn sha256
  "Lowercase hex SHA-256 of a byte array."
  [^bytes bs]
  (let [digest (.digest (MessageDigest/getInstance "SHA-256") bs)]
    (apply str (map #(format "%02x" %) digest))))

(defn read-bytes
  "Slurp a file, stream or reader-coercible source into a byte array."
  ^bytes [source]
  (with-open [in  (io/input-stream source)
              out (ByteArrayOutputStream.)]
    (io/copy ^InputStream in out)
    (.toByteArray out)))

(defn parse
  "Parse report bytes into a Clojure map with keyword keys."
  [^bytes bs]
  (j/read-value bs mapper))

(defn write-str
  "Serialise a value back to a JSON string, for the `raw`/`cvss` JSON columns."
  ^String [v]
  (j/write-value-as-string v))

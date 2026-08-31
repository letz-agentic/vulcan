(ns vulcan.ingest.json
  "Byte-level entry point for report files (spec §6.2).

  Identity is content-derived: the scan id is the SHA-256 of the raw report
  bytes, so the same file found in two directories is the same scan and
  re-ingestion is a no-op. Hashing happens on bytes, never on a decoded
  string, so line endings and platform cannot shift the id.

  Core utilities live in `vulcan.common`; this namespace re-exports them for
  backwards compatibility and adds ingest-specific conveniences."
  (:require [vulcan.common :as common]))

(def mapper
  "Jackson mapper producing keyword keys. Delegated to `vulcan.common`."
  common/mapper)

(def sha256
  "Lowercase hex SHA-256 of a byte array. Delegated to `vulcan.common`."
  common/sha256)

(def read-bytes
  "Slurp a file, stream or reader-coercible source into a byte array.
  Delegated to `vulcan.common`."
  common/read-bytes)

(defn parse
  "Parse report bytes into a Clojure map with keyword keys."
  [^bytes bs]
  (common/parse-json bs))

(defn write-str
  "Serialise a value back to a JSON string, for the `raw`/`cvss` JSON columns."
  ^String [v]
  (common/write-json v))

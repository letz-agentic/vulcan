(ns vulcan.ingest.schema
  "Malli schemas for the Trivy report (spec §3 validation row, §6.2).

  These are deliberately *loose*: Trivy adds fields between releases and we
  must not reject a report because it gained a key. What we assert is the
  spine — schema version 2, a results array, and the handful of fields the
  normaliser dereferences — so that a malformed file fails at the boundary
  with a readable message instead of as a NullPointerException three layers
  down."
  (:require [malli.core :as m]
            [malli.error :as me]))

(def supported-schema-version 2)

(def Vulnerability
  [:map {:closed false}
   [:VulnerabilityID :string]
   [:PkgName {:optional true} [:maybe :string]]
   [:InstalledVersion {:optional true} [:maybe :string]]
   [:FixedVersion {:optional true} [:maybe :string]]
   [:Status {:optional true} [:maybe :string]]
   [:Severity {:optional true} [:maybe :string]]
   [:CVSS {:optional true} [:maybe :map]]
   [:PublishedDate {:optional true} [:maybe :string]]
   [:LastModifiedDate {:optional true} [:maybe :string]]])

(def Pkg
  [:map {:closed false}
   [:Name {:optional true} [:maybe :string]]
   [:Version {:optional true} [:maybe :string]]])

(def Result
  [:map {:closed false}
   [:Target :string]
   [:Class {:optional true} [:maybe :string]]
   [:Type {:optional true} [:maybe :string]]
   [:Vulnerabilities {:optional true} [:maybe [:sequential Vulnerability]]]
   [:Packages {:optional true} [:maybe [:sequential Pkg]]]])

(def Report
  [:map {:closed false}
   [:SchemaVersion :int]
   [:ArtifactName {:optional true} [:maybe :string]]
   [:ArtifactType {:optional true} [:maybe :string]]
   [:CreatedAt {:optional true} [:maybe :string]]
   [:Metadata {:optional true} [:maybe :map]]
   [:Results {:optional true} [:maybe [:sequential Result]]]])

(def ^:private report-validator (m/validator Report))
(def ^:private report-explainer (m/explainer Report))

(defn validate
  "Returns `nil` when `report` is acceptable, or a map describing why it is
  not. Two distinct rejections (spec §6.3): a structurally malformed report,
  and one whose `SchemaVersion` is not 2 — the latter names the version it
  found, because that is the message a user can act on."
  [report]
  (cond
    (not (map? report))
    {:reason :not-a-map
     :message "Report is not a JSON object"}

    (not= supported-schema-version (:SchemaVersion report))
    {:reason  :unsupported-schema-version
     :message (format "Unsupported Trivy SchemaVersion %s (expected %d)"
                      (pr-str (:SchemaVersion report)) supported-schema-version)
     :found   (:SchemaVersion report)}

    (not (report-validator report))
    (let [errors (me/humanize (report-explainer report))]
      {:reason  :malformed
       :message (str "Report does not match the Trivy schema: " (pr-str errors))
       :errors  errors})

    :else nil))

(ns vulcan.arch-test
  "The layering rule from spec section 2, enforced rather than documented.

  This is cheap to run and prevents the lab-file entropy the project exists to
  escape: the moment `vulcan.analysis` requires a chart namespace, or
  `vulcan.store` reaches up into reporting, the whole 'same data, many
  stories' property quietly stops holding."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]))

(def forbidden
  "layer prefix -> namespace prefixes it must not depend on (spec section 2)."
  {"vulcan.ingest"   ["vulcan.viz" "vulcan.report" "notebooks" "scicloj.clay"
                      "scicloj.tableplot" "scicloj.kindly"]
   "vulcan.store"    ["vulcan.ingest" "vulcan.enrich" "vulcan.analysis"
                      "vulcan.viz" "vulcan.report" "notebooks" "scicloj.clay"
                      "scicloj.tableplot" "scicloj.kindly"]
   "vulcan.enrich"   ["vulcan.viz" "vulcan.report" "notebooks" "scicloj.clay"
                      "scicloj.tableplot"]
   "vulcan.analysis" ["vulcan.viz" "vulcan.report" "notebooks" "scicloj.clay"
                      "scicloj.tableplot" "scicloj.kindly"]
   "vulcan.viz"      ["vulcan.report" "notebooks" "scicloj.clay"]})

(defn- clj-files [dir]
  (->> (file-seq (io/file dir))
       (filter #(.isFile ^java.io.File %))
       (filter #(str/ends-with? (.getName ^java.io.File %) ".clj"))))

(defn- ns-form
  "The `ns` form of a source file, or nil if it has none."
  [file]
  (with-open [r (java.io.PushbackReader. (io/reader file))]
    (loop []
      (let [form (try (read {:eof ::eof :read-cond :preserve} r)
                      (catch Exception _ ::eof))]
        (cond
          (= ::eof form) nil
          (and (seq? form) (= 'ns (first form))) form
          :else (recur))))))

(defn- required-namespaces
  "Every namespace symbol mentioned in `:require` or `:use`."
  [ns-form]
  (->> ns-form
       (filter seq?)
       (filter #(#{:require :use} (first %)))
       (mapcat rest)
       (map #(if (sequential? %) (first %) %))
       (filter symbol?)
       (map str)))

(defn violations
  "Every dependency that crosses a layer boundary the wrong way."
  []
  (for [file (clj-files "src")
        :let [form (ns-form file)]
        :when form
        :let [this-ns (str (second form))]
        [layer banned] forbidden
        :when (str/starts-with? this-ns layer)
        dep (required-namespaces form)
        bad banned
        :when (str/starts-with? dep bad)]
    {:file (.getPath ^java.io.File file) :ns this-ns :requires dep :rule [layer bad]}))

(deftest dependency-direction-holds
  (let [vs (violations)]
    (is (empty? vs)
        (str "layering violations (spec section 2):\n"
             (str/join "\n" (map (fn [{:keys [ns requires]}]
                                   (str "  " ns " must not require " requires))
                                 vs))))))

(deftest every-source-file-declares-a-namespace
  (testing "a file without an ns form is a lab file, which is what we are escaping"
    (is (empty? (remove ns-form (clj-files "src"))))))

(deftest the-rule-can-actually-fail
  (testing "guard against a checker that vacuously passes"
    (with-redefs [forbidden {"vulcan.store" ["next.jdbc"]}]
      (is (seq (violations))
          "vulcan.store namespaces do require next.jdbc, so this must be caught"))))

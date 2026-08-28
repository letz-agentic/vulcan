(ns vulcan.analysis.diff
  "What changed since last time (spec section 8.4).

  Findings are compared between the current scan of an artifact and the one
  immediately before it, and labelled `new`, `persisting` or one of the two
  resolved outcomes, because those mean different things to an engineer:

    fixed-by-upgrade -- the package is still installed, at a newer version;
    disappeared      -- the package is no longer in the artifact at all.

  Whether a package is still installed is read from the `package` table, not
  from the surviving findings. Reading it from findings would be wrong in the
  common case: a package that was upgraded past its last CVE has no findings
  left, and would be reported as having vanished from the image when in fact
  it is right there, fixed. When scans were run without `--list-all-pkgs`
  there is no package table to consult, and the two outcomes cannot be told
  apart; they are then reported as the single label `resolved`.

  Comparison is by `(artifact, vulnerability, package)` and deliberately *not*
  by `finding_id`: the finding id includes the installed version, so every
  upgrade would make one finding look new and another resolved -- the exact
  opposite of what happened."
  (:require [clojure.set :as set]
            [tablecloth.api :as tc]
            [vulcan.store.query :as q]))

(defn- finding-key [{:keys [artifact-name vulnerability-id pkg-name]}]
  [artifact-name vulnerability-id pkg-name])

(defn- rows-by-key [ds]
  (into {} (map (juxt finding-key identity)) (tc/rows ds :as-maps)))

(defn- installed-versions
  "Installed version per `(artifact, package)` from the package inventory."
  [packages-ds]
  (when (and packages-ds (pos? (tc/row-count packages-ds)))
    (into {} (map (fn [{:keys [artifact-name pkg-name version]}]
                    [[artifact-name pkg-name] version]))
          (tc/rows packages-ds :as-maps))))

(defn- resolved-label
  "Split a resolved finding into its two outcomes, or fall back to the
  undifferentiated `resolved` when there is no package inventory."
  [inventory previous-row [artifact _vuln pkg]]
  (if (nil? inventory)
    "resolved"
    (if-let [now (get inventory [artifact pkg])]
      (if (= now (:installed-version previous-row))
        ;; Still installed, unchanged: the advisory stopped applying rather
        ;; than the package being fixed. Not an upgrade, and not gone.
        "no-longer-reported"
        "fixed-by-upgrade")
      "disappeared")))

(defn diff-rows
  "Compare two collections of finding rows. Pure, so it is the unit under
  test; `diff` below is the thin wrapper that fetches them.

  `current-packages` is the package inventory of the *current* scan, and may
  be nil when the scan carried no `--list-all-pkgs` data."
  [current-ds previous-ds current-packages]
  (let [cur       (rows-by-key current-ds)
        prev      (rows-by-key previous-ds)
        cur-keys  (set (keys cur))
        prev-keys (set (keys prev))
        inventory (installed-versions current-packages)
        label     (fn [k]
                    (let [row (or (cur k) (prev k))]
                      (assoc row
                             :change
                             (cond
                               (not (prev-keys k)) "new"
                               (cur-keys k)        "persisting"
                               :else (resolved-label inventory (prev k) k)))))]
    (mapv label (sort (set/union cur-keys prev-keys)))))

(def ^:private empty-diff
  {:artifact-name [] :vulnerability-id [] :pkg-name [] :severity [] :change []})

(defn diff
  "Diff every artifact in scope against its own previous scan.

  Artifacts scanned only once contribute nothing: there is no honest way to
  call a first scan's findings `new`, and doing so would make every trend
  begin with a spike that never happened."
  [connectable scope]
  (let [pairs (q/previous-scan-ids connectable scope)]
    (if (empty? pairs)
      (tc/dataset empty-diff {:dataset-name "diff"})
      (let [rows (mapcat (fn [[_artifact {:keys [current previous]}]]
                           (diff-rows (q/findings connectable {:scan-ids [current]})
                                      (q/findings connectable {:scan-ids [previous]})
                                      (q/packages connectable {:scan-ids [current]})))
                         pairs)]
        (if (empty? rows)
          (tc/dataset empty-diff {:dataset-name "diff"})
          (tc/dataset rows {:dataset-name "diff"}))))))

(defn summary
  "Counts per change label, which is what the waterfall chart plots."
  [diff-ds]
  (if (zero? (tc/row-count diff-ds))
    (tc/dataset {:change [] :n []} {:dataset-name "diff-summary"})
    (-> diff-ds
        (tc/group-by [:change])
        (tc/aggregate {:n tc/row-count})
        (tc/order-by [:change])
        (tc/set-dataset-name "diff-summary"))))

(ns vulcan.report.render
  "Notebook + profile -> rendered output (spec sections 10.3, 10.4).

  Everything format-specific lives behind `render!`, so notebooks are
  unaffected by how the output is actually produced.

  What a spike established, and what the design now relies on (spec section
  13, open question 1): Clay 2.0.21 *does* drive `pptx` and `pdf` directly
  through `:format [:quarto :pptx]`, with no `quarto render --to` post-step --
  but only if the profile also replaces Clay's default `:quarto {:format ...}`
  map. Clay writes that map verbatim into the qmd front matter, so a profile
  that sets `:format [:quarto :pptx]` and leaves the default `:quarto` config
  alone emits front matter offering `html` and `revealjs`, and Quarto renders
  HTML while reporting success. Each profile below therefore carries its own
  complete `:quarto :format` map. See doc/adr/0003-clay-output-profiles.md."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [scicloj.clay.v2.api :as clay]
            [vulcan.report.kinds :as kinds]
            [vulcan.viz.static :as static]))

(def base-defaults
  {:base-target-path "target/reports"
   :hide-ui-header   true
   :hide-info-line   true
   :browse           false
   :show             false
   ;; Code is hidden in every report profile (spec section 10.1 rule 3): a
   ;; reader of the posture deck is not the audience for a `tc/group-by`.
   ;; The `:explore` profile below turns this back on.
   :hide-code        true})

(def profiles
  "One Clay spec per output format. `slide-level 2` is fixed across all of
  them so that the same `##` headings work as sections in a document and as
  slides in a deck (spec section 10.1 rule 2)."
  {:html     {:format [:quarto :html]
              :quarto {:slide-level 2
                       :format {:html {:theme :cosmo
                                       :toc true
                                       :toc-depth 3
                                       :embed-resources true}}}}
   :revealjs {:format [:quarto :revealjs]
              :quarto {:slide-level 2
                       :format {:revealjs {:theme :simple
                                           :incremental false
                                           :embed-resources true}}}}
   :pptx     {:format [:quarto :pptx]
              :quarto {:slide-level 2
                       :format {:pptx {}}}}
   :pdf      {:format [:quarto :pdf]
              :quarto {:slide-level 2
                       :format {:pdf {:documentclass :article}}}}

   ;; The workbench profile (spec section 10.1 rule 3). Same context, same
   ;; charts, but the code is the point rather than an implementation detail.
   :explore  {:format [:quarto :html]
              :hide-code false
              :quarto {:slide-level 2
                       :format {:html {:theme :cosmo
                                       :toc true
                                       :toc-depth 3
                                       :embed-resources true}}}}})

(defn profile-names [] (vec (sort (keys profiles))))

(defn clay-config
  "Shared defaults from `clay.edn`, if present."
  []
  (let [f (io/file "clay.edn")]
    (when (.exists f) (edn/read-string (slurp f)))))

;; ---------------------------------------------------------------------------
;; notebooks

(def notebook-root "notebooks")

(defn- notebook-path
  "`management/posture` -> `notebooks/management/posture.clj`. A path that
  already looks like a file is taken as-is."
  [nb]
  (let [s (str nb)]
    (if (str/ends-with? s ".clj")
      s
      (str notebook-root "/" (str/replace s "." "/") ".clj"))))

(defn notebooks
  "Every notebook under `notebooks/`, excluding the `_template_*` files, which
  are meant to be copied rather than required (spec section 10.2)."
  []
  (->> (file-seq (io/file notebook-root))
       (filter #(.isFile ^java.io.File %))
       (filter #(str/ends-with? (.getName ^java.io.File %) ".clj"))
       (remove #(str/starts-with? (.getName ^java.io.File %) "_template"))
       (map #(.getPath ^java.io.File %))
       sort
       vec))

;; ---------------------------------------------------------------------------
;; preconditions

(defn- ensure-tools!
  "Fail before rendering, not halfway through it.

  A missing Quarto surfaces from Clay as a generic \"Clay Quarto failed\"
  several minutes into a run; checking here turns that into one clear line."
  [profile]
  (let [needed (cond-> #{"quarto"}
                 (contains? #{:pptx :pdf} profile) (conj "vl-convert"))
        checks (cond-> (filterv #(needed (:tool %)) (static/check))
                 ;; Only the pdf profile needs LaTeX, and Quarto reports its
                 ;; absence as a generic failure minutes into the render.
                 (= :pdf profile) (conj (static/check-latex (static/config))))]
    (when-let [bad (seq (remove :ok? checks))]
      (throw (ex-info (str "Required tools are not ready:\n"
                           (str/join "\n" (map #(str "  " (:tool %) ": " (:message %)) bad)))
                      {:checks bad})))
    checks))

;; ---------------------------------------------------------------------------

(defn render!
  "Render one notebook under one profile. Returns the Clay spec used.

  The profile is passed to the notebook through `VULCAN_PROFILE`, which
  `vulcan.report.context/load!` reads -- that is how a notebook knows whether
  to emit an interactive chart or a static image."
  [notebook profile & [{:keys [db scope target-path] :as _opts}]]
  (let [spec (get profiles profile)]
    (when-not spec
      (throw (ex-info "Unknown profile" {:profile profile
                                         :known (profile-names)})))
    (ensure-tools! profile)
    (kinds/reset-chart-counter!)
    (let [path (notebook-path notebook)]
      (when-not (.exists (io/file path))
        (throw (ex-info "No such notebook" {:notebook notebook :path path})))
      (log/infof "rendering %s as %s" path (name profile))
      ;; The context reads these from the environment; setting them as system
      ;; properties keeps a single-process render self-contained.
      ;; `:explore` differs from `:html` only in what it shows, not in how
      ;; charts are represented, so the context sees it as :html.
      (System/setProperty "vulcan.profile"
                          (name (if (= :explore profile) :html profile)))
      ;; Static chart PNGs go beside the generated qmd, because Quarto
      ;; resolves image paths relative to the qmd it is rendering.
      (let [out-root (or target-path (:base-target-path base-defaults))
            img-dir  (io/file out-root kinds/image-subdir)]
        (.mkdirs img-dir)
        (System/setProperty "vulcan.image-dir" (.getPath img-dir)))
      (when db (System/setProperty "vulcan.db" (str db)))
      (when scope (System/setProperty "vulcan.scope" (pr-str scope)))
      (let [full (merge base-defaults
                        (clay-config)
                        spec
                        {:source-path path}
                        (when target-path {:base-target-path target-path}))]
        (clay/make! full)
        full))))

(defn render-all!
  "Render every notebook under one profile."
  [profile & [opts]]
  (mapv #(render! % profile opts) (notebooks)))

(defn report!
  "Render a named set of notebooks across a set of profiles (spec section
  10.4's `bb report`). Returns a seq of `{:notebook :profile :ok? :error}` so
  that one broken profile does not hide the rest."
  [{selected-notebooks :notebooks selected-profiles :profiles
    :keys [db scope target-path]}]
  (let [nbs (or (seq selected-notebooks) (notebooks))
        pfs (or (seq selected-profiles) [:html])]
    (vec
     (for [nb nbs, pf pfs]
       (try
         (render! nb pf {:db db :scope scope :target-path target-path})
         {:notebook nb :profile pf :ok? true}
         (catch Exception e
           (log/warnf e "failed to render %s as %s" nb (name pf))
           {:notebook nb :profile pf :ok? false :error (.getMessage e)}))))))

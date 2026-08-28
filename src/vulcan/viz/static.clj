(ns vulcan.viz.static
  "Vega-Lite specs to static images, via the pinned `vl-convert` binary
  (spec section 9.2).

  Why this exists: Quarto drops raw HTML when rendering pptx and PDF. An
  interactive Plotly figure in a notebook simply *vanishes* from a PowerPoint
  deck -- no error, no placeholder, just a slide with a heading and nothing
  under it. That failure is silent, which is what makes it dangerous, so every
  chart in the toolkit must have a static path and the pptx/PDF profiles must
  take it.

  `vl-convert` is a single self-contained Rust binary embedding its own
  JavaScript engine: no Node, no browser, no network. It is pinned by version
  and SHA-256 in `vulcan.edn` and verified by `bb check`.

  The renderer is a protocol so an in-JVM implementation can replace it later
  without touching chart code."
  (:require [babashka.process :as p]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [jsonista.core :as j])
  (:import (java.io File)
           (java.security MessageDigest)))

(defprotocol StaticRenderer
  (render-svg* [this spec] "Vega-Lite spec -> SVG string.")
  (render-png* [this spec opts] "Vega-Lite spec -> PNG bytes."))

;; ---------------------------------------------------------------------------
;; configuration

(def default-config
  {:vl-convert {:path        "tools/bin/vl-convert"
                :version     "1.9.0"
                ;; The Vega-Lite version to compile against. tableplot's
                ;; Hanami target emits specs that render cleanly at 5.21,
                ;; which is also vl-convert 1.9.0's own default.
                :vl-version  "5.21"
                :sha256      nil}
   :quarto     {:path    "tools/bin/quarto"
                :version "1.10.18"}})

(defn config
  "Tool configuration from `vulcan.edn`, merged over the defaults."
  []
  (let [f (io/file "vulcan.edn")]
    (merge-with merge default-config
                (when (.exists f)
                  (select-keys (edn/read-string (slurp f)) [:vl-convert :quarto])))))

(defn sha256-file
  "Lowercase hex SHA-256 of a file's bytes, for the supply-chain check."
  [file]
  (let [digest (MessageDigest/getInstance "SHA-256")
        buf    (byte-array 65536)]
    (with-open [in (io/input-stream file)]
      (loop []
        (let [n (.read in buf)]
          (when (pos? n)
            (.update digest buf 0 n)
            (recur)))))
    (apply str (map #(format "%02x" %) (.digest digest)))))

;; ---------------------------------------------------------------------------
;; the vl-convert renderer

(defn- write-spec! [spec]
  (let [f (File/createTempFile "vulcan-vl-" ".json")]
    (spit f (j/write-value-as-string spec))
    f))

(defn- run-vl-convert!
  "Invoke `vl-convert <sub> -i in -o out`. Throws with the binary's own stderr,
  because a Vega-Lite compile error is the only useful thing to report."
  [{:keys [path vl-version]} sub spec out-file extra]
  (let [in (write-spec! spec)]
    (try
      (let [{:keys [exit err]} @(p/process (concat [path (name sub)
                                                    "-i" (.getPath in)
                                                    "-o" (.getPath ^File out-file)
                                                    "-v" vl-version]
                                                   extra)
                                           {:out :string :err :string})]
        (when-not (zero? exit)
          (throw (ex-info "vl-convert failed"
                          {:exit exit :stderr err :sub sub})))
        out-file)
      (finally (.delete in)))))

(defrecord VlConvertRenderer [cfg]
  StaticRenderer
  (render-svg* [_ spec]
    (let [out (File/createTempFile "vulcan-vl-" ".svg")]
      (try
        (run-vl-convert! cfg :vl2svg spec out nil)
        (slurp out)
        (finally (.delete out)))))

  (render-png* [_ spec {:keys [scale]}]
    (let [out (File/createTempFile "vulcan-vl-" ".png")]
      (try
        (run-vl-convert! cfg :vl2png spec out
                         (when scale ["--scale" (str scale)]))
        (with-open [in (io/input-stream out)
                    bos (java.io.ByteArrayOutputStream.)]
          (io/copy in bos)
          (.toByteArray bos))
        (finally (.delete out))))))

(defn renderer
  "The configured static renderer."
  ([] (renderer (config)))
  ([cfg] (->VlConvertRenderer (:vl-convert cfg))))

;; ---------------------------------------------------------------------------
;; public API

(defn render-svg
  "Vega-Lite spec -> SVG string."
  ([spec] (render-svg (renderer) spec))
  ([r spec] (render-svg* r spec)))

(defn render-png
  "Vega-Lite spec -> PNG bytes. Used where SVG is awkward; Quarto's pptx
  writer handles PNG more predictably than SVG."
  ([spec] (render-png (renderer) spec {}))
  ([r spec] (render-png* r spec {}))
  ([r spec opts] (render-png* r spec opts)))

(defn render-png-file!
  "Vega-Lite spec -> a PNG on disk, returning the file. Notebooks embed images
  by path so that Quarto copies them into the deck."
  [r spec ^File out-file]
  (io/make-parents out-file)
  (io/copy (render-png r spec) out-file)
  out-file)

;; ---------------------------------------------------------------------------
;; supply-chain verification (spec section 10.5)

(defn- check-tool
  [{:keys [path version sha256]} label version-args version-re]
  (let [f (io/file path)]
    (cond
      (not (.exists f))
      {:tool label :ok? false
       :message (str "not found at " path
                     " -- see README 'Pinned tools' for how to install it")}

      :else
      (let [{:keys [exit out err]} (try
                                     @(p/process (cons path version-args)
                                                 {:out :string :err :string})
                                     (catch Exception e
                                       {:exit 1 :err (.getMessage e) :out ""}))
            ;; The version regex has no capture groups, so re-find returns a
            ;; String, not a vector -- taking `first` would yield a Character.
            found (some-> (str out " " err) (->> (re-find version-re)) str/trim)
            actual-sha (when (.isFile f) (sha256-file f))]
        (cond
          (not (zero? exit))
          {:tool label :ok? false :message (str "could not run " path ": " err)}

          (and version found (not (str/includes? found version)))
          {:tool label :ok? false
           :message (format "version mismatch: pinned %s, found %s" version found)}

          (and sha256 actual-sha (not= sha256 actual-sha))
          {:tool label :ok? false
           :message (format "checksum mismatch: pinned %s, found %s" sha256 actual-sha)}

          :else
          {:tool label :ok? true :version found :sha256 actual-sha
           :message (str label " " found " ok"
                         (when-not sha256 " (no checksum pinned)"))})))))

(defn check-latex
  "Is a LaTeX engine available? Only the `:pdf` profile needs one, and Quarto
  reports its absence as a generic render failure several minutes in, so we
  check it up front and say exactly what to run."
  [cfg]
  (let [quarto (get-in cfg [:quarto :path])
        {:keys [exit out err]} (try
                                 @(p/process [quarto "check" "install"]
                                             {:out :string :err :string})
                                 (catch Exception e
                                   {:exit 1 :out "" :err (.getMessage e)}))
        text (str out " " err)]
    (if (and (zero? exit) (re-find #"(?i)tinytex|texlive|pdflatex|lualatex" text)
             (not (re-find #"(?i)quarto install tinytex" text)))
      {:tool "latex" :ok? true :message "a LaTeX engine is available"}
      {:tool "latex" :ok? false
       :message (str "no LaTeX engine found -- the pdf profile needs one. "
                     "Run: " quarto " install tinytex")})))

(defn check
  "Verify the pinned external tools. Returns a seq of
  `{:tool :ok? :message}`; `bb check` turns a false into an exit code.

  LaTeX is reported but never fails the check: only the `:pdf` profile needs
  it, and most runs do not produce a PDF."
  ([] (check (config)))
  ([cfg]
   [(check-tool (:vl-convert cfg) "vl-convert" ["--version"] #"\d+\.\d+\.\d+")
    (check-tool (:quarto cfg) "quarto" ["--version"] #"\d+\.\d+\.\d+")]))

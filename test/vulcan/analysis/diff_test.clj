(ns vulcan.analysis.diff-test
  (:require [clojure.test :refer [deftest is testing]]
            [tablecloth.api :as tc]
            [vulcan.analysis.diff :as diff]
            [vulcan.test-store :as ts]))

(defn- ds [rows] (tc/dataset rows))

(defn- changes [rows]
  (into {} (map (juxt :vulnerability-id :change)) rows))

;; ---------------------------------------------------------------------------
;; the pure core

(deftest labels-new-persisting-and-resolved
  (let [previous (ds [{:artifact-name "app" :vulnerability-id "CVE-1"
                       :pkg-name "openssl" :installed-version "1.0"}
                      {:artifact-name "app" :vulnerability-id "CVE-2"
                       :pkg-name "curl" :installed-version "7.0"}])
        current  (ds [{:artifact-name "app" :vulnerability-id "CVE-2"
                       :pkg-name "curl" :installed-version "7.0"}
                      {:artifact-name "app" :vulnerability-id "CVE-3"
                       :pkg-name "zlib" :installed-version "1.1"}])
        packages (ds [{:artifact-name "app" :pkg-name "openssl" :version "1.1"}
                      {:artifact-name "app" :pkg-name "curl" :version "7.0"}
                      {:artifact-name "app" :pkg-name "zlib" :version "1.1"}])]
    (is (= {"CVE-1" "fixed-by-upgrade"
            "CVE-2" "persisting"
            "CVE-3" "new"}
           (changes (diff/diff-rows current previous packages))))))

(deftest a-removed-package-disappeared
  (testing "gone from the inventory, not merely gone from the findings"
    (let [previous (ds [{:artifact-name "app" :vulnerability-id "CVE-1"
                         :pkg-name "leftpad" :installed-version "1.0"}])
          current  (ds [{:artifact-name "app" :vulnerability-id "CVE-9"
                         :pkg-name "curl" :installed-version "7.0"}])
          packages (ds [{:artifact-name "app" :pkg-name "curl" :version "7.0"}])]
      (is (= "disappeared" (get (changes (diff/diff-rows current previous packages))
                                "CVE-1"))))))

(deftest an-upgraded-package-is-not-reported-as-vanished
  (testing "the regression this design exists to prevent"
    (let [previous (ds [{:artifact-name "app" :vulnerability-id "CVE-1"
                         :pkg-name "musl" :installed-version "1.2.4"}])
          ;; No findings left for musl at all -- it was upgraded past them.
          current  (ds [{:artifact-name "app" :vulnerability-id "CVE-9"
                         :pkg-name "curl" :installed-version "7.0"}])
          packages (ds [{:artifact-name "app" :pkg-name "musl" :version "1.2.5"}
                        {:artifact-name "app" :pkg-name "curl" :version "7.0"}])]
      (is (= "fixed-by-upgrade"
             (get (changes (diff/diff-rows current previous packages)) "CVE-1"))))))

(deftest same-version-still-installed-is-not-an-upgrade
  (let [previous (ds [{:artifact-name "app" :vulnerability-id "CVE-1"
                       :pkg-name "musl" :installed-version "1.2.4"}])
        current  (ds [{:artifact-name "app" :vulnerability-id "CVE-9"
                       :pkg-name "musl" :installed-version "1.2.4"}])
        packages (ds [{:artifact-name "app" :pkg-name "musl" :version "1.2.4"}])]
    (is (= "no-longer-reported"
           (get (changes (diff/diff-rows current previous packages)) "CVE-1")))))

(deftest without-a-package-inventory-resolved-is-undifferentiated
  (testing "no --list-all-pkgs means the two outcomes cannot honestly be told apart"
    (let [previous (ds [{:artifact-name "app" :vulnerability-id "CVE-1"
                         :pkg-name "musl" :installed-version "1.2.4"}])
          current  (ds [{:artifact-name "app" :vulnerability-id "CVE-9"
                         :pkg-name "curl" :installed-version "7.0"}])]
      (is (= "resolved" (get (changes (diff/diff-rows current previous nil)) "CVE-1"))))))

(deftest comparison-survives-an-upgrade
  (testing "keying on finding_id would call this one new and one resolved"
    (let [previous (ds [{:artifact-name "app" :vulnerability-id "CVE-1"
                         :pkg-name "musl" :installed-version "1.2.4"}])
          current  (ds [{:artifact-name "app" :vulnerability-id "CVE-1"
                         :pkg-name "musl" :installed-version "1.2.5"}])
          packages (ds [{:artifact-name "app" :pkg-name "musl" :version "1.2.5"}])]
      (is (= {"CVE-1" "persisting"}
             (changes (diff/diff-rows current previous packages)))))))

;; ---------------------------------------------------------------------------
;; against the store

(deftest diff-over-the-fixtures
  (ts/with-store [conn]
    (let [d (diff/diff conn :latest)
          summary (into {} (map (juxt :change :n))
                        (tc/rows (diff/summary d) :as-maps))]
      (testing "only alpine:3.19 has two scans, so only it contributes"
        (is (pos? (tc/row-count d)))
        (is (every? #(= "alpine:3.19" %) (:artifact-name d))))

      (testing "the fixture corpus exercises a real upgrade"
        (is (pos? (get summary "fixed-by-upgrade" 0)))))))

(deftest single-scan-artifacts-contribute-nothing
  (testing "a first scan's findings are not `new` -- there is nothing to compare"
    (ts/with-store [conn]
      (let [d (diff/diff conn {:artifacts ["node:18-alpine"]})]
        (is (zero? (tc/row-count d)))))))

(deftest summary-of-an-empty-diff-is-empty-not-broken
  (is (zero? (tc/row-count (diff/summary (tc/dataset {:change []}))))))

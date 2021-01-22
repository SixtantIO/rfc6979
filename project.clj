(defproject io.sixtant/rfc6979 "0.1.0-SNAPSHOT"
  :description "RFC 6979's deterministic DSA/ECDSA signature scheme in Clojure for arbitrary elliptic curves."
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [org.bouncycastle/bcprov-jdk15on "1.68"]]
  :java-source-paths ["src/java"]
  :repl-options {:init-ns io.sixtant.rfc6979})

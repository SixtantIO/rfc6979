(ns io.sixtant.rfc6979-test
  (:require [clojure.test :refer :all]
            [io.sixtant.rfc6979 :refer :all]))


(def order (biginteger 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831))
(def priv (biginteger (biginteger 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4)))


;; Tested against the python rfc6979 ns result for:
;; >>> generate_k(order, priv, hashlib.sha256, b"sample")
;; >>> generate_k(order, priv, hashlib.sha256, b"sample", extra_entropy=b"seed")
(deftest generate-ks-test
  (testing "vanilla rfc6979 k generation without extra entropy"
    (is
      (= (first
           (generate-ks
             {:curve-order order
              :private-key priv
              :data        (.getBytes "sample")
              :hash-digest (sha-256-digest)}))
         93987516925140233289636602974981363253087044111722771293)
      "`k` generation for message 'sample'"))

  (testing "section 3.6 rfc6979 k generation with extra entropy (k prime)"
    (is
      (= (first
           (generate-ks
             {:curve-order order
              :private-key priv
              :data        (.getBytes "sample")
              :hash-digest (sha-256-digest)
              :extra-entropy (.getBytes "seed")}))
         1976315346348424951535402330023639247709696865529252022598)
      "`k` generation for message 'sample' with entropy 'seed'")))

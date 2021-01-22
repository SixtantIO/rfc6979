(ns io.sixtant.rfc6979-test
  (:require [clojure.test :refer :all]
            [io.sixtant.rfc6979 :refer :all])
  (:import (org.bouncycastle.asn1.nist NISTNamedCurves)))


(def order (biginteger 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831))
(def priv (biginteger (biginteger 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4)))


(deftest generate-ks-test
  (testing "vanilla rfc6979 k generation without extra entropy"
    ;; Test vector from rfc6979 appendix 2.3
    ;; https://tools.ietf.org/html/rfc6979#appendix-A.2.3
    (is (= (first
             (generate-ks
               {:curve-order order
                :private-key priv
                :data        (hash-with-digest
                               (sha-256-digest)
                               (.getBytes "sample"))
                :hash-digest (sha-256-digest)}))
           0x32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496))

    ;; Tested against the python rfc6979 ns result for:
    ;; >>> generate_k(order, priv, hashlib.sha256, b"sample")
    (is
      (= (first
           (generate-ks
             {:curve-order order
              :private-key priv
              :data        (.getBytes "sample")
              :hash-digest (sha-256-digest)}))
         93987516925140233289636602974981363253087044111722771293)
      "`k` generation for message 'sample'"))

  ;; Tested against the python rfc6979 ns result for:
  ;; >>> generate_k(order, priv, hashlib.sha256, b"sample", extra_entropy=b"seed")
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


(deftest ecdsa-with-k-prime-test
  ;; Test vector from rfc6979 appendix 2.3
  ;; https://tools.ietf.org/html/rfc6979#appendix-A.2.3
  (testing "deterministic rfc6969 ec signature with extra entropy"
    (is (= (ec-sign-deterministic
             {:data          (hash-with-digest (sha-256-digest) (.getBytes "sample"))
              :private-key   priv
              :hash-digest   (sha-256-digest)
              :curve         (NISTNamedCurves/getByName "P-192")})
           [0x4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55
            0xCCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85])))

  ;; Tested against the python-ecdsa library with:
  ;; >>> from ecdsa import SigningKey
  ;; >>> from ecdsa.curves import NIST192p
  ;; >>> import hashlib
  ;; >>> exp = int('0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4', 16)
  ;; >>> k = SigningKey.from_secret_exponent(exp, hashfunc=hashlib.sha256, curve=NIST192p)
  ;; >>> k.sign_deterministic(b"sample", extra_entropy=b"seed", sigencode=lambda r, s, o: [r, s])
  (testing "deterministic rfc6969 ec signature with extra entropy"
    (is
      (= (ec-sign-deterministic
           {:data          (hash-with-digest (sha-256-digest) (.getBytes "sample"))
            :extra-entropy (.getBytes "seed")
            :private-key   priv
            :hash-digest   (sha-256-digest)
            :curve         (NISTNamedCurves/getByName "P-192")})
         [962550273645777332201477239297978599957983764722740361210
          1215809841795932025900241180552496703469250337438771316994]))))

(ns io.sixtant.rfc6979
  (:import (org.bouncycastle.crypto.digests SHA256Digest)
           (io.sixtant RFC6979)))


(defn sha-256-digest
  "A SHA256 digest suitable for the :hash-digest parameter of `generate-ks`."
  []
  (SHA256Digest.))


(defn generate-ks
  "Generate an infinite sequence of `k` values for ECDSA deterministically from
  `data`.

  Required
    - curve-order   Order of the curve (e.g. 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
                    for secp256k1).
    - private-key   Private key as a BigInteger.
    - data          Byte array of hashed message data (for signing).
    - hash-digest   An instance of org.bouncycastle.crypto.Digest specifying the
                    hash function to use (see `sha-256-digest` in this ns).
  Optional
    - extra-entropy A k' value as described in section 3.6 of rfc6979, and
                    as implemented in rfc6979.py."
  [{:keys [^BigInteger curve-order
           ^BigInteger private-key
           ^bytes data
           ^org.bouncycastle.crypto.Digest hash-digest
           ^bytes extra-entropy]}]
  (let [calculator (doto
                     (RFC6979. hash-digest)
                     (.init
                       curve-order
                       private-key
                       data
                       (or extra-entropy (byte-array []))))]
    (repeatedly #(.nextK calculator))))

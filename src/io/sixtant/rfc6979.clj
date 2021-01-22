(ns io.sixtant.rfc6979
  (:import (org.bouncycastle.crypto.digests SHA256Digest)
           (io.sixtant RFC6979)
           (org.bouncycastle.crypto.signers ECDSASigner DSAKCalculator)
           (org.bouncycastle.crypto.params ECPrivateKeyParameters ECDomainParameters)))


(defn sha-256-digest
  "A SHA256 digest suitable for the :hash-digest parameter of `generate-ks`."
  []
  (SHA256Digest.))


(defn ^bytes hash-with-digest
  "Helper to hash bytes -> bytes with some digest."
  [digest ^bytes msg-bytes]
  (let [m (byte-array (.getDigestSize digest))]
    (.update digest msg-bytes 0 (count msg-bytes))
    (.doFinal digest m 0)
    m))


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
  (assert (and curve-order private-key data hash-digest))
  (let [calculator (doto
                     (RFC6979. hash-digest)
                     (.init
                       curve-order
                       private-key
                       data
                       (or extra-entropy (byte-array []))))]
    (repeatedly #(.nextK calculator))))


(defn dsak-calculator
  "Create a `org.bouncycastle.crypto.signers.DSAKCalculator` which returns the
  given `k` values in order.

  Useful to supply custom `k` values to Bouncy Castle's DSA/ECDSA algorithms."
  [k-seq]
  (let [k-seq (atom k-seq)]
    (reify DSAKCalculator
      (isDeterministic [_] true)
      (init [_ _ _] nil)
      (init [_ _ _ _] nil)
      (nextK [_] (let [[old _] (swap-vals! k-seq rest)] (first old))))))


(defn ec-sign-deterministic
  ""
  [{:keys [^bytes data
           ^BigInteger private-key
           curve
           hash-digest
           extra-entropy]
    :as x}]
  (let [deterministic-ks (-> x
                             (assoc :curve-order (.getN curve))
                             (generate-ks))
        signer (ECDSASigner. (dsak-calculator deterministic-ks))
        ecd-params (ECDomainParameters.
                     (.getCurve curve) (.getG curve) (.getN curve))
        pk-params (ECPrivateKeyParameters. private-key ecd-params)]
    (.init signer true pk-params)
    (into [] (.generateSignature signer data))))

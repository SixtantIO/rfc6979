(ns io.sixtant.rfc6979
  (:import (org.bouncycastle.crypto.digests SHA256Digest SHA384Digest SHA512Digest)
           (io.sixtant RFC6979)
           (org.bouncycastle.crypto.signers ECDSASigner DSAKCalculator)
           (org.bouncycastle.crypto.params ECPrivateKeyParameters ECDomainParameters ECPublicKeyParameters)
           (org.bouncycastle.math.ec ECPoint)
           (org.bouncycastle.crypto Digest)
           (org.bouncycastle.asn1.x9 X9ECParameters)))


(set! *warn-on-reflection* true)


(defn sha-256-digest
  "A SHA256 digest suitable for the :hash-digest parameter of `generate-ks`."
  []
  (SHA256Digest.))


(defn sha-384-digest
  "A SHA384 digest suitable for the :hash-digest parameter of `generate-ks`."
  []
  (SHA384Digest.))


(defn sha-512-digest
  "A SHA512 digest suitable for the :hash-digest parameter of `generate-ks`."
  []
  (SHA512Digest.))


(defn ^bytes hash-with-digest
  "Helper to hash bytes -> bytes with some digest."
  [^Digest digest ^bytes msg-bytes]
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
    - extra-entropy A k' value as described in section 3.6 of rfc6979."
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


(defn ec-sign
  "Sign the `data` and return the [r s] pair as BigIntegers.

  Required
    - data        The final, hashed bytes to sign.
    - private-key Private key as a BigInteger.
    - hash-digest An instance of org.bouncycastle.crypto.Digest specifying the
                  hash function to use (see `sha-256-digest` in this ns).
    - curve       The Bouncy Castle representation of the elliptic curve, e.g.
                  (org.bouncycastle.asn1.nist.NISTNamedCurves/getByName \"P-192\")

  Optional
    - extra-entropy A k' value as described in section 3.6 of rfc6979."
  [{:keys [^bytes data
           ^BigInteger private-key
           hash-digest
           ^X9ECParameters curve
           ^bytes extra-entropy]
    :as x}]
  (assert (and data private-key hash-digest curve))
  (let [deterministic-ks (-> x
                             (assoc :curve-order (.getN curve))
                             (generate-ks))
        signer (ECDSASigner. (dsak-calculator deterministic-ks))
        ecd-params (ECDomainParameters.
                     (.getCurve curve) (.getG curve) (.getN curve))
        pk-params (ECPrivateKeyParameters. private-key ecd-params)]
    (.init signer true pk-params)
    (into [] (.generateSignature signer data))))


(defn- ^ECPoint ->public-key
  "Use the BigInteger private key to find the public EC point on the curve
  (public key)."
  [{:keys [^BigInteger private-key ^X9ECParameters curve]}]
  (.multiply (.getG curve) private-key))


(defn ^ECPoint public-key
  "Convert the affine coordinates to a public key on the given `curve`."
  [^X9ECParameters curve x y]
  (.createPoint (.getCurve curve) (biginteger x) (biginteger y)))


(defn ec-verify
  "Verify the signature (`r` and `s` values) against the unsigned `data` bytes
  and the `public-key` on the given `curve`, returning a boolean.

  Provide either a `public-key` in Bouncy Castle's ECPoint format, or a
  BigInteger private key. See the `public-key` function for building an
  ECPoint from affine public key coordinates."
  [{:keys [^bytes data
           ^ECPoint public-key
           ^BigInteger private-key
           ^X9ECParameters curve]
    :as   x}
   ^BigInteger r ^BigInteger s]
  (assert (and data curve))
  (assert (or public-key private-key))
  (let [signer (ECDSASigner.)
        ecd-params (ECDomainParameters.
                     (.getCurve curve) (.getG curve) (.getN curve))
        pub (or public-key (->public-key x))]
    (.init signer false (ECPublicKeyParameters. pub ecd-params))
    (.verifySignature signer data (biginteger r) (biginteger s))))

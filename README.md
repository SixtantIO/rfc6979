# RFC 6979
## Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)


[RFC 6979's](https://tools.ietf.org/html/rfc6979) deterministic DSA/ECDSA 
signature scheme in Clojure — with support for a `k'` parameter as a source of 
extra entropy as described under ["Variants" (section 3.6)](https://tools.ietf.org/html/rfc6979#section-3.6).

Available as:
```
[io.sixtant/rfc6979 "0.1.0"]
```

## Usage

### Generating Deterministic K Values

To generate `k` values as described in [rfc6979 3.2](https://tools.ietf.org/html/rfc6979#section-3.2):
```clojure
(require '[io.sixtant.rfc6979 :as sig])

;; E.g. generate k values to sign the message SHA256("sample")
(def message-bytes
  (sig/hash-with-digest (sig/sha-256-digest) (.getBytes "sample")))

;; rfc6979 describes an algorithm for selecting a series of k values, since
;; different signature algorithms might have requirements which cause them to
;; reject certain k values until one is satisfactory.

;; So this generates an infinite series of k values.
(def k-values
  (sig/generate-ks
    {:curve-order (biginteger 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831)
     :private-key (biginteger 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4)
     :data        message-bytes
     :hash-digest (sig/sha-256-digest)}))

(first k-values)
;=> 1243018074331921709198038856699476057063451281636813313174

;; The hex encoded k-value, which matches the test vector at:
;; https://tools.ietf.org/html/rfc6979#appendix-A.2.3
(.toString (biginteger (first k-values)) 16)
;=> "32b1b6d7d42a05cb449065727a84804fb1a3e34d8f261496"
```

To generate `k` values with `k'` (extra entropy) under [the section 3.6 variant](https://tools.ietf.org/html/rfc6979#section-3.6),
just add a `:extra-entropy` parameter:
```clojure 
(sig/generate-ks
  {:curve-order   (biginteger 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831)
   :private-key   (biginteger 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4)
   :data          (.getBytes "hashed-message")
   :extra-entropy (.getBytes "seed")
   :hash-digest   (sig/sha-256-digest)})
```

### ECDSA

Deterministic elliptic curve signatures:

```clojure
(require '[io.sixtant.rfc6979 :as sig])

;; To compare against the test vector, we'll use the NIST P-192 curve
;; https://tools.ietf.org/html/rfc6979#appendix-A.2.3
(import '(org.bouncycastle.asn1.nist NISTNamedCurves))

;; Returns signature is the `r` and `s` pair of BigIntegers
(sig/ec-sign
  {:data          (sig/hash-with-digest
                    (sig/sha-256-digest)
                    (.getBytes "sample"))
   :private-key   (biginteger 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4)
   :hash-digest   (sig/sha-256-digest)
   :curve         (NISTNamedCurves/getByName "P-192")})
;=> [1840100961263083710623367090499191253309337908038449679189 5023041631781708045212851554060961543112660311254607862661]

;; Again, to add k' entropy, use the :extra-entropy key
(sig/ec-sign
  {:data          (sig/hash-with-digest
                    (sig/sha-256-digest)
                    (.getBytes "sample"))
   :private-key   (biginteger 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4)
   :extra-entropy (.getBytes "seed")
   :hash-digest   (sig/sha-256-digest)
   :curve         (NISTNamedCurves/getByName "P-192")})
;=> [962550273645777332201477239297978599957983764722740361210 1215809841795932025900241180552496703469250337438771316994]

;; There are no test vectors for the section 3.6 variant in rfc6979, but the
;; result can be compared against python-ecdsa:
;;
;; >>> from ecdsa import SigningKey
;; >>> from ecdsa.curves import NIST192p
;; >>> import hashlib
;; >>> exp = int('0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4', 16)
;; >>> k = SigningKey.from_secret_exponent(exp, hashfunc=hashlib.sha256, curve=NIST192p)
;; >>> k.sign_deterministic(b"sample", extra_entropy=b"seed", sigencode=lambda r, s, o: [r, s])

;; Alternatively, using secp256k1 (Bitcoin's elliptic curve):
(import '(org.bouncycastle.asn1.sec SECNamedCurves))

(sig/ec-sign
  {:data          (sig/hash-with-digest
                    (sig/sha-256-digest)
                    (.getbytes "sample"))
   :private-key   (biginteger 0x6fab034934e4c0fc9ae67f5b5659a9d7d1fefd187ee09fd4)
   :extra-entropy (.getbytes "seed")
   :hash-digest   (sig/sha-256-digest)
   :curve         (secnamedcurves/getbyname "secp256k1")})
;=> [69074179111879087176937429694430936543403435253273751714142900628115392158333 19728962829314034319645060574950784725465669219458722957246117220361954573201]
```

Verification:
```clojure
(require '[io.sixtant.rfc6979 :as sig])
(import '(org.bouncycastle.asn1.nist NISTNamedCurves))

;; Verify against private key
(sig/ec-verify
  {:data        (sig/hash-with-digest
                  (sig/sha-256-digest)
                  (.getBytes "sample"))
   :private-key (biginteger 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4)
   :curve       (NISTNamedCurves/getByName "P-192")}
  962550273645777332201477239297978599957983764722740361210
  1215809841795932025900241180552496703469250337438771316994)
;=> true

;; Verify against public key (affine coordinates)
(let [curve (NISTNamedCurves/getByName "P-192")]
  (sig/ec-verify
    {:data       (sig/hash-with-digest
                   (sig/sha-256-digest)
                   (.getBytes "sample"))
     :public-key (public-key
                   curve
                   0xAC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56
                   0x3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43)
     :curve      curve}
    962550273645777332201477239297978599957983764722740361210
    1215809841795932025900241180552496703469250337438771316994))
;=> true
```


### Bouncy Castle

To work with Bouncy Castle at a lower level for custom signature schemes, the
`dsak-calculator` function creates a `org.bouncycastle.crypto.signers.DSAKCalculator`
which returns an arbitrary series of `k` values, which is compatible with BC's 
primitives.

E.g.
```clojure 
(require '[io.sixtant.rfc6979 :as sig])
(import '(org.bouncycastle.crypto.signers ECDSASigner))

(let [custom-signer (ECDSASigner. (sig/dsak-calculator (sig/generate-ks {...})))]
  ...)
```

## Rationale 

Bouncy Castle exposes a [`HMACDSAKCalculator`](https://github.com/bcgit/bc-java/blob/bc3b92f1f0e78b82e2584c5fb4b226a13e7f8b3b/core/src/main/java/org/bouncycastle/crypto/signers/HMacDSAKCalculator.java#L15)
class for deterministic generation of `k` as described by RFC 6979, but without
support for the `k'` (k prime) parameter described in section 3.6.

The [`python-ecdsa`](https://github.com/ecdsa/python-ecdsa) library exposes a 
nice, functional approach to ECDSA, including an easily accessible function for
deterministic generation of k, with support for `k'`. 

This library replicates that functionality for Clojure, such that the same `k`
values are generated in both languages. The resulting `k` can then be used with
this library's `sign` function, with Bouncy Castle's ECDSAs, or with a custom 
deterministic signature algorithm.

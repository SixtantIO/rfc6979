/* Copyright (c) 2000 - 2021 The Legion of the Bouncy Castle Inc.
   (https://www.bouncycastle.org)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.


   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
 */


package io.sixtant;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A deterministic K calculator based on the algorithm in section 3.2 of RFC
 * 6979, **modified from BouncyCastle's implementation** to include an optional
 * k' parameter as described in section 3.6.
 */
public class RFC6979 implements DSAKCalculator {
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private final HMac hMac;
    private final byte[] K;
    private final byte[] V;

    private BigInteger n;

    /**
     * Base constructor.
     *
     * @param digest digest to build the HMAC on.
     */
    public RFC6979(Digest digest)
    {
        this.hMac = new HMac(digest);
        this.V = new byte[hMac.getMacSize()];
        this.K = new byte[hMac.getMacSize()];
    }

    public boolean isDeterministic()
    {
        return true;
    }

    public void init(BigInteger n, SecureRandom random)
    {
        throw new IllegalStateException("Operation not supported");
    }

    public void init(BigInteger n, BigInteger d, byte[] message) {
        init(n, d, message, null);
    }

    public void init(BigInteger n, BigInteger d, byte[] message, byte[] kPrime)
    {
        this.n = n;

        Arrays.fill(V, (byte)0x01);
        Arrays.fill(K, (byte)0);

        byte[] x = new byte[(n.bitLength() + 7) / 8];
        byte[] dVal = BigIntegers.asUnsignedByteArray(d);

        System.arraycopy(dVal, 0, x, x.length - dVal.length, dVal.length);

        byte[] m = new byte[(n.bitLength() + 7) / 8];

        BigInteger mInt = bitsToInt(message);

        if (mInt.compareTo(n) >= 0)
        {
            mInt = mInt.subtract(n);
        }

        byte[] mVal = BigIntegers.asUnsignedByteArray(mInt);

        System.arraycopy(mVal, 0, m, m.length - mVal.length, mVal.length);

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);
        hMac.update((byte)0x00);
        hMac.update(x, 0, x.length);
        hMac.update(m, 0, m.length);

        // Extra entropy as defined in section 3.6
        if (kPrime != null) {
            hMac.update(kPrime, 0, kPrime.length);
        }

        hMac.doFinal(K, 0);

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);

        hMac.doFinal(V, 0);

        hMac.update(V, 0, V.length);
        hMac.update((byte)0x01);
        hMac.update(x, 0, x.length);
        hMac.update(m, 0, m.length);

        // Extra entropy as defined in section 3.6
        if (kPrime != null) {
            hMac.update(kPrime, 0, kPrime.length);
        }

        hMac.doFinal(K, 0);

        hMac.init(new KeyParameter(K));

        hMac.update(V, 0, V.length);

        hMac.doFinal(V, 0);
    }

    public BigInteger nextK()
    {
        byte[] t = new byte[((n.bitLength() + 7) / 8)];

        for (;;)
        {
            int tOff = 0;

            while (tOff < t.length)
            {
                hMac.update(V, 0, V.length);

                hMac.doFinal(V, 0);

                int len = Math.min(t.length - tOff, V.length);
                System.arraycopy(V, 0, t, tOff, len);
                tOff += len;
            }

            BigInteger k = bitsToInt(t);

            if (k.compareTo(ZERO) > 0 && k.compareTo(n) < 0)
            {
                return k;
            }

            hMac.update(V, 0, V.length);
            hMac.update((byte)0x00);

            hMac.doFinal(K, 0);

            hMac.init(new KeyParameter(K));

            hMac.update(V, 0, V.length);

            hMac.doFinal(V, 0);
        }
    }

    private BigInteger bitsToInt(byte[] t)
    {
        BigInteger v = new BigInteger(1, t);

        if (t.length * 8 > n.bitLength())
        {
            v = v.shiftRight(t.length * 8 - n.bitLength());
        }

        return v;
    }
}

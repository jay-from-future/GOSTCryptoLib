
package com.crypto.hash.stribog;

import com.crypto.hash.stribog.exceptions.InvalidVectorLenException;

import java.security.MessageDigestSpi;

abstract class StribogAlg extends MessageDigestSpi {

    protected int[] E(int[] K, int[] m) {
        if (K.length != 64) {
            throw new InvalidVectorLenException("K.length != 64");
        }
        int[] result = xor(K, m);
        int[] Ki = new int[64];
        System.arraycopy(K, 0, Ki, 0, 64);
        for (int i = 0; i < 12; i++) {
            result = LPS(result);
            Ki = ks(Ki, i);
            result = xor(result, Ki);
        }
        return result;
    }

    protected int[] L(int[] state) {
        if (state.length != 64) {
            throw new InvalidVectorLenException("state.length != 64");
        }
        int[] result = new int[64];
        for (int i = 0; i < 8; i++) {
            int[] v = new int[8];
            for (int k = 0; k < 8; k++) {
                for (int j = 0; j < 8; j++) {
                    if ((state[i * 8 + k] & (1 << (7 - j))) != 0) {
                        v = xor(v, Data.A[k * 8 + j]);
                    }
                }
            }
            System.arraycopy(v, 0, result, i * 8, 8);
        }
        return result;
    }

    protected int[] LPS(int[] state) {
        return L(P(S(state)));
    }

    protected int[] P(int[] state) {
        if (state.length != 64) {
            throw new InvalidVectorLenException("state.length != 64");
        }
        int[] result = new int[64];
        for (int i = 0; i < 64; i++) {
            result[i] = state[Data.Tau[i]];
        }
        return result;
    }

    protected int[] S(int[] state) {
        if (state.length != 64) {
            throw new InvalidVectorLenException("state.length != 64");
        }
        int[] result = new int[64];
        for (int i = 0; i < 64; i++) {
            result[i] = Data.SBox[state[i]];
        }
        return result;
    }

    protected int[] add(int[] a, int[] b) {
        if (a.length != b.length) {
            throw new InvalidVectorLenException("a.length == " + a.length + " and b.length == " + b.length + " but should be the same.");
        }
        int[] result = new int[a.length];
        int r = 0;
        for (int i = a.length - 1; i >= 0; i--) {
            result[i] = (a[i] + b[i] + r) & 255;
            r = ((a[i] + b[i]) >> 8) & 255;
        }
        return result;
    }

    protected final int[] gN(int[] Nn, int[] h, int[] m) {
        int[] K = LPS(xor(h, Nn));
        int[] e = E(K, m);
        return xor(e, xor(h, m));
    }

    protected int[] ks(int[] k, int i) {
        return LPS(xor(k, Data.C[i]));
    }

    protected int[] xor(int[] a, int[] b) {
        if (a.length != b.length) {
            throw new InvalidVectorLenException("a.length == " + a.length + " and b.length == " + b.length + " but should be the same.");
        }
        int[] result = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

}

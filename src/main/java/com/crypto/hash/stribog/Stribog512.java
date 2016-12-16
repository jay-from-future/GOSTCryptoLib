package com.crypto.hash.stribog;

/**
 * Created by Admin on 08.09.2015.
 */
public final class Stribog512 extends Stribog{
    private static final int[] IV = new int[64];

    @Override
    protected byte[] engineDigest() {
        return getDigest(IV);
    }

}

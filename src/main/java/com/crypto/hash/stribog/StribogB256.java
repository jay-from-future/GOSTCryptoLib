package com.crypto.hash.stribog;


public class StribogB256 extends StribogB{
    
    public static final int[] IV = new int[64];
    
    static {
        for (int i = 0; i < IV.length; i++) {
            IV[i] = 0x01;
        }
    }

    public StribogB256() {
        super(IV);
    }
    
    @Override
    protected byte[] engineDigest() {
        byte[] result = new byte[32];
        System.arraycopy(super.engineDigest(), 0, result, 0, result.length);
        return result;
    }
    
}

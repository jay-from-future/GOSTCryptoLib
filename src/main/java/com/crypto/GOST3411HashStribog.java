package com.crypto;


import com.crypto.hash.stribog.StribogProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static com.crypto.HexUtils.toHexString;


public class GOST3411HashStribog {

    static {
        if (Security.getProvider("JStribog") == null) {
            Security.addProvider(new StribogProvider());
        }
    }

    public static byte[] stribog256Digest(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("Stribog256");
        byte[] digest = new byte[0];
        if (md != null) {
            digest = md.digest(message);
        }
        return digest;
    }

    public static byte[] stribog256BigDigest(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("StribogB256");
        byte[] digest = null;
        if (md != null) {
            digest = md.digest(reverse(message));
        }
        return digest;
    }

    public static byte[] stribog512Digest(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("Stribog512");
        byte[] digest = new byte[0];
        if (md != null) {
            digest = md.digest(message);
        }
        return digest;
    }

    public static byte[] stribog512BigDigest(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("StribogB512");
        byte[] digest = new byte[0];
        if (md != null) {
            digest = md.digest(reverse(message));
        }
        return digest;
    }

    private static byte[] reverse(byte[] ba) {
        byte[] result = new byte[ba.length];
        for (int i = ba.length - 1; i >= 0; i--) {
            result[ba.length - 1 - i] = ba[i];
        }
        return result;
    }
}

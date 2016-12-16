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

    public static byte[] stribog256Digest(byte[] message) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("Stribog256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] digest = new byte[0];
        if (md != null) {
            digest = md.digest(message);
        }
        return digest;
    }

//    public static String stribog256Digest(String message) {
//        return stribog256Digest(message.getBytes());
//    }
//
//    public static String stribog256BigDigest(String message) {
//        return stribog256Digest(message.getBytes());
//    }

    public static byte[] stribog256BigDigest(byte[] message) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("StribogB256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] digest = null;
        if (md != null) {
            digest = md.digest(reverse(message));
        }
        return digest;
    }

    public static byte[] stribog512Digest(byte[] message) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("Stribog512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] digest = new byte[0];
        if (md != null) {
            digest = md.digest(message);
        }
        return digest;
    }

    public static byte[] stribog512BigDigest(byte[] message) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("StribogB512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] digest = new byte[0];
        if (md != null) {
            digest = md.digest(reverse(message));
        }
        return digest;
    }


    private static String getHex(byte[] digest) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : digest) {
            int iv = (int) b & 0xFF;
            if (iv < 0x10) {
                stringBuilder.append('0');
            }
            stringBuilder.append(Integer.toHexString(iv).toUpperCase());
        }
        return stringBuilder.toString();
    }

    private static byte[] reverse(byte[] ba) {
        byte[] result = new byte[ba.length];
        for (int i = ba.length - 1; i >= 0; i--) {
            result[ba.length - 1 - i] = ba[i];
        }
        return result;
    }

    public static String generateHash256ForFile(File file) throws IOException {
        byte[] msg = new byte[(int) file.length()];
        FileInputStream fileInputStream = new FileInputStream(file);
        int readResult = fileInputStream.read(msg);
        if (readResult < 0) {
            String errorMsg = "Cannot read from input file : " + file.getAbsolutePath();
            throw new IOException(errorMsg);
        }
        byte[] hash = GOST3411HashStribog.stribog256BigDigest(msg);
        return toHexString(hash);
    }
}

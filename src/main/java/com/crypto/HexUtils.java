package com.crypto;

public final class HexUtils {

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private static final byte[] TABLE;

    static {
        TABLE = new byte['f' + 1];
        for (int i = 0; i <= 'f'; i++) {
            TABLE[i] = -1;
        }
        for (int i = '0'; i <= '9'; i++) {
            TABLE[i] = (byte) (i - '0');
        }
        for (int i = 'a'; i <= 'f'; i++) {
            TABLE[i] = (byte) (10 + i - 'a');
        }
        for (int i = 'A'; i <= 'F'; i++) {
            TABLE[i] = (byte) (10 + i - 'A');
        }
    }

    public static String from(byte... b) {
        char[] result = new char[b.length * 2];
        int j = 0;
        for (byte s : b) {
            result[j++] = HEX_CHARS[(s & 0xf0) >>> 4];
            result[j++] = HEX_CHARS[s & 0x0f];
        }
        return new String(result);
    }

    public static byte[] toByteArray(String hexString) {
        int length = hexString.length();
        if ((length & 0x1) != 0) {
            throw new IllegalArgumentException("fromHexString requires an even number of hex characters, [length = "
                    + length + ", hexstring = '" + hexString + "']");
        }
        byte[] result = new byte[length >> 1];
        for (int i = 0; i < length;) {
            result[i >> 1] = toByte(hexString.charAt(i++), hexString.charAt(i++));
        }
        return result;
    }

    private static byte toByte(char c1, char c2) {
        return (byte) ((value(c1) << 4) | value(c2));
    }

    private static int value(char c) {
        if (c > 'f') {
            throw new IllegalArgumentException("Invalid hex character, character = '" + c + "'");
        }
        byte result = TABLE[c];
        if (result < 0) {
            throw new IllegalArgumentException("Invalid hex character, character = '" + c + "'");
        }
        return result;
    }

    public static String toHexString(byte[] digest) {
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
}

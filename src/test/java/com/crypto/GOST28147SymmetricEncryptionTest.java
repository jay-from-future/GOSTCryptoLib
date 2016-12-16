package com.crypto;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class GOST28147SymmetricEncryptionTest {

    private static final byte[] KEY = {49, 51, 115, 56, 51, 98, 48, 104, 53, 113, 97, 100, 56, 117, 104, 114, 100, 51, 56, 97, 103, 56, 111, 109, 106, 114, 49, 99, 50, 99, 110, 109};
    private static final byte[] SOURCE_MSG = {116, 101, 115, 116, 32, 109, 101, 115, 115, 97, 103, 101, 32, 116, 101, 115, 116, 32, 109, 101, 115, 115, 97, 103, 101, 32, 116, 101, 115, 116, 32, 109, 101, 115, 115, 97, 103, 101, 32, 116, 101, 115, 116, 32, 109, 101, 115, 115, 97, 103, 101, 32, 116, 101, 115, 116, 32, 109, 101, 115, 115, 97, 103, 101};
    private static final byte[] ENCRYPTED_MSG = {0, 117, 63, -64, 120, 54, -32, -29, -116, -3, 56, -103, -60, -7, -124, 5, 114, 8, 63, 28, -81, -90, 114, 52, -116, 21, 125, -76, 69, -112, -85, -57, 85, -81, 26, 127, 114, -24, 73, 119, 59, 55, 12, -116, 14, 63, -97, 34, -16, 124, 59, 115, -63, 110, -55, 90, 10, -4, 84, -123, 11, 38, -116, -12};
    private static final String DEFAULT_S_BOX = "DEFAULT";

    private GOST28147SymmetricEncryption gost28147SymmetricEncryption;

    @Before
    public void setUp() throws Exception {
        gost28147SymmetricEncryption = new GOST28147SymmetricEncryption();
        gost28147SymmetricEncryption.init(DEFAULT_S_BOX, KEY);
    }

    @Test
    public void testEncryptMessage() throws Exception {
        byte[] out = new byte[SOURCE_MSG.length];
        gost28147SymmetricEncryption.encryptMessage(SOURCE_MSG, out);
        assertTrue(Arrays.equals(ENCRYPTED_MSG, out));
    }

    @Test
    public void testDecryptMessage() throws Exception {
        byte[] out = new byte[ENCRYPTED_MSG.length];
        gost28147SymmetricEncryption.decryptMessage(ENCRYPTED_MSG, out);
        assertTrue(Arrays.equals(SOURCE_MSG, out));
    }
}
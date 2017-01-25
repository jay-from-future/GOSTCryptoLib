package com.crypto;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;

public class GOST3410DigitalSignatureTest {

    private static final String SIGNATURE_IS_NULL = "Signature is NULL";
    private static final String SIGNATURE_IS_NOT_VALID = "Signature is not valid";
    private byte[] msg = "test message".getBytes();
    private File testFile;
    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        keyPair = GOST3410DigitalSignature.generateKeyPair();
        initTestFile();
    }

    private void initTestFile() throws IOException {
        testFile = File.createTempFile("testFile", ".txt");
        testFile.deleteOnExit();

        FileOutputStream outputStream = new FileOutputStream(testFile);
        outputStream.write(msg);
        outputStream.flush();
        outputStream.close();
    }

    @Test
    public void testGenerateAndSignatureForFile() throws Exception {
        byte[] signature = GOST3410DigitalSignature.generateSignatureForFile(testFile, keyPair.getPrivate());
        Assert.assertNotNull(SIGNATURE_IS_NULL, signature);

        boolean verification = GOST3410DigitalSignature.verifySignatureForFile(testFile, signature, keyPair.getPublic());
        Assert.assertTrue(SIGNATURE_IS_NOT_VALID, verification);
    }

    @Test
    public void testGenerateAndVerifySignature() throws Exception {

        byte[] signature = GOST3410DigitalSignature.generateSignature(msg, keyPair.getPrivate());
        Assert.assertNotNull(SIGNATURE_IS_NULL, signature);

        boolean verification = GOST3410DigitalSignature.verifySignature(msg, signature, keyPair.getPublic());
        Assert.assertTrue(SIGNATURE_IS_NOT_VALID, verification);
    }
}
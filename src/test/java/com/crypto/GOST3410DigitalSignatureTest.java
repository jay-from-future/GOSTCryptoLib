package com.crypto;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class GOST3410DigitalSignatureTest {

    private static final String SIGNATURE_IS_NULL = "Signature is NULL";
    private static final String SIGNATURE_IS_NOT_VALID = "Signature is not valid";
    private byte[] msg = "test message".getBytes();
    private File testFile;
    private GOST3410DigitalSignature edsGOSTUtil;

    @Before
    public void setUp() throws Exception {
        edsGOSTUtil = new GOST3410DigitalSignature();
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
        BigInteger privateKey = edsGOSTUtil.generatePrivateKey();
        ECPoint publicKey = edsGOSTUtil.generatePublicKey(privateKey);

        String signature = edsGOSTUtil.generateSignatureForFile(testFile, privateKey);
        Assert.assertNotNull(SIGNATURE_IS_NULL, signature);

        boolean verification = edsGOSTUtil.verifySignatureForFile(testFile, signature, publicKey);
        Assert.assertTrue(SIGNATURE_IS_NOT_VALID, verification);
    }

    @Test
    public void testGenerateAndVerifySignature() throws Exception {
        BigInteger privateKey = edsGOSTUtil.generatePrivateKey();
        ECPoint publicKey = edsGOSTUtil.generatePublicKey(privateKey);

        String signature = edsGOSTUtil.generateSignature(msg, privateKey);
        Assert.assertNotNull(SIGNATURE_IS_NULL, signature);

        boolean verification = edsGOSTUtil.verifySignature(msg, signature, publicKey);
        Assert.assertTrue(SIGNATURE_IS_NOT_VALID, verification);
    }
}
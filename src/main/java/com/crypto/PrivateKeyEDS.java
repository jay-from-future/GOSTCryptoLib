package com.crypto;

import java.math.BigInteger;
import java.security.PrivateKey;

/**
 * @author Grigorii Liullin.
 */
public class PrivateKeyEDS implements PrivateKey {

    private BigInteger privateKey;

    public PrivateKeyEDS(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return privateKey.toByteArray();
    }
}

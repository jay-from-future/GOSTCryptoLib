package com.crypto;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.security.PublicKey;

/**
 * @author Grigorii Liullin.
 */
public class PublicKeyEDS implements PublicKey, ECPublicKey {
    private ECPoint publicKey;

    public PublicKeyEDS(ECPoint publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public ECPoint getQ() {
        return publicKey;
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
        return new byte[0];
    }

    @Override
    public ECParameterSpec getParameters() {
        return null;
    }
}

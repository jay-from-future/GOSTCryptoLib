package com.crypto;

import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * @author Grigorii Liullin.
 */
public class PBKDF2WithStribog {

    public static final int ITERATIONS = 5000;
    public static final int KEY_LENGTH = 256;

    /**
     * @param password
     * @param salt
     * @param iterations
     * @param keyLength
     * @return
     */
    public static byte[] hashPassword(final String password, final String salt, final int iterations,
                                      final int keyLength) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new GOST3411Digest());
        gen.init(password.getBytes(), salt.getBytes(), iterations);
        return ((KeyParameter) gen.generateDerivedParameters(keyLength)).getKey();
    }
}

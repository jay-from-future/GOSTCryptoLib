package com.crypto;

import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Class for generation hash that will be used as a key in symmetric encryption by PBKDF2 standard.
 *
 * @author Grigorii Liullin.
 */
public class PBKDF2WithStribog {

    public static final int PBKDF2_ITERATIONS = 5000;

    public static final int KEY_LENGTH = 256;

    /**
     * Generates hash by PBKDF2 standard. GOST3411 Stribog uses as a hash function.
     *
     * @param password   user password
     * @param salt       user PIN code
     * @param iterations count of XOR iterations (for more labor-intensive computations agains brut-force attacks)
     * @param keyLength  length of the resulting hash
     * @return generated hash that may be used as a key in symmetric encryption
     */
    public static byte[] hashPassword(final String password, final String salt, final int iterations,
                                      final int keyLength) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new GOST3411Digest());
        gen.init(password.getBytes(), salt.getBytes(), iterations);
        return ((KeyParameter) gen.generateDerivedParameters(keyLength)).getKey();
    }
}

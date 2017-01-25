package com.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static com.crypto.HexUtils.toHexString;

/**
 * @author Grigorii Liullin.
 */
public final class FileUtils {

    private FileUtils() {

    }

    public static String generateHash256ForFile(File file) throws IOException, NoSuchAlgorithmException {
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

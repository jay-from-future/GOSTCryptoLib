package com.crypto;

import org.junit.Test;

import static com.crypto.HexUtils.toByteArray;
import static com.crypto.HexUtils.toHexString;
import static org.junit.Assert.assertEquals;

public class GOST3411HashStribogTest {

    private static final String MSG = "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130";
    private static final String STRIBOG_256_DIGEST = "00557BE5E584FD52A449B16B0251D05D27F94AB76CBAA6DA890B59D8EF1E159D";
    private static final String STRIBOG_512_DIGEST = "486F64C1917879417FEF082B3381A4E211C324F074654C38823A7B76F830AD00FA1FBAE42B1285C0352F227524BC9AB16254288DD6863DCCD5B9F54A1AD0541B";

    @Test
    public void stribog256Digest() throws Exception {
        byte[] actualStribog256Digest = GOST3411HashStribog.stribog256Digest(toByteArray(MSG));
        assertEquals(STRIBOG_256_DIGEST, toHexString(actualStribog256Digest));
    }

    @Test
    public void stribog256BigDigest() throws Exception {
        byte[] actualStribog256BigDigest = GOST3411HashStribog.stribog256BigDigest(toByteArray(MSG));
        assertEquals(STRIBOG_256_DIGEST, toHexString(actualStribog256BigDigest));

    }

    @Test
    public void stribog512Digest() throws Exception {
        byte[] actualStribog512Digest = GOST3411HashStribog.stribog512Digest(toByteArray(MSG));
        assertEquals(STRIBOG_512_DIGEST, toHexString(actualStribog512Digest));
    }

    @Test
    public void stribog512BigDigest() throws Exception {
        byte[] actualStribog512BigDigest = GOST3411HashStribog.stribog512BigDigest(toByteArray(MSG));
        assertEquals(STRIBOG_512_DIGEST, toHexString(actualStribog512BigDigest));
    }
}
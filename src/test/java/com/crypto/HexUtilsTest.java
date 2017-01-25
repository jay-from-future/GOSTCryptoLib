package com.crypto;

import org.junit.Test;

public class HexUtilsTest {

    @Test(expected = IllegalArgumentException.class)
    public void toByteArrayWithNotEvenNumberOfHexCharacters() throws Exception {
        String notEvenNumberOfHexCharacters ="111";
        HexUtils.toByteArray(notEvenNumberOfHexCharacters);
    }

    @Test(expected = IllegalArgumentException.class)
    public void toByteArrayWithInvalidHexCharacter() throws Exception {
        String invalidHexCharacter ="gg";
        HexUtils.toByteArray(invalidHexCharacter);
    }

    @Test(expected = IllegalArgumentException.class)
    public void toByteArrayWithInvalidHexCharacter1() throws Exception {
        String invalidHexCharacter ="-1";
        HexUtils.toByteArray(invalidHexCharacter);
    }
}
package com.crypto;

import org.junit.Test;

import static com.crypto.PBKDF2WithStribog.*;
import static org.junit.Assert.*;

public class PBKDF2WithStribogTest {

    @Test
    public void hashPasswordTest() throws Exception {
        String expectedHashPassword = "80BF1D99B69F91F2E0ABF88FDE01C4AE018AC2BB2608624F9FE22C1DBF037D38";
        byte[] actualHashPassword = hashPassword("PASSWORD", "SALT", PBKDF2_ITERATIONS, KEY_LENGTH);
        assertTrue(actualHashPassword.length == (KEY_LENGTH / 8));
        assertEquals(HexUtils.toHexString(actualHashPassword), expectedHashPassword);
    }

    @Test
    public void hashForTwoDifferentPasswordsTest() throws Exception {
        String password1 = "PASSWORD1";
        String password2 = "PASSWORD2";

        byte[] actualHashPassword1 = hashPassword(password1, "SALT", PBKDF2_ITERATIONS, KEY_LENGTH);
        byte[] actualHashPassword2 = hashPassword(password2, "SALT", PBKDF2_ITERATIONS, KEY_LENGTH);

        assertNotEquals(actualHashPassword1, actualHashPassword2);
    }
}
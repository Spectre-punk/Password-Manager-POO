package crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class Argon2KDFTest {

    private static void wipe(byte[] value) {
        Arrays.fill(value, (byte) 0);
    }

    private static void wipe(char[] value) {
        Arrays.fill(value, '\0');
    }

    @Test
    void generatesRandom16ByteSalts() {
        byte[] first = Argon2KDF.generateSalt();
        byte[] second = Argon2KDF.generateSalt();
        try {
            assertEquals(Argon2KDF.SALT_LENGTH_BYTES, first.length);
            assertEquals(16, first.length);
            assertFalse(Arrays.equals(first, second), "salts must be random");
        } finally {
            wipe(first);
            wipe(second);
        }
    }

    @Test
    void derivesDeterministic32ByteKey() {
        byte[] salt = Argon2KDF.generateSalt();
        char[] password = "correct horse battery staple".toCharArray();
        byte[] first = Argon2KDF.deriveKey(password, salt);
        byte[] second = Argon2KDF.deriveKey(password, salt);
        try {
            assertEquals(32, first.length);
            assertArrayEquals(first, second, "same password + salt must derive the same key");
        } finally {
            wipe(password);
            wipe(salt);
            wipe(first);
            wipe(second);
        }
    }

    @Test
    void differentSaltsDeriveDifferentKeys() {
        byte[] saltA = Argon2KDF.generateSalt();
        byte[] saltB = Argon2KDF.generateSalt();
        char[] password = "same-password".toCharArray();
        byte[] keyA = Argon2KDF.deriveKey(password, saltA);
        byte[] keyB = Argon2KDF.deriveKey(password, saltB);
        try {
            assertFalse(Arrays.equals(keyA, keyB), "different salts must derive different keys");
        } finally {
            wipe(password);
            wipe(saltA);
            wipe(saltB);
            wipe(keyA);
            wipe(keyB);
        }
    }

    @Test
    void rejectsInvalidInputs() {
        byte[] salt = new byte[Argon2KDF.SALT_LENGTH_BYTES];
        assertThrows(IllegalArgumentException.class,
                () -> Argon2KDF.deriveKey(null, salt));
        assertThrows(IllegalArgumentException.class,
                () -> Argon2KDF.deriveKey(new char[0], salt));
        assertThrows(IllegalArgumentException.class,
                () -> Argon2KDF.deriveKey(new char[] {'a'}, null));
        assertThrows(IllegalArgumentException.class,
                () -> Argon2KDF.deriveKey(new char[] {'a'}, new byte[15]));
    }
}

package util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class GeneradorDeContraseñasTest {

    @Test
    void generatesFifteenCharactersPlusSeparators() {
        char[] password = GeneradorDeContraseñas.generarContraseña();
        try {
            assertEquals(18, password.length);
            assertEquals('-', password[4]);
            assertEquals('-', password[9]);
            assertEquals('-', password[14]);
        } finally {
            SecretWiper.wipe(password);
        }
    }

    @Test
    void generatesDifferentPasswords() {
        char[] first = GeneradorDeContraseñas.generarContraseña();
        char[] second = GeneradorDeContraseñas.generarContraseña();
        try {
            assertFalse(Arrays.equals(first, second));
        } finally {
            SecretWiper.wipe(first);
            SecretWiper.wipe(second);
        }
    }

    @Test
    void multipleGeneratesRequestedCount() {
        List<char[]> passwords = GeneradorDeContraseñas.multiple(3);
        try {
            assertEquals(3, passwords.size());
        } finally {
            passwords.forEach(SecretWiper::wipe);
        }
    }

    @Test
    void rejectsNegativeCount() {
        assertThrows(IllegalArgumentException.class, () -> GeneradorDeContraseñas.multiple(-1));
    }
}

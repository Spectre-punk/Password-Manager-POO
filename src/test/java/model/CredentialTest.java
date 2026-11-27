package model;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class CredentialTest {

    @Test
    void storesAllFields() {
        Credential credential = new Credential(
                "github", "alice", "s3cret".toCharArray(), "work account");

        assertEquals("github", credential.getServicio());
        assertEquals("alice", credential.getNombreUsuario());
        assertEquals("work account", credential.getNotas());
        assertArrayEquals("s3cret".toCharArray(), credential.getContrasena());
    }

    @Test
    void copiesPasswordOnInputAndOutput() {
        char[] original = "s3cret".toCharArray();
        Credential credential = new Credential("s", "u", original, "n");

        Arrays.fill(original, '\0');
        char[] copy = credential.getContrasena();
        copy[0] = 'X';

        assertArrayEquals("s3cret".toCharArray(), credential.getContrasena());
    }

    @Test
    void clearPasswordZeroizesInternalBuffer() throws Exception {
        Credential credential = new Credential("s", "u", "secret".toCharArray(), "n");
        Field field = Credential.class.getDeclaredField("contrasena");
        field.setAccessible(true);
        char[] internal = (char[]) field.get(credential);

        credential.clearPassword();

        assertNull(field.get(credential));
        for (char value : internal) {
            assertEquals('\0', value);
        }
    }

    @Test
    void toStringNeverLeaksPassword() {
        Credential credential = new Credential("s", "u", "super-secret".toCharArray(), "n");

        String text = credential.toString();

        assertFalse(text.contains("super-secret"));
        assertTrue(text.contains("<protected>"));
    }
}

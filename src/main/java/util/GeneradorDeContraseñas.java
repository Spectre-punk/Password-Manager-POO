package util;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Cryptographically secure password generator (migrated from the legacy tree).
 *
 * <p>Returns {@code char[]} instead of {@link String} so callers can wipe the
 * generated secret after use with {@link SecretWiper#wipe(char[])}.</p>
 */
public final class GeneradorDeContraseñas {

    private static final int LENGTH = 15;
    private static final int BLOQUE = 4;

    private static final char[] ALFABETO =
            "ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñopqrstuvwxyz0123456789!@#$%&*()-".toCharArray();

    private static final SecureRandom RANDOM = new SecureRandom();

    private GeneradorDeContraseñas() {
        throw new AssertionError("No instances.");
    }

    /**
     * Generates a 15-character password with a {@code -} separator every four
     * characters, using {@link SecureRandom}.
     *
     * @return a fresh password
     */
    public static char[] generarContraseña() {
        int separators = (LENGTH - 1) / BLOQUE;
        char[] password = new char[LENGTH + separators];

        int index = 0;
        for (int i = 0; i < LENGTH; i++) {
            password[index++] = ALFABETO[RANDOM.nextInt(ALFABETO.length)];
            if ((i + 1) % BLOQUE == 0 && i + 1 < LENGTH) {
                password[index++] = '-';
            }
        }
        return password;
    }

    /**
     * Generates several passwords.
     *
     * @param cantidad number of passwords, must be non-negative
     * @return independent password buffers
     */
    public static List<char[]> multiple(int cantidad) {
        if (cantidad < 0) {
            throw new IllegalArgumentException("cantidad must be non-negative");
        }
        List<char[]> result = new ArrayList<>(cantidad);
        for (int i = 0; i < cantidad; i++) {
            result.add(generarContraseña());
        }
        return result;
    }
}

package crypto;

import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id password-based key derivation (RFC 9106).
 *
 * <p>Derives a 256-bit key from a master password using Argon2id with 64 MiB of
 * memory, 3 iterations and parallelism 1. Passwords are accepted as
 * {@code char[]} and never converted to {@link String}.</p>
 *
 * <p><strong>Caller responsibility:</strong> the supplied password array is not
 * wiped by this class. The caller must wipe it with
 * {@code Arrays.fill(password, '\0')} immediately after the derivation
 * returns.</p>
 */
public final class Argon2KDF {

    /** Required salt length in bytes. */
    public static final int SALT_LENGTH_BYTES = 16;

    /** Derived key length in bytes (256 bits). */
    public static final int KEY_LENGTH_BYTES = 32;

    /** Memory cost: 64 MiB, expressed in KiB as required by Bouncy Castle. */
    public static final int MEMORY_KIB = 64 * 1024;

    /** Time cost: number of iterations. */
    public static final int ITERATIONS = 3;

    /** Degree of parallelism. */
    public static final int PARALLELISM = 1;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Argon2KDF() {
        throw new AssertionError("No instances.");
    }

    /**
     * Generates a cryptographically random 16-byte salt.
     *
     * @return a fresh salt suitable for {@link #deriveKey(char[], byte[])}
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Derives a 256-bit key with Argon2id.
     *
     * @param password master password, never {@code null} or empty
     * @param salt     16-byte random salt
     * @return a new 32-byte key
     * @throws IllegalArgumentException if the password or salt is invalid
     */
    public static byte[] deriveKey(char[] password, byte[] salt) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be null or empty");
        }
        if (salt == null || salt.length != SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "salt must be exactly " + SALT_LENGTH_BYTES + " bytes");
        }

        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_KIB)
                .withParallelism(PARALLELISM)
                .withSalt(salt)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);

        byte[] derivedKey = new byte[KEY_LENGTH_BYTES];
        generator.generateBytes(password, derivedKey);
        return derivedKey;
    }
}

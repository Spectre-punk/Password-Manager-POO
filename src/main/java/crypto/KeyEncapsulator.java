package crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Key encapsulation mechanism (IND1) using RSA-OAEP with SHA-256.
 *
 * <p>A random data-encryption key (DEK) is wrapped under an RSA public key and
 * unwrapped with the matching private key. Both the OAEP digest and the MGF1
 * digest are pinned to SHA-256 so providers cannot silently fall back to
 * SHA-1.</p>
 */
public final class KeyEncapsulator {

    /** RSA modulus size in bits. */
    public static final int RSA_KEY_SIZE_BITS = 3072;

    /** Expected DEK size in bytes (AES-256). */
    public static final int DEK_LENGTH_BYTES = 32;

    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static final OAEPParameterSpec OAEP_SHA256 = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT);

    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyEncapsulator() {
        throw new AssertionError("No instances.");
    }

    /**
     * Generates a 3072-bit RSA key pair for OAEP encapsulation.
     *
     * @return a fresh RSA key pair
     * @throws GeneralSecurityException if key generation fails
     */
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(RSA_KEY_SIZE_BITS, RANDOM);
        return generator.generateKeyPair();
    }

    /**
     * Encapsulates (wraps) a 256-bit DEK under an RSA public key.
     *
     * @param dek       data-encryption key to wrap
     * @param publicKey recipient RSA public key
     * @return the OAEP-wrapped DEK
     * @throws GeneralSecurityException if wrapping fails
     */
    public static byte[] encapsulate(SecretKey dek, PublicKey publicKey) throws GeneralSecurityException {
        Objects.requireNonNull(dek, "dek");
        Objects.requireNonNull(publicKey, "publicKey");
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("publicKey must be an RSA public key");
        }
        if (!"AES".equalsIgnoreCase(dek.getAlgorithm())) {
            throw new IllegalArgumentException("dek must be an AES key");
        }

        byte[] dekBytes = dek.getEncoded();
        if (dekBytes == null || dekBytes.length != DEK_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "dek must be " + (DEK_LENGTH_BYTES * 8) + " bits");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.WRAP_MODE, publicKey, OAEP_SHA256);
            return cipher.wrap(dek);
        } finally {
            Arrays.fill(dekBytes, (byte) 0);
        }
    }

    /**
     * Decapsulates (unwraps) an OAEP-wrapped DEK with the RSA private key.
     *
     * @param wrappedDek wrapped DEK produced by {@link #encapsulate(SecretKey, PublicKey)}
     * @param privateKey recipient RSA private key
     * @return the recovered AES-256 DEK
     * @throws GeneralSecurityException if unwrapping or OAEP validation fails
     */
    public static SecretKey decapsulate(byte[] wrappedDek, PrivateKey privateKey)
            throws GeneralSecurityException {
        Objects.requireNonNull(wrappedDek, "wrappedDek");
        Objects.requireNonNull(privateKey, "privateKey");
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("privateKey must be an RSA private key");
        }

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.UNWRAP_MODE, privateKey, OAEP_SHA256);
        return (SecretKey) cipher.unwrap(wrappedDek, "AES", Cipher.SECRET_KEY);
    }
}

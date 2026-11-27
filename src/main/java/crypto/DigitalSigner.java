package crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

/**
 * Digital signatures (IND2) using Ed25519.
 *
 * <p>Provides key-pair generation plus detached {@code sign}/{@code verify}
 * operations over arbitrary byte arrays.</p>
 */
public final class DigitalSigner {

    /** JCA algorithm name. */
    public static final String ALGORITHM = "Ed25519";

    /** Raw Ed25519 signature length in bytes. */
    public static final int SIGNATURE_LENGTH_BYTES = 64;

    private DigitalSigner() {
        throw new AssertionError("No instances.");
    }

    /**
     * Generates an Ed25519 key pair.
     *
     * @return a fresh Ed25519 key pair
     * @throws GeneralSecurityException if key generation fails
     */
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
    }

    /**
     * Signs data with an Ed25519 private key.
     *
     * @param data       message to sign
     * @param privateKey Ed25519 private key
     * @return a 64-byte detached signature
     * @throws GeneralSecurityException if signing fails
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(privateKey, "privateKey");

        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verifies a detached Ed25519 signature.
     *
     * @param data       message that was signed
     * @param signature  detached signature bytes
     * @param publicKey  Ed25519 public key
     * @return {@code true} if the signature is valid for the data and key
     * @throws GeneralSecurityException if the verification operation fails
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey)
            throws GeneralSecurityException {
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(signature, "signature");
        Objects.requireNonNull(publicKey, "publicKey");

        Signature verifier = Signature.getInstance(ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }
}

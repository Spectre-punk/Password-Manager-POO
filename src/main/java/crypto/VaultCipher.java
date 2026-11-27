package crypto;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Authenticated encryption with AES-256-GCM.
 *
 * <p>Every encryption uses a fresh 12-byte random nonce and produces a 128-bit
 * authentication tag appended to the ciphertext. ECB and all unauthenticated
 * modes are deliberately unsupported.</p>
 *
 * <p>Secrets can be passed as {@code char[]} and are wiped internally after the
 * UTF-8 conversion. Callers remain responsible for wiping their own buffers.</p>
 */
public final class VaultCipher {

    /** AES key size in bits. */
    public static final int KEY_LENGTH_BITS = 256;

    /** AES key size in bytes. */
    public static final int KEY_LENGTH_BYTES = KEY_LENGTH_BITS / 8;

    /** GCM nonce/IV length in bytes. */
    public static final int IV_LENGTH_BYTES = 12;

    /** GCM authentication tag length in bits. */
    public static final int TAG_LENGTH_BITS = 128;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final SecureRandom RANDOM = new SecureRandom();

    private VaultCipher() {
        throw new AssertionError("No instances.");
    }

    /**
     * Generates a fresh AES-256 key.
     *
     * @return a new 256-bit AES key
     * @throws GeneralSecurityException if the platform cannot create the key
     */
    public static SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_LENGTH_BITS, RANDOM);
        return generator.generateKey();
    }

    /**
     * Encrypts a byte array with AES-256-GCM.
     *
     * @param plaintext data to encrypt
     * @param key       256-bit AES key
     * @return the nonce and authenticated ciphertext
     * @throws GeneralSecurityException if encryption fails
     */
    public static SealedData encrypt(byte[] plaintext, SecretKey key) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "plaintext");
        requireAes256(key);

        byte[] iv = new byte[IV_LENGTH_BYTES];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);
        return new SealedData(iv, ciphertext);
    }

    /**
     * Encrypts a {@code char[]} secret. The intermediate UTF-8 bytes are wiped
     * before returning; the caller's array is left untouched.
     *
     * @param plaintext secret characters to encrypt
     * @param key       256-bit AES key
     * @return the nonce and authenticated ciphertext
     * @throws GeneralSecurityException if encryption fails
     */
    public static SealedData encrypt(char[] plaintext, SecretKey key) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "plaintext");
        byte[] encoded = encodeUtf8(plaintext);
        try {
            return encrypt(encoded, key);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Decrypts and authenticates an AES-256-GCM payload.
     *
     * @param sealed nonce plus ciphertext/tag
     * @param key    256-bit AES key
     * @return the recovered plaintext bytes
     * @throws GeneralSecurityException if authentication fails (tampering/wrong key)
     */
    public static byte[] decrypt(SealedData sealed, SecretKey key) throws GeneralSecurityException {
        Objects.requireNonNull(sealed, "sealed");
        requireAes256(key);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, sealed.iv()));
        return cipher.doFinal(sealed.ciphertext());
    }

    /**
     * Decrypts an authenticated payload into a {@code char[]}. The intermediate
     * plaintext bytes are wiped before returning.
     *
     * @param sealed nonce plus ciphertext/tag
     * @param key    256-bit AES key
     * @return the recovered secret characters
     * @throws GeneralSecurityException if authentication fails (tampering/wrong key)
     */
    public static char[] decryptToChars(SealedData sealed, SecretKey key) throws GeneralSecurityException {
        byte[] plaintext = decrypt(sealed, key);
        try {
            return decodeUtf8(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static void requireAes256(SecretKey key) {
        Objects.requireNonNull(key, "key");
        if (!"AES".equalsIgnoreCase(key.getAlgorithm())) {
            throw new IllegalArgumentException("key must be an AES key");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                    "key must be " + KEY_LENGTH_BITS + " bits");
        }
        Arrays.fill(encoded, (byte) 0);
    }

    private static byte[] encodeUtf8(char[] chars) {
        try {
            ByteBuffer buffer = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(chars));
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            if (buffer.hasArray()) {
                Arrays.fill(buffer.array(), (byte) 0);
            }
            return bytes;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("plaintext contains invalid UTF-16", e);
        }
    }

    private static char[] decodeUtf8(byte[] bytes) {
        try {
            CharBuffer buffer = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes));
            char[] chars = new char[buffer.remaining()];
            buffer.get(chars);
            if (buffer.hasArray()) {
                Arrays.fill(buffer.array(), '\0');
            }
            return chars;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("plaintext is not valid UTF-8", e);
        }
    }

    /**
     * Immutable AES-GCM payload: the random nonce and the ciphertext (which
     * includes the 128-bit authentication tag).
     */
    public record SealedData(byte[] iv, byte[] ciphertext) {

        public SealedData {
            Objects.requireNonNull(iv, "iv");
            Objects.requireNonNull(ciphertext, "ciphertext");
            if (iv.length != IV_LENGTH_BYTES) {
                throw new IllegalArgumentException(
                        "iv must be exactly " + IV_LENGTH_BYTES + " bytes");
            }
            if (ciphertext.length < TAG_LENGTH_BITS / 8) {
                throw new IllegalArgumentException("ciphertext is shorter than the GCM tag");
            }
            iv = iv.clone();
            ciphertext = ciphertext.clone();
        }

        @Override
        public byte[] iv() {
            return iv.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }
    }
}

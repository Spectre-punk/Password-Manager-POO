package crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

class VaultCipherTest {

    private static void wipe(byte[] value) {
        Arrays.fill(value, (byte) 0);
    }

    private static void wipe(char[] value) {
        Arrays.fill(value, '\0');
    }

    @Test
    void generatesAes256Keys() throws Exception {
        SecretKey key = VaultCipher.generateKey();
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length);
    }

    @Test
    void encryptsAndDecryptsBytes() throws Exception {
        SecretKey key = VaultCipher.generateKey();
        byte[] plaintext = "vault payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        VaultCipher.SealedData sealed = VaultCipher.encrypt(plaintext, key);
        byte[] recovered = VaultCipher.decrypt(sealed, key);

        try {
            assertEquals(VaultCipher.IV_LENGTH_BYTES, sealed.iv().length);
            assertArrayEquals(plaintext, recovered);
        } finally {
            wipe(plaintext);
            wipe(recovered);
        }
    }

    @Test
    void encryptsAndDecryptsCharsIncludingUnicode() throws Exception {
        SecretKey key = VaultCipher.generateKey();
        char[] plaintext = "contraseña-ñ-🔐".toCharArray();

        VaultCipher.SealedData sealed = VaultCipher.encrypt(plaintext, key);
        char[] recovered = VaultCipher.decryptToChars(sealed, key);

        try {
            assertArrayEquals(plaintext, recovered);
        } finally {
            wipe(plaintext);
            wipe(recovered);
        }
    }

    @Test
    void usesFreshNoncePerEncryption() throws Exception {
        SecretKey key = VaultCipher.generateKey();
        byte[] plaintext = "same message".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        VaultCipher.SealedData first = VaultCipher.encrypt(plaintext, key);
        VaultCipher.SealedData second = VaultCipher.encrypt(plaintext, key);

        assertNotEquals(Arrays.toString(first.iv()), Arrays.toString(second.iv()));
        assertFalse(Arrays.equals(first.ciphertext(), second.ciphertext()));
    }

    @Test
    void rejectsTamperedCiphertext() throws Exception {
        SecretKey key = VaultCipher.generateKey();
        VaultCipher.SealedData sealed = VaultCipher.encrypt(
                "tamper me".getBytes(java.nio.charset.StandardCharsets.UTF_8), key);

        byte[] tampered = sealed.ciphertext();
        tampered[tampered.length - 1] ^= 0x01;
        VaultCipher.SealedData forged = new VaultCipher.SealedData(sealed.iv(), tampered);

        assertThrows(GeneralSecurityException.class, () -> VaultCipher.decrypt(forged, key));
    }

    @Test
    void rejectsWrongKey() throws Exception {
        SecretKey key = VaultCipher.generateKey();
        SecretKey wrongKey = VaultCipher.generateKey();
        VaultCipher.SealedData sealed = VaultCipher.encrypt(
                "secret".getBytes(java.nio.charset.StandardCharsets.UTF_8), key);

        assertThrows(GeneralSecurityException.class, () -> VaultCipher.decrypt(sealed, wrongKey));
    }

    @Test
    void sealedDataDefensivelyCopiesArrays() throws Exception {
        SecretKey key = VaultCipher.generateKey();
        VaultCipher.SealedData sealed = VaultCipher.encrypt(
                "immutable".getBytes(java.nio.charset.StandardCharsets.UTF_8), key);

        byte[] ivCopy = sealed.iv();
        byte[] ciphertextCopy = sealed.ciphertext();
        byte[] expectedIv = sealed.iv();
        byte[] expectedCiphertext = sealed.ciphertext();

        ivCopy[0] ^= 0x01;
        ciphertextCopy[0] ^= 0x01;

        assertArrayEquals(expectedIv, sealed.iv());
        assertArrayEquals(expectedCiphertext, sealed.ciphertext());
        assertArrayEquals("immutable".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                VaultCipher.decrypt(sealed, key));
    }

    @Test
    void rejectsNonAesKeys() throws Exception {
        java.security.KeyPair ed25519 = DigitalSigner.generateKeyPair();
        java.security.PublicKey publicKey = ed25519.getPublic();

        assertThrows(IllegalArgumentException.class,
                () -> VaultCipher.encrypt(new byte[] {1}, new javax.crypto.spec.SecretKeySpec(
                        publicKey.getEncoded(), "Ed25519")));
    }
}

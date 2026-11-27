package crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class KeyEncapsulatorTest {

    private static KeyPair keyPair;
    private static KeyPair otherKeyPair;

    @BeforeAll
    static void generateKeys() throws Exception {
        keyPair = KeyEncapsulator.generateKeyPair();
        otherKeyPair = KeyEncapsulator.generateKeyPair();
    }

    @Test
    void generatesRsa3072KeyPairs() {
        assertEquals(KeyEncapsulator.RSA_KEY_SIZE_BITS, 3072);
        assertEquals(3072, ((java.security.interfaces.RSAPublicKey) keyPair.getPublic()).getModulus().bitLength());
    }

    @Test
    void encapsulateAndDecapsulateRoundTrip() throws Exception {
        SecretKey dek = VaultCipher.generateKey();
        byte[] wrapped = KeyEncapsulator.encapsulate(dek, keyPair.getPublic());
        SecretKey recovered = KeyEncapsulator.decapsulate(wrapped, keyPair.getPrivate());

        byte[] expected = dek.getEncoded();
        byte[] actual = recovered.getEncoded();
        try {
            assertEquals("AES", recovered.getAlgorithm());
            assertArrayEquals(expected, actual);
        } finally {
            Arrays.fill(expected, (byte) 0);
            Arrays.fill(actual, (byte) 0);
        }
    }

    @Test
    void decapsulationWithWrongPrivateKeyFails() throws Exception {
        SecretKey dek = VaultCipher.generateKey();
        byte[] wrapped = KeyEncapsulator.encapsulate(dek, keyPair.getPublic());

        assertThrows(GeneralSecurityException.class,
                () -> KeyEncapsulator.decapsulate(wrapped, otherKeyPair.getPrivate()));
    }

    @Test
    void rejectsNonRsaKeys() throws Exception {
        KeyPair ed25519 = DigitalSigner.generateKeyPair();
        SecretKey dek = VaultCipher.generateKey();

        assertThrows(IllegalArgumentException.class,
                () -> KeyEncapsulator.encapsulate(dek, ed25519.getPublic()));
        assertThrows(IllegalArgumentException.class,
                () -> KeyEncapsulator.decapsulate(new byte[384], ed25519.getPrivate()));
    }

    @Test
    void rejectsNonAesDek() throws Exception {
        javax.crypto.SecretKey wrong = new javax.crypto.spec.SecretKeySpec(new byte[32], "ChaCha20");

        assertThrows(IllegalArgumentException.class,
                () -> KeyEncapsulator.encapsulate(wrong, keyPair.getPublic()));
    }
}

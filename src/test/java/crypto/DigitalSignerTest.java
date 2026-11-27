package crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class DigitalSignerTest {

    private static KeyPair keyPair;
    private static KeyPair otherKeyPair;

    @BeforeAll
    static void generateKeys() throws Exception {
        keyPair = DigitalSigner.generateKeyPair();
        otherKeyPair = DigitalSigner.generateKeyPair();
    }

    @Test
    void signsAndVerifiesData() throws Exception {
        byte[] data = "vault manifest v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] signature = DigitalSigner.sign(data, keyPair.getPrivate());

        assertEquals(DigitalSigner.SIGNATURE_LENGTH_BYTES, signature.length);
        assertTrue(DigitalSigner.verify(data, signature, keyPair.getPublic()));
    }

    @Test
    void rejectsTamperedData() throws Exception {
        byte[] data = "vault manifest v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] tampered = data.clone();
        tampered[0] ^= 0x01;

        byte[] signature = DigitalSigner.sign(data, keyPair.getPrivate());

        assertFalse(DigitalSigner.verify(tampered, signature, keyPair.getPublic()));
    }

    @Test
    void rejectsSignatureFromAnotherKey() throws Exception {
        byte[] data = "vault manifest v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] signature = DigitalSigner.sign(data, otherKeyPair.getPrivate());

        assertFalse(DigitalSigner.verify(data, signature, keyPair.getPublic()));
    }

    @Test
    void rejectsTamperedSignature() throws Exception {
        byte[] data = "vault manifest v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] signature = DigitalSigner.sign(data, keyPair.getPrivate());
        signature[0] ^= 0x01;

        assertFalse(DigitalSigner.verify(data, signature, keyPair.getPublic()));
    }
}

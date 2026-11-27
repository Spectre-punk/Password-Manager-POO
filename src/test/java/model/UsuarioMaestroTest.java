package model;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import crypto.DigitalSigner;
import crypto.KeyEncapsulator;
import crypto.SchnorrZKP;
import crypto.VaultCipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import util.SecretWiper;

class UsuarioMaestroTest {

    private static char[] password() {
        return "Master-Pass-123!".toCharArray();
    }

    @Test
    void createStoresOnlyPublicMetadataAndEncryptedPrivateKeys() throws Exception {
        char[] password = password();
        try {
            UsuarioMaestro usuario = UsuarioMaestro.create("alice", password);

            assertEquals("alice", usuario.getNombreDeUsuario());
            assertEquals(16, usuario.getSalt().length);
            assertNotNull(usuario.getVerifier());
            assertNotNull(usuario.getKemPublicKey());
            assertNotNull(usuario.getSigningPublicKey());
            assertNotNull(usuario.getKemPrivateKeyIv());
            assertNotNull(usuario.getKemPrivateKeyCiphertext());
            assertNotNull(usuario.getSigningPrivateKeyIv());
            assertNotNull(usuario.getSigningPrivateKeyCiphertext());
        } finally {
            SecretWiper.wipe(password);
        }
    }

    @Test
    void authenticatesWithZkpAndRejectsWrongPassword() throws Exception {
        char[] password = password();
        char[] wrong = "not-the-password".toCharArray();
        try {
            UsuarioMaestro usuario = UsuarioMaestro.create("alice", password);

            assertTrue(usuario.authenticate(password));
            assertFalse(usuario.authenticate(wrong));
        } finally {
            SecretWiper.wipe(password);
            SecretWiper.wipe(wrong);
        }
    }

    @Test
    void verifierMatchesSecretDerivedFromPassword() throws Exception {
        char[] password = password();
        try {
            UsuarioMaestro usuario = UsuarioMaestro.create("alice", password);
            BigInteger expected = SchnorrZKP.computeVerifier(
                    SchnorrZKP.deriveSecret(password, usuario.getSalt()));

            assertEquals(expected, usuario.getVerifier());
        } finally {
            SecretWiper.wipe(password);
        }
    }

    @Test
    void unlockReturnsUsableKemAndSigningKeys() throws Exception {
        char[] password = password();
        try {
            UsuarioMaestro usuario = UsuarioMaestro.create("alice", password);
            UsuarioMaestro.UnlockedKeys keys = usuario.unlock(password);
            try {
                byte[] data = "vault manifest".getBytes(StandardCharsets.UTF_8);
                byte[] signature = DigitalSigner.sign(data, keys.signingPrivateKey());
                assertTrue(DigitalSigner.verify(data, signature, usuario.getSigningPublicKey()));

                SecretKey dek = VaultCipher.generateKey();
                byte[] wrapped = KeyEncapsulator.encapsulate(dek, usuario.getKemPublicKey());
                SecretKey recovered = KeyEncapsulator.decapsulate(wrapped, keys.kemPrivateKey());
                byte[] expected = dek.getEncoded();
                byte[] actual = recovered.getEncoded();
                try {
                    assertArrayEquals(expected, actual);
                } finally {
                    SecretWiper.wipe(expected);
                    SecretWiper.wipe(actual);
                    SecretWiper.destroy(dek);
                    SecretWiper.destroy(recovered);
                }
            } finally {
                SecretWiper.destroy(keys.kemPrivateKey());
                SecretWiper.destroy(keys.signingPrivateKey());
            }
        } finally {
            SecretWiper.wipe(password);
        }
    }

    @Test
    void wrongPasswordCannotUnlock() throws Exception {
        char[] password = password();
        char[] wrong = "wrong-password".toCharArray();
        try {
            UsuarioMaestro usuario = UsuarioMaestro.create("alice", password);

            assertThrows(SecurityException.class, () -> usuario.unlock(wrong));
        } finally {
            SecretWiper.wipe(password);
            SecretWiper.wipe(wrong);
        }
    }
}

package security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import crypto.VaultCipher;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import model.Credential;
import model.UsuarioMaestro;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import storage.PersistenciaBoveda;
import storage.VaultFile;
import util.SecretWiper;

/**
 * Positive end-to-end proof that every primitive works together:
 * Argon2id + Schnorr (registration/auth), RSA-OAEP KEM, AES-256-GCM and
 * Ed25519, followed by a master-password rotation that must keep the
 * credentials blob untouched.
 */
class EndToEndLifecycleTest {

    @Test
    void fullLifecycleIncludingMasterPasswordRotation(@TempDir Path dir) throws Exception {
        Path file = dir.resolve(PersistenciaBoveda.DEFAULT_FILE_NAME);
        char[] password = "Master-Pass-123!".toCharArray();
        char[] newPassword = "New-Master-Pass-456!".toCharArray();
        List<Credential> stored = new ArrayList<>();
        byte[] dek = null;
        SecretKey dekKey = null;

        try {
            // Registration: Argon2id salt, ZKP verifier, KEM and Ed25519 key pairs.
            UsuarioMaestro usuario = UsuarioMaestro.create("alice", password);
            assertTrue(usuario.authenticate(password), "ZKP registration must authenticate");

            UsuarioMaestro.UnlockedKeys keys = usuario.unlock(password);
            try {
                dekKey = VaultCipher.generateKey();
                dek = dekKey.getEncoded();

                stored.add(new Credential("github", "alice", "s3cret".toCharArray(), "work"));
                stored.add(new Credential(
                        "mail", "alice@example.com", "hunter2".toCharArray(), "personal"));

                // Ed25519 signs the payload; KEM wraps the DEK; AES-GCM seals the vault.
                PersistenciaBoveda.save(file, usuario, dek, stored, keys.signingPrivateKey());

                // Reload verifies the Ed25519 signature before any decryption.
                VaultFile loaded = PersistenciaBoveda.read(file);

                byte[] recoveredDek = PersistenciaBoveda.decapsulateDek(
                        loaded, keys.kemPrivateKey());
                try {
                    assertArrayEquals(dek, recoveredDek, "KEM must recover the same DEK");

                    List<Credential> decrypted = PersistenciaBoveda.decryptCredentials(
                            loaded, recoveredDek);
                    try {
                        assertEquals(2, decrypted.size());
                        assertArrayEquals("s3cret".toCharArray(),
                                decrypted.get(0).getContrasena());
                        assertArrayEquals("hunter2".toCharArray(),
                                decrypted.get(1).getContrasena());
                    } finally {
                        decrypted.forEach(Credential::clearPassword);
                    }
                } finally {
                    SecretWiper.wipe(recoveredDek);
                }

                String ivBefore = loaded.getPayload().getCredentialsIv();
                String ciphertextBefore = loaded.getPayload().getCredentialsCiphertext();

                // Rotation: new salt/verifier and KEK-encrypted private keys,
                // re-wrapped DEK, but the credentials blob must be preserved.
                UsuarioMaestro rotated = usuario.reencrypt(
                        newPassword, keys.kemPrivateKey(), keys.signingPrivateKey());
                PersistenciaBoveda.rewrap(
                        file, loaded.getPayload(), rotated, dek, keys.signingPrivateKey());

                VaultFile reloaded = PersistenciaBoveda.read(file);
                assertEquals(ivBefore, reloaded.getPayload().getCredentialsIv(),
                        "rotation must not re-encrypt the credentials blob");
                assertEquals(ciphertextBefore, reloaded.getPayload().getCredentialsCiphertext(),
                        "rotation must not re-encrypt the credentials blob");

                assertFalse(rotated.authenticate(password), "old password must stop working");
                assertTrue(rotated.authenticate(newPassword), "new password must work");

                UsuarioMaestro.UnlockedKeys rotatedKeys = rotated.unlock(newPassword);
                try {
                    byte[] rotatedDek = PersistenciaBoveda.decapsulateDek(
                            reloaded, rotatedKeys.kemPrivateKey());
                    try {
                        assertArrayEquals(dek, rotatedDek,
                                "the DEK must survive rotation unchanged");
                        List<Credential> decrypted = PersistenciaBoveda.decryptCredentials(
                                reloaded, rotatedDek);
                        try {
                            assertEquals(2, decrypted.size());
                            assertArrayEquals("hunter2".toCharArray(),
                                    decrypted.get(1).getContrasena());
                        } finally {
                            decrypted.forEach(Credential::clearPassword);
                        }
                    } finally {
                        SecretWiper.wipe(rotatedDek);
                    }
                } finally {
                    SecretWiper.destroy(rotatedKeys.kemPrivateKey());
                    SecretWiper.destroy(rotatedKeys.signingPrivateKey());
                }
            } finally {
                SecretWiper.destroy(keys.kemPrivateKey());
                SecretWiper.destroy(keys.signingPrivateKey());
            }
        } finally {
            stored.forEach(Credential::clearPassword);
            SecretWiper.wipe(dek);
            SecretWiper.destroy(dekKey);
            SecretWiper.wipe(password);
            SecretWiper.wipe(newPassword);
        }
    }
}

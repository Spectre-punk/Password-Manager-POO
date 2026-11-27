package storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import crypto.VaultCipher;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.SecretKey;
import model.Credential;
import model.UsuarioMaestro;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import util.SecretWiper;

class PersistenciaBovedaTest {

    private static UsuarioMaestro usuario;
    private static PrivateKey signingPrivateKey;
    private static PrivateKey kemPrivateKey;
    private static byte[] dek;

    @BeforeAll
    static void setUp() throws Exception {
        char[] password = "Master-Pass-123!".toCharArray();
        try {
            usuario = UsuarioMaestro.create("alice", password);
            UsuarioMaestro.UnlockedKeys keys = usuario.unlock(password);
            signingPrivateKey = keys.signingPrivateKey();
            kemPrivateKey = keys.kemPrivateKey();

            SecretKey key = VaultCipher.generateKey();
            try {
                dek = key.getEncoded();
            } finally {
                SecretWiper.destroy(key);
            }
        } finally {
            SecretWiper.wipe(password);
        }
    }

    @AfterAll
    static void tearDown() {
        SecretWiper.wipe(dek);
        SecretWiper.destroy(kemPrivateKey);
        SecretWiper.destroy(signingPrivateKey);
    }

    private static List<Credential> sampleCredentials() {
        List<Credential> credentials = new ArrayList<>();
        credentials.add(new Credential("github", "alice", "s3cret".toCharArray(), "work"));
        credentials.add(new Credential("mail", "alice@example.com", "hunter2".toCharArray(), "personal"));
        return credentials;
    }

    @Test
    void savesReloadsAndDecrypts(@TempDir Path dir) throws Exception {
        Path file = dir.resolve(PersistenciaBoveda.DEFAULT_FILE_NAME);
        List<Credential> credentials = sampleCredentials();
        try {
            PersistenciaBoveda.save(file, usuario, dek, credentials, signingPrivateKey);

            assertTrue(Files.exists(file));
            assertEquals("boveda.json", file.getFileName().toString());

            VaultFile loaded = PersistenciaBoveda.read(file);
            assertNotNull(loaded.getPayload());
            assertNotNull(loaded.getSignature());
            assertNotNull(loaded.getPayload().getEncapsulatedDek());

            byte[] recoveredDek = PersistenciaBoveda.decapsulateDek(loaded, kemPrivateKey);
            try {
                assertArrayEquals(dek, recoveredDek);
            } finally {
                SecretWiper.wipe(recoveredDek);
            }

            List<Credential> decrypted = PersistenciaBoveda.decryptCredentials(loaded, dek);
            try {
                assertEquals(2, decrypted.size());
                assertEquals("github", decrypted.get(0).getServicio());
                assertArrayEquals("s3cret".toCharArray(), decrypted.get(0).getContrasena());
                assertEquals("mail", decrypted.get(1).getServicio());
            } finally {
                decrypted.forEach(Credential::clearPassword);
            }
        } finally {
            credentials.forEach(Credential::clearPassword);
        }
    }

    @Test
    void rejectsTamperedSignature(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("boveda.json");
        List<Credential> credentials = sampleCredentials();
        try {
            PersistenciaBoveda.save(file, usuario, dek, credentials, signingPrivateKey);

            String json = Files.readString(file);
            String tampered = json.replaceFirst(
                    "\"signature\"\\s*:\\s*\"[^\"]*\"", "\"signature\": \"AAAA\"");
            assertNotEquals(json, tampered, "the test must actually tamper the signature");
            Files.writeString(file, tampered);

            assertThrows(SecurityException.class, () -> PersistenciaBoveda.read(file));
        } finally {
            credentials.forEach(Credential::clearPassword);
        }
    }

    @Test
    void rejectsTamperedPayloadBeforeDecryption(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("boveda.json");
        List<Credential> credentials = sampleCredentials();
        try {
            PersistenciaBoveda.save(file, usuario, dek, credentials, signingPrivateKey);

            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            VaultFile loaded = gson.fromJson(Files.readString(file), VaultFile.class);
            loaded.getPayload().setCredentialsCiphertext("AAAA");
            Files.writeString(file, gson.toJson(loaded));

            VaultFile tampered = gson.fromJson(Files.readString(file), VaultFile.class);
            assertThrows(SecurityException.class,
                    () -> PersistenciaBoveda.decryptCredentials(tampered, dek));
        } finally {
            credentials.forEach(Credential::clearPassword);
        }
    }

    @Test
    void wrongDekFailsAeadAfterSignatureVerification(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("boveda.json");
        List<Credential> credentials = sampleCredentials();
        byte[] wrongDek = new byte[VaultCipher.KEY_LENGTH_BYTES];
        Arrays.fill(wrongDek, (byte) 1);
        try {
            PersistenciaBoveda.save(file, usuario, dek, credentials, signingPrivateKey);
            VaultFile loaded = PersistenciaBoveda.read(file);

            assertThrows(GeneralSecurityException.class,
                    () -> PersistenciaBoveda.decryptCredentials(loaded, wrongDek));
        } finally {
            SecretWiper.wipe(wrongDek);
            credentials.forEach(Credential::clearPassword);
        }
    }
}

package model;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import storage.PersistenciaBoveda;
import storage.VaultFile;
import util.SecretWiper;

class GestorTest {

    @AfterEach
    void cleanup() {
        Gestor.getInstancia().lock();
    }

    @Test
    void singletonIsStable() {
        assertSame(Gestor.getInstancia(), Gestor.getInstancia());
    }

    @Test
    void initializesSavesLocksAndReloads(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("boveda.json");
        char[] password = "Master-Pass-123!".toCharArray();
        Gestor gestor = Gestor.getInstancia();
        try {
            gestor.inicializar(file, "alice", password);
            assertFalse(gestor.isLocked());

            gestor.agregarCredencial(
                    new Credential("github", "alice", "s3cret".toCharArray(), "work"));
            gestor.guardar();

            Field dekField = Gestor.class.getDeclaredField("dek");
            dekField.setAccessible(true);
            byte[] dekReference = (byte[]) dekField.get(gestor);
            assertNotNull(dekReference);

            gestor.lock();

            assertTrue(gestor.isLocked());
            assertNull(dekField.get(gestor));
            assertTrue(allZero(dekReference), "lock() must zeroize the DEK buffer");
            assertTrue(gestor.getCredenciales().isEmpty());

            gestor.desbloquear(file, password);

            assertFalse(gestor.isLocked());
            assertEquals(1, gestor.getCredenciales().size());
            assertArrayEquals("s3cret".toCharArray(),
                    gestor.getCredenciales().get(0).getContrasena());
        } finally {
            SecretWiper.wipe(password);
        }
    }

    @Test
    void wrongPasswordCannotUnlock(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("boveda.json");
        char[] password = "Master-Pass-123!".toCharArray();
        char[] wrong = "wrong-password".toCharArray();
        Gestor gestor = Gestor.getInstancia();
        try {
            gestor.inicializar(file, "alice", password);
            gestor.lock();

            assertThrows(SecurityException.class, () -> gestor.desbloquear(file, wrong));
            assertTrue(gestor.isLocked());
        } finally {
            SecretWiper.wipe(password);
            SecretWiper.wipe(wrong);
        }
    }

    @Test
    void lockedGestorRejectsMutations() {
        Gestor gestor = Gestor.getInstancia();
        gestor.lock();

        assertThrows(IllegalStateException.class,
                () -> gestor.agregarCredencial(
                        new Credential("s", "u", "p".toCharArray(), "n")));
        assertThrows(IllegalStateException.class, gestor::guardar);
    }

    @Test
    void changingMasterPasswordPreservesCredentialsBlob(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("boveda.json");
        char[] oldPassword = "Master-Pass-123!".toCharArray();
        char[] newPassword = "New-Master-Pass-456!".toCharArray();
        Gestor gestor = Gestor.getInstancia();
        try {
            gestor.inicializar(file, "alice", oldPassword);
            gestor.agregarCredencial(
                    new Credential("github", "alice", "s3cret".toCharArray(), "work"));
            gestor.guardar();

            VaultFile before = PersistenciaBoveda.read(file);
            String ivBefore = before.getPayload().getCredentialsIv();
            String ciphertextBefore = before.getPayload().getCredentialsCiphertext();
            String dekBefore = before.getPayload().getEncapsulatedDek();

            gestor.cambiarContraseñaMaestra(oldPassword, newPassword);

            VaultFile after = PersistenciaBoveda.read(file);
            assertEquals(ivBefore, after.getPayload().getCredentialsIv(),
                    "changing the master password must not re-encrypt the credentials blob");
            assertEquals(ciphertextBefore, after.getPayload().getCredentialsCiphertext(),
                    "changing the master password must not re-encrypt the credentials blob");
            assertNotEquals(dekBefore, after.getPayload().getEncapsulatedDek(),
                    "the DEK must be re-encapsulated");

            gestor.lock();
            assertThrows(SecurityException.class, () -> gestor.desbloquear(file, oldPassword));
            assertTrue(gestor.isLocked());

            gestor.desbloquear(file, newPassword);
            assertFalse(gestor.isLocked());
            assertEquals(1, gestor.getCredenciales().size());
            assertArrayEquals("s3cret".toCharArray(),
                    gestor.getCredenciales().get(0).getContrasena());
        } finally {
            SecretWiper.wipe(oldPassword);
            SecretWiper.wipe(newPassword);
        }
    }

    private static boolean allZero(byte[] value) {
        for (byte b : value) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}

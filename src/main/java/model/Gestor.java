package model;

import crypto.VaultCipher;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import javax.crypto.SecretKey;
import storage.PersistenciaBoveda;
import storage.VaultFile;
import util.SecretWiper;

/**
 * Vault session manager (singleton).
 *
 * <p>The DEK is held only while the vault is unlocked. {@link #lock()} zeroizes
 * it, clears decrypted credentials and drops private-key references.</p>
 */
public final class Gestor {

    private static final Gestor INSTANCIA = new Gestor();

    private final List<Credential> credenciales = new ArrayList<>();
    private UsuarioMaestro usuario;
    private Path vaultPath;
    private byte[] dek;
    private PrivateKey kemPrivateKey;
    private PrivateKey signingPrivateKey;
    private boolean locked = true;

    private Gestor() {
        // Singleton: the recursion bug from the legacy constructor is gone.
    }

    public static Gestor getInstancia() {
        return INSTANCIA;
    }

    /**
     * Creates a brand-new vault, keeps the session unlocked and writes
     * {@code boveda.json}.
     */
    public synchronized void inicializar(Path vaultPath, String nombreUsuario, char[] masterPassword)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(vaultPath, "vaultPath");
        lock();

        this.vaultPath = vaultPath;
        this.usuario = UsuarioMaestro.create(nombreUsuario, masterPassword);
        UsuarioMaestro.UnlockedKeys keys = usuario.unlock(masterPassword);
        this.kemPrivateKey = keys.kemPrivateKey();
        this.signingPrivateKey = keys.signingPrivateKey();

        SecretKey newDek = VaultCipher.generateKey();
        try {
            this.dek = newDek.getEncoded();
        } finally {
            SecretWiper.destroy(newDek);
        }
        this.credenciales.clear();
        this.locked = false;

        guardar();
    }

    /**
     * Reads and verifies the vault, authenticates the password with the ZKP,
     * decapsulates the DEK and decrypts the credentials.
     */
    public synchronized void desbloquear(Path vaultPath, char[] masterPassword)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(vaultPath, "vaultPath");
        lock();

        VaultFile file = PersistenciaBoveda.read(vaultPath);
        UsuarioMaestro user = file.getPayload().getUsuario();
        UsuarioMaestro.UnlockedKeys keys = user.unlock(masterPassword);

        byte[] dekBytes = null;
        try {
            dekBytes = PersistenciaBoveda.decapsulateDek(file, keys.kemPrivateKey());
            List<Credential> decrypted = PersistenciaBoveda.decryptCredentials(file, dekBytes);

            this.vaultPath = vaultPath;
            this.usuario = user;
            this.kemPrivateKey = keys.kemPrivateKey();
            this.signingPrivateKey = keys.signingPrivateKey();
            this.dek = dekBytes;
            this.credenciales.clear();
            this.credenciales.addAll(decrypted);
            this.locked = false;
        } catch (GeneralSecurityException | RuntimeException e) {
            SecretWiper.wipe(dekBytes);
            SecretWiper.destroy(keys.kemPrivateKey());
            SecretWiper.destroy(keys.signingPrivateKey());
            throw e;
        }
    }

    /** Persists the current session. */
    public synchronized void guardar() throws IOException, GeneralSecurityException {
        requireUnlocked();
        PersistenciaBoveda.save(vaultPath, usuario, dek, credenciales, signingPrivateKey);
    }

    /** Ends the session and zeroizes the DEK. */
    public synchronized void lock() {
        SecretWiper.wipe(dek);
        dek = null;

        for (Credential credential : credenciales) {
            credential.clearPassword();
        }
        credenciales.clear();

        SecretWiper.destroy(kemPrivateKey);
        kemPrivateKey = null;
        SecretWiper.destroy(signingPrivateKey);
        signingPrivateKey = null;

        locked = true;
    }

    public synchronized void agregarCredencial(Credential credential) {
        requireUnlocked();
        credenciales.add(Objects.requireNonNull(credential, "credential"));
    }

    public synchronized List<Credential> getCredenciales() {
        return Collections.unmodifiableList(new ArrayList<>(credenciales));
    }

    public synchronized UsuarioMaestro getUsuario() {
        return usuario;
    }

    public synchronized Path getVaultPath() {
        return vaultPath;
    }

    public synchronized boolean isLocked() {
        return locked;
    }

    private void requireUnlocked() {
        if (locked) {
            throw new IllegalStateException("Vault is locked");
        }
    }
}

package storage;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import crypto.DigitalSigner;
import crypto.KeyEncapsulator;
import crypto.VaultCipher;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import model.Credential;
import model.UsuarioMaestro;
import util.SecretWiper;

/**
 * Authenticated persistence for the vault.
 *
 * <p>Loading always verifies the Ed25519 signature over the payload <em>before</em>
 * any decryption is attempted. A bad signature raises {@link SecurityException}
 * immediately.</p>
 */
public final class PersistenciaBoveda {

    public static final String DEFAULT_FILE_NAME = "boveda.json";

    private static final Type CREDENTIAL_LIST_TYPE = new TypeToken<List<Credential>>() {
    }.getType();

    private static final Gson FILE_GSON = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();

    private static final Gson SIGNING_GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .create();

    private static final Gson CREDENTIALS_GSON = new GsonBuilder()
            .registerTypeAdapter(char[].class, new CharArrayAdapter())
            .disableHtmlEscaping()
            .create();

    private PersistenciaBoveda() {
        throw new AssertionError("No instances.");
    }

    /**
     * Encrypts the credentials, encapsulates the DEK and writes a signed vault
     * file atomically.
     *
     * @param path               destination (typically {@code boveda.json})
     * @param usuario            master-user metadata
     * @param dek                32-byte data-encryption key
     * @param credentials        credentials to persist
     * @param signingPrivateKey  Ed25519 private key used to sign the payload
     */
    public static void save(Path path, UsuarioMaestro usuario, byte[] dek,
                            List<Credential> credentials, PrivateKey signingPrivateKey)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(usuario, "usuario");
        Objects.requireNonNull(dek, "dek");
        Objects.requireNonNull(credentials, "credentials");
        Objects.requireNonNull(signingPrivateKey, "signingPrivateKey");
        if (dek.length != VaultCipher.KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("dek must be 32 bytes");
        }

        SecretKey dekKey = new SecretKeySpec(dek, "AES");
        byte[] credentialsJson = null;
        byte[] wrappedDek = null;
        try {
            credentialsJson = serializeCredentials(credentials);
            VaultCipher.SealedData sealed = VaultCipher.encrypt(credentialsJson, dekKey);
            wrappedDek = KeyEncapsulator.encapsulate(dekKey, usuario.getKemPublicKey());

            VaultFile.VaultPayload payload = new VaultFile.VaultPayload();
            payload.setUsuario(usuario);
            payload.setEncapsulatedDek(b64(wrappedDek));
            payload.setCredentialsIv(b64(sealed.iv()));
            payload.setCredentialsCiphertext(b64(sealed.ciphertext()));

            byte[] signature = DigitalSigner.sign(signingInput(payload), signingPrivateKey);

            VaultFile file = new VaultFile();
            file.setPayload(payload);
            file.setSignature(b64(signature));

            writeAtomically(path, FILE_GSON.toJson(file));
        } finally {
            SecretWiper.wipe(credentialsJson);
            SecretWiper.wipe(wrappedDek);
            SecretWiper.destroy(dekKey);
        }
    }

    /**
     * Reads the vault and verifies its signature before returning.
     *
     * @param path vault file
     * @return the verified vault file
     * @throws IOException       if the file cannot be read
     * @throws SecurityException if the payload is missing or the signature is invalid
     */
    public static VaultFile read(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        String json = Files.readString(path, StandardCharsets.UTF_8);
        VaultFile file = FILE_GSON.fromJson(json, VaultFile.class);
        if (file == null || file.getPayload() == null || file.getPayload().getUsuario() == null) {
            throw new SecurityException("Invalid vault file: missing payload");
        }
        verifySignature(file);
        return file;
    }

    /**
     * Decapsulates the vault DEK. Signature verification happens first.
     *
     * @param file          verified-or-untrusted vault file
     * @param kemPrivateKey RSA private key
     * @return the 32-byte DEK
     */
    public static byte[] decapsulateDek(VaultFile file, PrivateKey kemPrivateKey)
            throws GeneralSecurityException {
        Objects.requireNonNull(kemPrivateKey, "kemPrivateKey");
        verifySignature(file);

        byte[] wrapped = Base64.getDecoder().decode(file.getPayload().getEncapsulatedDek());
        try {
            SecretKey dek = KeyEncapsulator.decapsulate(wrapped, kemPrivateKey);
            try {
                byte[] encoded = dek.getEncoded();
                if (encoded == null) {
                    throw new GeneralSecurityException("DEK is not exportable");
                }
                return encoded;
            } finally {
                SecretWiper.destroy(dek);
            }
        } finally {
            SecretWiper.wipe(wrapped);
        }
    }

    /**
     * Decrypts and deserializes the credentials blob. Signature verification
     * happens first, so tampering aborts with {@link SecurityException} rather
     * than an AEAD failure.
     *
     * @param file verified-or-untrusted vault file
     * @param dek  32-byte DEK
     * @return decrypted credentials
     */
    public static List<Credential> decryptCredentials(VaultFile file, byte[] dek)
            throws GeneralSecurityException {
        Objects.requireNonNull(dek, "dek");
        verifySignature(file);

        SecretKey dekKey = new SecretKeySpec(dek, "AES");
        byte[] plaintext = null;
        try {
            VaultFile.VaultPayload payload = file.getPayload();
            VaultCipher.SealedData sealed = new VaultCipher.SealedData(
                    Base64.getDecoder().decode(payload.getCredentialsIv()),
                    Base64.getDecoder().decode(payload.getCredentialsCiphertext()));
            plaintext = VaultCipher.decrypt(sealed, dekKey);
            return deserializeCredentials(plaintext);
        } finally {
            SecretWiper.wipe(plaintext);
            SecretWiper.destroy(dekKey);
        }
    }

    private static void verifySignature(VaultFile file) {
        Objects.requireNonNull(file, "file");
        VaultFile.VaultPayload payload = file.getPayload();
        if (payload == null || payload.getUsuario() == null
                || file.getSignature() == null || file.getSignature().isEmpty()) {
            throw new SecurityException("Vault signature verification failed: missing data");
        }
        try {
            PublicKey key = payload.getUsuario().getSigningPublicKey();
            byte[] signature = Base64.getDecoder().decode(file.getSignature());
            if (!DigitalSigner.verify(signingInput(payload), signature, key)) {
                throw new SecurityException("Vault signature verification failed");
            }
        } catch (SecurityException e) {
            throw e;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new SecurityException("Vault signature verification failed", e);
        }
    }

    private static byte[] signingInput(VaultFile.VaultPayload payload) {
        return SIGNING_GSON.toJson(payload).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] serializeCredentials(List<Credential> credentials) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
            CREDENTIALS_GSON.toJson(credentials, CREDENTIAL_LIST_TYPE, writer);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to serialize credentials", e);
        }
        return out.toByteArray();
    }

    private static List<Credential> deserializeCredentials(byte[] json) {
        try (Reader reader = new InputStreamReader(
                new ByteArrayInputStream(json), StandardCharsets.UTF_8)) {
            List<Credential> credentials = CREDENTIALS_GSON.fromJson(reader, CREDENTIAL_LIST_TYPE);
            return credentials == null ? new ArrayList<>() : credentials;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to deserialize credentials", e);
        }
    }

    private static void writeAtomically(Path path, String json) throws IOException {
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temp = Files.createTempFile(parent, "boveda-", ".tmp");
        try {
            Files.writeString(temp, json, StandardCharsets.UTF_8);
            try {
                Files.move(temp, absolute,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static String b64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    /** Serializes {@code char[]} secrets as numeric code units, never as a String. */
    private static final class CharArrayAdapter extends TypeAdapter<char[]> {

        @Override
        public void write(JsonWriter out, char[] value) throws IOException {
            if (value == null) {
                out.nullValue();
                return;
            }
            out.beginArray();
            for (char c : value) {
                out.value((int) c);
            }
            out.endArray();
        }

        @Override
        public char[] read(JsonReader in) throws IOException {
            if (in.peek() == JsonToken.NULL) {
                in.nextNull();
                return null;
            }
            List<Character> chars = new ArrayList<>();
            in.beginArray();
            while (in.hasNext()) {
                int code = in.nextInt();
                if (code < Character.MIN_VALUE || code > Character.MAX_VALUE) {
                    throw new JsonParseException("Invalid character code: " + code);
                }
                chars.add((char) code);
            }
            in.endArray();

            char[] result = new char[chars.size()];
            for (int i = 0; i < result.length; i++) {
                result[i] = chars.get(i);
            }
            return result;
        }
    }
}

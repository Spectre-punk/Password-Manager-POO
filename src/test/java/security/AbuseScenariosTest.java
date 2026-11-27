package security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import crypto.KeyEncapsulator;
import crypto.SchnorrZKP;
import crypto.VaultCipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import model.Credential;
import model.UsuarioMaestro;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import storage.PersistenciaBoveda;
import storage.VaultFile;
import util.SecretWiper;

/**
 * Negative / abuse scenarios: tampering, impersonation and key substitution
 * must all be rejected.
 */
class AbuseScenariosTest {

    private static final String MASTER_PASSWORD = "Master-Pass-123!";
    private static final Pattern SIGNATURE_FIELD =
            Pattern.compile("\"signature\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"");

    private static char[] password;
    private static UsuarioMaestro usuario;
    private static UsuarioMaestro.UnlockedKeys keys;
    private static byte[] dek;

    @BeforeAll
    static void setUp() throws Exception {
        password = MASTER_PASSWORD.toCharArray();
        usuario = UsuarioMaestro.create("alice", password);
        keys = usuario.unlock(password);

        SecretKey dekKey = VaultCipher.generateKey();
        try {
            dek = dekKey.getEncoded();
        } finally {
            SecretWiper.destroy(dekKey);
        }
    }

    @AfterAll
    static void tearDown() {
        SecretWiper.wipe(dek);
        SecretWiper.wipe(password);
        SecretWiper.destroy(keys.kemPrivateKey());
        SecretWiper.destroy(keys.signingPrivateKey());
    }

    @Test
    void tamperedFileFailsSignatureVerification(@TempDir Path dir) throws Exception {
        Path file = saveSampleVault(dir);
        String json = Files.readString(file);

        // Flip exactly one byte: the first character of the Base64 signature.
        Files.writeString(file, flipOneSignatureByte(json));

        SecurityException error = assertThrows(SecurityException.class,
                () -> PersistenciaBoveda.read(file),
                "a one-byte change must invalidate the Ed25519 signature");
        assertTrue(error.getMessage().toLowerCase().contains("signature"),
                "the rejection must come from signature verification");
    }

    @Test
    void tamperedAesGcmCiphertextThrowsAeadBadTag() throws Exception {
        SecretKey key = VaultCipher.generateKey();
        byte[] plaintext = "vault credentials block".getBytes(StandardCharsets.UTF_8);
        VaultCipher.SealedData sealed = VaultCipher.encrypt(plaintext, key);

        byte[] ciphertext = sealed.ciphertext();
        ciphertext[ciphertext.length / 2] ^= 0x01;
        VaultCipher.SealedData tampered =
                new VaultCipher.SealedData(sealed.iv(), ciphertext);

        assertThrows(AEADBadTagException.class, () -> VaultCipher.decrypt(tampered, key),
                "AES-GCM must report a bad authentication tag");
        SecretWiper.wipe(plaintext);
    }

    @Test
    void tamperedVaultCiphertextIsRejectedBeforeDecryption(@TempDir Path dir) throws Exception {
        Path file = saveSampleVault(dir);
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        VaultFile vault = gson.fromJson(Files.readString(file), VaultFile.class);

        byte[] ciphertext = Base64.getDecoder()
                .decode(vault.getPayload().getCredentialsCiphertext());
        ciphertext[0] ^= 0x01;
        vault.getPayload().setCredentialsCiphertext(
                Base64.getEncoder().encodeToString(ciphertext));
        Files.writeString(file, gson.toJson(vault));

        VaultFile tampered = gson.fromJson(Files.readString(file), VaultFile.class);
        assertThrows(SecurityException.class,
                () -> PersistenciaBoveda.decryptCredentials(tampered, dek),
                "signature verification must abort before AES-GCM is attempted");
    }

    @Test
    void zkpImpersonationWithInvalidPasswordIsRejected() {
        char[] wrong = "not-the-master-password".toCharArray();
        try {
            assertFalse(usuario.authenticate(wrong),
                    "an invalid password must not authenticate");

            // Even an attacker who runs the protocol with a different secret
            // cannot produce a proof for the stored verifier.
            BigInteger attackerSecret = BigInteger.valueOf(424242);
            SchnorrZKP.ProverSession attacker = SchnorrZKP.startProver(attackerSecret);
            BigInteger commitment = attacker.commitment();
            BigInteger challenge = SchnorrZKP.generateChallenge();
            BigInteger response = attacker.respond(challenge);

            assertFalse(SchnorrZKP.verify(
                            commitment, usuario.getVerifier(), challenge, response),
                    "a forged Schnorr proof must not verify");
        } finally {
            SecretWiper.wipe(wrong);
        }
    }

    @Test
    void decapsulationWithUnrelatedPrivateKeyFails(@TempDir Path dir) throws Exception {
        Path file = saveSampleVault(dir);
        VaultFile vault = PersistenciaBoveda.read(file);

        KeyPair unrelated = KeyEncapsulator.generateKeyPair();
        try {
            assertThrows(GeneralSecurityException.class,
                    () -> PersistenciaBoveda.decapsulateDek(vault, unrelated.getPrivate()),
                    "an unrelated RSA key must not unwrap the DEK");
        } finally {
            SecretWiper.destroy(unrelated.getPrivate());
        }
    }

    private static Path saveSampleVault(Path dir) throws Exception {
        Path file = dir.resolve(PersistenciaBoveda.DEFAULT_FILE_NAME);
        List<Credential> credentials = new ArrayList<>();
        credentials.add(new Credential("github", "alice", "s3cret".toCharArray(), "work"));
        try {
            PersistenciaBoveda.save(file, usuario, dek, credentials, keys.signingPrivateKey());
        } finally {
            credentials.forEach(Credential::clearPassword);
        }
        return file;
    }

    private static String flipOneSignatureByte(String json) {
        Matcher matcher = SIGNATURE_FIELD.matcher(json);
        if (!matcher.find()) {
            throw new AssertionError("signature field not found in vault JSON");
        }
        String signature = matcher.group(1);
        char original = signature.charAt(0);
        char replacement = original == 'A' ? 'B' : 'A';
        String flipped = replacement + signature.substring(1);
        return json.substring(0, matcher.start(1)) + flipped + json.substring(matcher.end(1));
    }
}

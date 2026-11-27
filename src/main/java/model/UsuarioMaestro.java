package model;

import crypto.Argon2KDF;
import crypto.DigitalSigner;
import crypto.KeyEncapsulator;
import crypto.SchnorrZKP;
import crypto.VaultCipher;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import util.SecretWiper;

/**
 * Master-user metadata for the vault.
 *
 * <p>No password hash is stored. The object keeps only public metadata plus
 * private keys encrypted under a KEK derived from the master password:</p>
 * <ul>
 *   <li>Argon2id salt</li>
 *   <li>Schnorr public verifier {@code Y = g^x mod p}</li>
 *   <li>KEM (RSA) and signing (Ed25519) public keys</li>
 *   <li>KEK-encrypted KEM and Ed25519 private keys</li>
 * </ul>
 *
 * <p>Login runs the interactive Schnorr protocol against {@code Y}; it never
 * compares a stored password hash.</p>
 */
public class UsuarioMaestro extends Usuario {

    private static final int MASTER_KEY_LENGTH_BYTES = 64;
    private static final int KEK_LENGTH_BYTES = 32;

    private String salt;
    private String verifier;
    private String kemPublicKey;
    private String kemPrivateKeyIv;
    private String kemPrivateKeyCiphertext;
    private String signingPublicKey;
    private String signingPrivateKeyIv;
    private String signingPrivateKeyCiphertext;

    /** Required by Gson. */
    private UsuarioMaestro() {
    }

    /**
     * Registers a new master user: derives the master key, computes the ZKP
     * verifier, generates KEM/signing key pairs and stores their private keys
     * encrypted under the KEK.
     *
     * @param nombreDeUsuario public user name
     * @param masterPassword  master password (wiped by the caller)
     * @return the new metadata object
     * @throws GeneralSecurityException if key generation or encryption fails
     */
    public static UsuarioMaestro create(String nombreDeUsuario, char[] masterPassword)
            throws GeneralSecurityException {
        Objects.requireNonNull(nombreDeUsuario, "nombreDeUsuario");
        Objects.requireNonNull(masterPassword, "masterPassword");
        if (masterPassword.length == 0) {
            throw new IllegalArgumentException("masterPassword must not be empty");
        }

        byte[] saltBytes = Argon2KDF.generateSalt();
        byte[] master = null;
        byte[] kek = null;
        byte[] seed = null;
        try {
            master = Argon2KDF.deriveKey(masterPassword, saltBytes, MASTER_KEY_LENGTH_BYTES);
            kek = Arrays.copyOfRange(master, 0, KEK_LENGTH_BYTES);
            seed = Arrays.copyOfRange(master, KEK_LENGTH_BYTES, MASTER_KEY_LENGTH_BYTES);

            BigInteger secret = SchnorrZKP.secretFromSeed(seed);
            BigInteger verifierValue = SchnorrZKP.computeVerifier(secret);

            KeyPair kem = KeyEncapsulator.generateKeyPair();
            KeyPair signing = DigitalSigner.generateKeyPair();

            EncryptedKey encryptedKem = encryptPrivateKey(kem.getPrivate(), kek);
            EncryptedKey encryptedSigning = encryptPrivateKey(signing.getPrivate(), kek);

            UsuarioMaestro usuario = new UsuarioMaestro();
            usuario.nombreDeUsuario = nombreDeUsuario;
            usuario.salt = b64(saltBytes);
            usuario.verifier = b64(verifierValue.toByteArray());
            usuario.kemPublicKey = b64(kem.getPublic().getEncoded());
            usuario.kemPrivateKeyIv = encryptedKem.iv();
            usuario.kemPrivateKeyCiphertext = encryptedKem.ciphertext();
            usuario.signingPublicKey = b64(signing.getPublic().getEncoded());
            usuario.signingPrivateKeyIv = encryptedSigning.iv();
            usuario.signingPrivateKeyCiphertext = encryptedSigning.ciphertext();
            return usuario;
        } finally {
            SecretWiper.wipe(master);
            SecretWiper.wipe(kek);
            SecretWiper.wipe(seed);
            SecretWiper.wipe(saltBytes);
        }
    }

    /**
     * Re-encrypts the existing private keys under a new master password and
     * produces fresh metadata (new salt and verifier) while keeping the same
     * public keys. The credentials blob is untouched by this operation.
     *
     * @param newPassword       new master password (wiped by the caller)
     * @param kemPrivateKey     existing KEM private key
     * @param signingPrivateKey existing Ed25519 private key
     * @return new metadata for the same key pairs
     * @throws GeneralSecurityException if re-encryption fails
     */
    public UsuarioMaestro reencrypt(char[] newPassword, PrivateKey kemPrivateKey,
                                    PrivateKey signingPrivateKey) throws GeneralSecurityException {
        Objects.requireNonNull(newPassword, "newPassword");
        Objects.requireNonNull(kemPrivateKey, "kemPrivateKey");
        Objects.requireNonNull(signingPrivateKey, "signingPrivateKey");
        if (newPassword.length == 0) {
            throw new IllegalArgumentException("newPassword must not be empty");
        }

        byte[] saltBytes = Argon2KDF.generateSalt();
        byte[] master = null;
        byte[] kek = null;
        byte[] seed = null;
        try {
            master = Argon2KDF.deriveKey(newPassword, saltBytes, MASTER_KEY_LENGTH_BYTES);
            kek = Arrays.copyOfRange(master, 0, KEK_LENGTH_BYTES);
            seed = Arrays.copyOfRange(master, KEK_LENGTH_BYTES, MASTER_KEY_LENGTH_BYTES);

            BigInteger secret = SchnorrZKP.secretFromSeed(seed);
            BigInteger verifierValue = SchnorrZKP.computeVerifier(secret);

            EncryptedKey encryptedKem = encryptPrivateKey(kemPrivateKey, kek);
            EncryptedKey encryptedSigning = encryptPrivateKey(signingPrivateKey, kek);

            UsuarioMaestro nuevo = new UsuarioMaestro();
            nuevo.nombreDeUsuario = this.nombreDeUsuario;
            nuevo.salt = b64(saltBytes);
            nuevo.verifier = b64(verifierValue.toByteArray());
            nuevo.kemPublicKey = this.kemPublicKey;
            nuevo.kemPrivateKeyIv = encryptedKem.iv();
            nuevo.kemPrivateKeyCiphertext = encryptedKem.ciphertext();
            nuevo.signingPublicKey = this.signingPublicKey;
            nuevo.signingPrivateKeyIv = encryptedSigning.iv();
            nuevo.signingPrivateKeyCiphertext = encryptedSigning.ciphertext();
            return nuevo;
        } finally {
            SecretWiper.wipe(master);
            SecretWiper.wipe(kek);
            SecretWiper.wipe(seed);
            SecretWiper.wipe(saltBytes);
        }
    }

    /**
     * Runs the 3-step Schnorr protocol against the stored verifier. A wrong
     * password yields a wrong secret and the proof fails; no hash comparison is
     * performed.
     *
     * @param masterPassword candidate master password (wiped by the caller)
     * @return {@code true} if the proof verifies
     */
    public boolean authenticate(char[] masterPassword) {
        byte[] master = Argon2KDF.deriveKey(masterPassword, getSalt(), MASTER_KEY_LENGTH_BYTES);
        try {
            BigInteger secret = secretFromMaster(master);
            SchnorrZKP.ProverSession prover = SchnorrZKP.startProver(secret);
            BigInteger commitment = prover.commitment();
            BigInteger challenge = SchnorrZKP.generateChallenge();
            BigInteger response = prover.respond(challenge);
            return SchnorrZKP.verify(commitment, getVerifier(), challenge, response);
        } finally {
            SecretWiper.wipe(master);
        }
    }

    /**
     * Authenticates the password with the ZKP and, only on success, decrypts
     * the KEM and Ed25519 private keys with the KEK.
     *
     * @param masterPassword master password (wiped by the caller)
     * @return the decrypted private keys
     * @throws SecurityException          if the ZKP fails (wrong password)
     * @throws GeneralSecurityException   if private-key decryption fails
     */
    public UnlockedKeys unlock(char[] masterPassword) throws GeneralSecurityException {
        byte[] master = Argon2KDF.deriveKey(masterPassword, getSalt(), MASTER_KEY_LENGTH_BYTES);
        byte[] kek = Arrays.copyOfRange(master, 0, KEK_LENGTH_BYTES);
        try {
            BigInteger secret = secretFromMaster(master);
            SchnorrZKP.ProverSession prover = SchnorrZKP.startProver(secret);
            BigInteger commitment = prover.commitment();
            BigInteger challenge = SchnorrZKP.generateChallenge();
            BigInteger response = prover.respond(challenge);
            if (!SchnorrZKP.verify(commitment, getVerifier(), challenge, response)) {
                throw new SecurityException("Invalid master password");
            }

            PrivateKey kemPrivateKey = null;
            try {
                kemPrivateKey = decryptPrivateKey(
                        kemPrivateKeyIv, kemPrivateKeyCiphertext, kek, "RSA");
                PrivateKey signingPrivateKey = decryptPrivateKey(
                        signingPrivateKeyIv, signingPrivateKeyCiphertext, kek, "Ed25519");
                return new UnlockedKeys(kemPrivateKey, signingPrivateKey);
            } catch (GeneralSecurityException | RuntimeException e) {
                SecretWiper.destroy(kemPrivateKey);
                throw e;
            }
        } finally {
            SecretWiper.wipe(master);
            SecretWiper.wipe(kek);
        }
    }

    public byte[] getSalt() {
        return Base64.getDecoder().decode(salt);
    }

    public BigInteger getVerifier() {
        return new BigInteger(1, Base64.getDecoder().decode(verifier));
    }

    public PublicKey getKemPublicKey() throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(kemPublicKey)));
    }

    public PublicKey getSigningPublicKey() throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(signingPublicKey)));
    }

    public String getKemPrivateKeyIv() {
        return kemPrivateKeyIv;
    }

    public String getKemPrivateKeyCiphertext() {
        return kemPrivateKeyCiphertext;
    }

    public String getSigningPrivateKeyIv() {
        return signingPrivateKeyIv;
    }

    public String getSigningPrivateKeyCiphertext() {
        return signingPrivateKeyCiphertext;
    }

    private static BigInteger secretFromMaster(byte[] master) {
        byte[] seed = Arrays.copyOfRange(master, KEK_LENGTH_BYTES, MASTER_KEY_LENGTH_BYTES);
        try {
            return SchnorrZKP.secretFromSeed(seed);
        } finally {
            SecretWiper.wipe(seed);
        }
    }

    private static EncryptedKey encryptPrivateKey(PrivateKey privateKey, byte[] kek)
            throws GeneralSecurityException {
        byte[] encoded = privateKey.getEncoded();
        SecretKey kekKey = new SecretKeySpec(kek, "AES");
        try {
            VaultCipher.SealedData sealed = VaultCipher.encrypt(encoded, kekKey);
            return new EncryptedKey(b64(sealed.iv()), b64(sealed.ciphertext()));
        } finally {
            SecretWiper.wipe(encoded);
            SecretWiper.destroy(kekKey);
        }
    }

    private static PrivateKey decryptPrivateKey(String iv, String ciphertext,
                                                byte[] kek, String algorithm)
            throws GeneralSecurityException {
        SecretKey kekKey = new SecretKeySpec(kek, "AES");
        byte[] pkcs8 = null;
        try {
            VaultCipher.SealedData sealed = new VaultCipher.SealedData(
                    Base64.getDecoder().decode(iv),
                    Base64.getDecoder().decode(ciphertext));
            pkcs8 = VaultCipher.decrypt(sealed, kekKey);
            return KeyFactory.getInstance(algorithm)
                    .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } finally {
            SecretWiper.wipe(pkcs8);
            SecretWiper.destroy(kekKey);
        }
    }

    private static String b64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    /** Decrypted private keys for an active session. */
    public record UnlockedKeys(PrivateKey kemPrivateKey, PrivateKey signingPrivateKey) {
    }

    private record EncryptedKey(String iv, String ciphertext) {
    }
}

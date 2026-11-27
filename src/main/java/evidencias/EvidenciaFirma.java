package evidencias;

import crypto.DigitalSigner;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import util.SecretWiper;

/**
 * IND2 standalone evidence: Ed25519 detached signatures.
 *
 * <p>Run with:</p>
 * <pre>{@code mvn exec:java -Dexec.mainClass=evidencias.EvidenciaFirma}</pre>
 *
 * <p>The key pair is derived from the RFC 8032 TEST 1 seed, so the public key,
 * the known-answer signature and the demo signature are byte-for-byte
 * reproducible across runs.</p>
 */
public final class EvidenciaFirma {

    private static final HexFormat HEX = HexFormat.of();

    // RFC 8032, Section 7.1, TEST 1 (deterministic test vector).
    private static final String RFC_SEED_HEX =
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    private static final String RFC_PUBLIC_HEX =
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    private static final String RFC_SIGNATURE_HEX =
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                    + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    private EvidenciaFirma() {
        throw new AssertionError("No instances.");
    }

    public static void main(String[] args) {
        boolean ok = run();
        System.out.println();
        System.out.println("[RESULT] " + (ok ? "PASS" : "FAIL"));
        if (!ok) {
            System.exit(1);
        }
    }

    static boolean run() {
        section("IND2 - Digital Signature (Ed25519)");

        byte[] seed = HEX.parseHex(RFC_SEED_HEX);
        System.out.println("[INPUT]  RFC 8032 TEST 1 seed (32 bytes): " + RFC_SEED_HEX);

        PrivateKey privateKey = null;
        byte[] signature = null;
        try {
            Ed25519PrivateKeyParameters privateParams =
                    new Ed25519PrivateKeyParameters(seed, 0);
            Ed25519PublicKeyParameters publicParams = privateParams.generatePublicKey();

            byte[] rawPublic = SubjectPublicKeyInfoFactory
                    .createSubjectPublicKeyInfo(publicParams)
                    .getPublicKeyData()
                    .getBytes();
            String publicHex = HEX.formatHex(rawPublic);
            System.out.println("[OUTPUT] Derived public key (32 bytes): " + publicHex);
            verify("Derived public key matches RFC 8032", publicHex.equals(RFC_PUBLIC_HEX));

            KeyFactory keyFactory = KeyFactory.getInstance(DigitalSigner.ALGORITHM);
            privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(
                    PrivateKeyInfoFactory.createPrivateKeyInfo(privateParams).getEncoded()));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicParams)
                            .getEncoded()));

            // Known-answer test: Ed25519 is deterministic.
            byte[] empty = new byte[0];
            String katSignature = HEX.formatHex(DigitalSigner.sign(empty, privateKey));
            System.out.println("[OUTPUT] RFC 8032 signature (empty message): " + katSignature);
            boolean katOk = katSignature.equals(RFC_SIGNATURE_HEX);
            verify("Signature matches RFC 8032 vector", katOk);

            // Demo vault payload.
            byte[] message = "boveda.json|usuario=alice|credenciales=2"
                    .getBytes(StandardCharsets.UTF_8);
            signature = DigitalSigner.sign(message, privateKey);
            System.out.println("[INPUT]  Message: "
                    + new String(message, StandardCharsets.UTF_8));
            System.out.println("[OUTPUT] Signature (64 bytes): " + HEX.formatHex(signature));
            System.out.println("[OUTPUT] Signature SHA-256: " + fingerprint(signature));

            boolean verifyOk = DigitalSigner.verify(message, signature, publicKey);
            verify("Valid signature accepted", verifyOk);

            byte[] tamperedSignature = signature.clone();
            tamperedSignature[0] ^= 0x01;
            boolean tamperedRejected =
                    !DigitalSigner.verify(message, tamperedSignature, publicKey);
            verify("One-byte signature tampering rejected", tamperedRejected);

            byte[] otherMessage = "boveda.json|usuario=mallory|credenciales=2"
                    .getBytes(StandardCharsets.UTF_8);
            boolean wrongMessageRejected =
                    !DigitalSigner.verify(otherMessage, signature, publicKey);
            verify("Different message rejected", wrongMessageRejected);

            Arrays.fill(tamperedSignature, (byte) 0);
            Arrays.fill(otherMessage, (byte) 0);
            Arrays.fill(message, (byte) 0);

            return katOk && verifyOk && tamperedRejected && wrongMessageRejected;
        } catch (GeneralSecurityException | IOException e) {
            System.out.println("[ERROR]  " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
            return false;
        } finally {
            SecretWiper.wipe(seed);
            SecretWiper.wipe(signature);
            SecretWiper.destroy(privateKey);
        }
    }

    private static String fingerprint(byte[] value) {
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void verify(String label, boolean passed) {
        System.out.println("[VERIFY] " + label + ": " + (passed ? "PASS" : "FAIL"));
    }

    private static void section(String title) {
        System.out.println("============================================================");
        System.out.println(" " + title);
        System.out.println("============================================================");
    }
}

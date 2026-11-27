package evidencias;

import crypto.KeyEncapsulator;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import util.SecretWiper;

/**
 * IND1 standalone evidence: RSA-OAEP-SHA256 key encapsulation.
 *
 * <p>Run with:</p>
 * <pre>{@code mvn exec:java -Dexec.mainClass=evidencias.EvidenciaKEM}</pre>
 *
 * <p>The printed DEK is a fixed demo value, so its fingerprints and every
 * PASS/FAIL line are reproducible. The RSA key pair and the OAEP ciphertext
 * are intentionally random and only their sizes are printed.</p>
 */
public final class EvidenciaKEM {

    private static final HexFormat HEX = HexFormat.of();

    private EvidenciaKEM() {
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
        section("IND1 - KEM (RSA-OAEP-SHA256)");

        // Fixed 256-bit demo DEK (0x00..0x1f) so the printed values are stable.
        byte[] dekBytes = new byte[32];
        for (int i = 0; i < dekBytes.length; i++) {
            dekBytes[i] = (byte) i;
        }
        System.out.println("[INPUT]  DEK (32 bytes): " + HEX.formatHex(dekBytes));
        System.out.println("[INPUT]  DEK SHA-256:    " + fingerprint(dekBytes));

        SecretKey dek = new SecretKeySpec(dekBytes, "AES");
        byte[] wrapped = null;
        byte[] recovered = null;
        KeyPair unrelated = null;
        try {
            KeyPair keyPair = KeyEncapsulator.generateKeyPair();
            System.out.println("[OUTPUT] KEM key pair: RSA / "
                    + KeyEncapsulator.RSA_KEY_SIZE_BITS + "-bit modulus");
            System.out.println("[OUTPUT] OAEP: SHA-256 digest, MGF1-SHA256");

            wrapped = KeyEncapsulator.encapsulate(dek, keyPair.getPublic());
            final byte[] encapsulated = wrapped;
            System.out.println("[OUTPUT] Encapsulated DEK length: " + wrapped.length
                    + " bytes (OAEP randomness makes the bytes differ per run)");

            SecretKey unwrapped = KeyEncapsulator.decapsulate(wrapped, keyPair.getPrivate());
            try {
                recovered = unwrapped.getEncoded();
            } finally {
                SecretWiper.destroy(unwrapped);
            }
            System.out.println("[OUTPUT] Recovered DEK: " + HEX.formatHex(recovered));

            boolean roundTrip = MessageDigest.isEqual(dekBytes, recovered);
            verify("Recovered DEK equals input DEK", roundTrip);

            byte[] tampered = wrapped.clone();
            tampered[tampered.length - 1] ^= 0x01;
            boolean tamperedRejected = fails(() ->
                    KeyEncapsulator.decapsulate(tampered, keyPair.getPrivate()));
            Arrays.fill(tampered, (byte) 0);
            verify("Tampered encapsulation rejected", tamperedRejected);

            unrelated = KeyEncapsulator.generateKeyPair();
            final KeyPair unrelatedKey = unrelated;
            boolean wrongKeyRejected = fails(() ->
                    KeyEncapsulator.decapsulate(encapsulated, unrelatedKey.getPrivate()));
            verify("Unrelated private key rejected", wrongKeyRejected);

            return roundTrip && tamperedRejected && wrongKeyRejected;
        } catch (GeneralSecurityException e) {
            System.out.println("[ERROR]  " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
            return false;
        } finally {
            SecretWiper.wipe(dekBytes);
            SecretWiper.wipe(wrapped);
            SecretWiper.wipe(recovered);
            SecretWiper.destroy(dek);
            if (unrelated != null) {
                SecretWiper.destroy(unrelated.getPrivate());
            }
        }
    }

    private static boolean fails(ThrowingRunnable action) {
        try {
            action.run();
            return false;
        } catch (GeneralSecurityException e) {
            return true;
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

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws GeneralSecurityException;
    }
}

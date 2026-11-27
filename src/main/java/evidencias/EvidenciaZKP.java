package evidencias;

import crypto.SchnorrZKP;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import util.SecretWiper;

/**
 * IND3 standalone evidence: interactive Schnorr zero-knowledge proof.
 *
 * <p>Run with:</p>
 * <pre>{@code mvn exec:java -Dexec.mainClass=evidencias.EvidenciaZKP}</pre>
 *
 * <p>The password and salt are fixed demo values, so the derived-secret and
 * verifier fingerprints are reproducible. The prover nonce and challenge are
 * fresh per run; their values are not printed.</p>
 */
public final class EvidenciaZKP {

    private static final HexFormat HEX = HexFormat.of();
    private static final String DEMO_PASSWORD = "demo-master-password";
    private static final String WRONG_PASSWORD = "wrong-demo-password";

    private EvidenciaZKP() {
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
        section("IND3 - Schnorr Zero-Knowledge Proof (IND3)");

        byte[] salt = new byte[16];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) i;
        }
        char[] password = DEMO_PASSWORD.toCharArray();
        char[] wrongPassword = WRONG_PASSWORD.toCharArray();

        System.out.println("[INPUT]  Group: RFC 3526 Group 14 (p 2048 bits, q 2047 bits, g=2)");
        System.out.println("[INPUT]  Password (fixed demo value): \"" + DEMO_PASSWORD + "\"");
        System.out.println("[INPUT]  Salt (16 bytes): " + HEX.formatHex(salt));

        try {
            // Registration: x = Argon2id(password, salt), Y = g^x mod p.
            BigInteger secret = SchnorrZKP.deriveSecret(password, salt);
            BigInteger verifier = SchnorrZKP.computeVerifier(secret);
            System.out.println("[OUTPUT] Secret x SHA-256:   " + fingerprint(secret.toByteArray()));
            System.out.println("[OUTPUT] Verifier Y SHA-256: " + fingerprint(verifier.toByteArray()));

            boolean subgroupOk = verifier.modPow(SchnorrZKP.Q, SchnorrZKP.P)
                    .equals(BigInteger.ONE);
            verify("Verifier is in the order-q subgroup", subgroupOk);

            boolean registrationOk = SchnorrZKP.registerVerifier(password, salt)
                    .equals(verifier);
            verify("Registration is deterministic", registrationOk);

            // Three-step proof: commitment R, challenge c, response s.
            SchnorrZKP.ProverSession prover = SchnorrZKP.startProver(secret);
            BigInteger commitment = prover.commitment();
            BigInteger challenge = SchnorrZKP.generateChallenge();
            BigInteger response = prover.respond(challenge);
            System.out.println("[OUTPUT] Commitment R, challenge c and response s generated "
                    + "(random nonce; values vary per run)");
            boolean proofOk = SchnorrZKP.verify(commitment, verifier, challenge, response);
            verify("Valid proof accepted", proofOk);

            // Impersonation: a different password yields a different secret.
            BigInteger attackerSecret = SchnorrZKP.deriveSecret(wrongPassword, salt);
            SchnorrZKP.ProverSession attacker = SchnorrZKP.startProver(attackerSecret);
            BigInteger attackerCommitment = attacker.commitment();
            BigInteger attackerChallenge = SchnorrZKP.generateChallenge();
            BigInteger attackerResponse = attacker.respond(attackerChallenge);
            boolean impersonationRejected = !SchnorrZKP.verify(
                    attackerCommitment, verifier, attackerChallenge, attackerResponse);
            verify("Impersonation with wrong password rejected", impersonationRejected);

            // Tampered response for an otherwise valid transcript.
            BigInteger tamperedResponse = response.add(BigInteger.ONE).mod(SchnorrZKP.Q);
            boolean tamperedRejected = !SchnorrZKP.verify(
                    commitment, verifier, challenge, tamperedResponse);
            verify("Tampered response rejected", tamperedRejected);

            return subgroupOk && registrationOk && proofOk
                    && impersonationRejected && tamperedRejected;
        } catch (RuntimeException e) {
            System.out.println("[ERROR]  " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
            return false;
        } finally {
            SecretWiper.wipe(salt);
            SecretWiper.wipe(password);
            SecretWiper.wipe(wrongPassword);
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

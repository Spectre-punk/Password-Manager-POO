package crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class SchnorrZKPTest {

    @Test
    void usesAValid2048BitSafePrimeGroup() {
        assertEquals(2048, SchnorrZKP.P.bitLength());
        assertTrue(SchnorrZKP.P.isProbablePrime(64), "p must be prime");
        assertTrue(SchnorrZKP.Q.isProbablePrime(64), "q = (p - 1) / 2 must be prime");
        assertEquals(SchnorrZKP.P.subtract(BigInteger.ONE).shiftRight(1), SchnorrZKP.Q);
        assertEquals(BigInteger.ONE, SchnorrZKP.G.modPow(SchnorrZKP.Q, SchnorrZKP.P),
                "g must generate the order-q subgroup");
    }

    @Test
    void derivesDeterministicSecretFromPassword() {
        byte[] salt = Argon2KDF.generateSalt();
        char[] password = "master-password".toCharArray();
        try {
            BigInteger first = SchnorrZKP.deriveSecret(password, salt);
            BigInteger second = SchnorrZKP.deriveSecret(password, salt);

            assertEquals(first, second);
            assertTrue(first.signum() > 0);
            assertTrue(first.compareTo(SchnorrZKP.Q) < 0);
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(salt, (byte) 0);
        }
    }

    @Test
    void completesInteractiveProof() {
        BigInteger secret = new BigInteger("1234567890abcdef1234567890abcdef", 16)
                .mod(SchnorrZKP.Q);
        if (secret.signum() == 0) {
            secret = BigInteger.ONE;
        }
        BigInteger verifier = SchnorrZKP.computeVerifier(secret);

        SchnorrZKP.ProverSession prover = SchnorrZKP.startProver(secret);
        BigInteger commitment = prover.commitment();
        BigInteger challenge = SchnorrZKP.generateChallenge();
        BigInteger response = prover.respond(challenge);

        assertTrue(SchnorrZKP.verify(commitment, verifier, challenge, response));
    }

    @Test
    void rejectsWrongChallenge() {
        BigInteger secret = BigInteger.valueOf(42);
        BigInteger verifier = SchnorrZKP.computeVerifier(secret);
        SchnorrZKP.ProverSession prover = SchnorrZKP.startProver(secret);

        BigInteger commitment = prover.commitment();
        BigInteger challenge = SchnorrZKP.generateChallenge();
        BigInteger response = prover.respond(challenge);
        BigInteger wrongChallenge = challenge.add(BigInteger.ONE).mod(SchnorrZKP.Q);

        assertFalse(SchnorrZKP.verify(commitment, verifier, wrongChallenge, response));
    }

    @Test
    void rejectsTamperedResponse() {
        BigInteger secret = BigInteger.valueOf(7);
        BigInteger verifier = SchnorrZKP.computeVerifier(secret);
        SchnorrZKP.ProverSession prover = SchnorrZKP.startProver(secret);

        BigInteger commitment = prover.commitment();
        BigInteger challenge = SchnorrZKP.generateChallenge();
        BigInteger response = prover.respond(challenge);
        BigInteger wrongResponse = response.add(BigInteger.ONE).mod(SchnorrZKP.Q);

        assertFalse(SchnorrZKP.verify(commitment, verifier, challenge, wrongResponse));
    }

    @Test
    void rejectsVerifierOutsideSubgroup() {
        BigInteger secret = BigInteger.valueOf(11);
        SchnorrZKP.ProverSession prover = SchnorrZKP.startProver(secret);
        BigInteger commitment = prover.commitment();
        BigInteger challenge = SchnorrZKP.generateChallenge();
        BigInteger response = prover.respond(challenge);

        BigInteger notInSubgroup = SchnorrZKP.P.subtract(BigInteger.ONE);
        assertFalse(SchnorrZKP.verify(commitment, notInSubgroup, challenge, response));
        assertFalse(SchnorrZKP.verify(commitment, BigInteger.ZERO, challenge, response));
    }

    @Test
    void proverSessionIsOneShot() {
        SchnorrZKP.ProverSession prover = SchnorrZKP.startProver(BigInteger.valueOf(3));
        BigInteger challenge = SchnorrZKP.generateChallenge();
        prover.respond(challenge);

        assertThrows(IllegalStateException.class, () -> prover.respond(challenge));
    }

    @Test
    void rejectsOutOfRangeInputs() {
        assertThrows(IllegalArgumentException.class,
                () -> SchnorrZKP.startProver(BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> SchnorrZKP.computeVerifier(SchnorrZKP.Q));

        SchnorrZKP.ProverSession prover = SchnorrZKP.startProver(BigInteger.ONE);
        assertThrows(IllegalArgumentException.class,
                () -> prover.respond(SchnorrZKP.Q));
    }
}

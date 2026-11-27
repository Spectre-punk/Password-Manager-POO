package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Interactive Schnorr zero-knowledge proof of knowledge (IND3) over the
 * 2048-bit RFC 3526 MODP group (Group 14), using {@code BigInteger}.
 *
 * <p>The group uses the safe prime {@code p} from RFC 3526, generator
 * {@code g = 2} and prime-order subgroup {@code q = (p - 1) / 2}.</p>
 *
 * <p><strong>Registration:</strong> derive the secret {@code x} from the master
 * password with {@link #deriveSecret(char[], byte[])} and publish the verifier
 * {@code Y = g^x mod p} from {@link #computeVerifier(BigInteger)}.</p>
 *
 * <p><strong>Authentication (3 steps):</strong></p>
 * <ol>
 *   <li>Prover sends commitment {@code R = g^r mod p}.</li>
 *   <li>Verifier sends a random challenge {@code c}.</li>
 *   <li>Prover sends {@code s = (r + c * x) mod q}; verifier checks
 *       {@code g^s ≡ R * Y^c (mod p)}.</li>
 * </ol>
 *
 * <p>The master password is accepted as {@code char[]} only. Callers must wipe
 * their password buffer after use.</p>
 */
public final class SchnorrZKP {

    /**
     * RFC 3526 2048-bit MODP Group (Group 14) safe prime.
     */
    public static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
                    + "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
                    + "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
                    + "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
                    + "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
                    + "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
            16);

    /** Prime-order subgroup order: {@code q = (p - 1) / 2}. */
    public static final BigInteger Q = P.subtract(BigInteger.ONE).shiftRight(1);

    /** Generator of the prime-order subgroup. */
    public static final BigInteger G = BigInteger.TWO;

    private static final SecureRandom RANDOM = new SecureRandom();

    private SchnorrZKP() {
        throw new AssertionError("No instances.");
    }

    /**
     * Derives the Schnorr secret {@code x} from the master password using
     * Argon2id, reduced into {@code [1, q - 1]}.
     *
     * @param masterPassword master password (wiped by the caller)
     * @param salt           16-byte Argon2id salt
     * @return the secret exponent {@code x}
     */
    public static BigInteger deriveSecret(char[] masterPassword, byte[] salt) {
        byte[] key = Argon2KDF.deriveKey(masterPassword, salt);
        try {
            BigInteger secret = new BigInteger(1, key).mod(Q);
            return secret.signum() == 0 ? BigInteger.ONE : secret;
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Computes the public verifier {@code Y = g^x mod p}.
     *
     * @param secret secret exponent in {@code [1, q - 1]}
     * @return the public verifier
     */
    public static BigInteger computeVerifier(BigInteger secret) {
        requireInRange(secret, BigInteger.ONE, Q.subtract(BigInteger.ONE), "secret");
        return G.modPow(secret, P);
    }

    /**
     * Registration convenience: derives {@code x} from the password and returns
     * the public verifier {@code Y}. The derived secret is discarded.
     *
     * @param masterPassword master password (wiped by the caller)
     * @param salt           16-byte Argon2id salt
     * @return the public verifier to store
     */
    public static BigInteger registerVerifier(char[] masterPassword, byte[] salt) {
        return computeVerifier(deriveSecret(masterPassword, salt));
    }

    /**
     * Starts a prover session by sampling the nonce {@code r} and computing the
     * commitment {@code R = g^r mod p}.
     *
     * @param secret secret exponent {@code x} in {@code [1, q - 1]}
     * @return a one-shot prover session
     */
    public static ProverSession startProver(BigInteger secret) {
        requireInRange(secret, BigInteger.ONE, Q.subtract(BigInteger.ONE), "secret");
        return new ProverSession(secret);
    }

    /**
     * Generates a random challenge {@code c} in {@code [1, q - 1]}.
     *
     * @return a fresh challenge
     */
    public static BigInteger generateChallenge() {
        return randomInRange(BigInteger.ONE, Q.subtract(BigInteger.ONE));
    }

    /**
     * Verifies a Schnorr transcript: {@code g^s ≡ R * Y^c (mod p)}.
     *
     * <p>Also rejects commitments/verifiers outside the prime-order subgroup and
     * values outside their valid ranges.</p>
     *
     * @param commitment {@code R}
     * @param verifier   {@code Y}
     * @param challenge  {@code c}
     * @param response   {@code s}
     * @return {@code true} if the proof is valid
     */
    public static boolean verify(BigInteger commitment, BigInteger verifier,
                                 BigInteger challenge, BigInteger response) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(verifier, "verifier");
        Objects.requireNonNull(challenge, "challenge");
        Objects.requireNonNull(response, "response");

        if (commitment.signum() <= 0 || commitment.compareTo(P) >= 0) {
            return false;
        }
        if (verifier.signum() <= 0 || verifier.compareTo(P) >= 0) {
            return false;
        }
        if (challenge.signum() < 0 || challenge.compareTo(Q) >= 0) {
            return false;
        }
        if (response.signum() < 0 || response.compareTo(Q) >= 0) {
            return false;
        }
        if (!commitment.modPow(Q, P).equals(BigInteger.ONE)
                || !verifier.modPow(Q, P).equals(BigInteger.ONE)) {
            return false;
        }

        BigInteger left = G.modPow(response, P);
        BigInteger right = commitment.multiply(verifier.modPow(challenge, P)).mod(P);
        return MessageDigest.isEqual(left.toByteArray(), right.toByteArray());
    }

    /**
     * One-shot prover session holding the secret and the nonce for a single
     * Schnorr exchange.
     */
    public static final class ProverSession {

        private final BigInteger secret;
        private final BigInteger nonce;
        private final BigInteger commitment;
        private boolean consumed;

        private ProverSession(BigInteger secret) {
            this.secret = secret;
            this.nonce = randomInRange(BigInteger.ONE, Q.subtract(BigInteger.ONE));
            this.commitment = G.modPow(nonce, P);
        }

        /**
         * @return the commitment {@code R = g^r mod p} to send first
         */
        public BigInteger commitment() {
            return commitment;
        }

        /**
         * Computes the response {@code s = (r + c * x) mod q}. A session may be
         * answered only once to prevent nonce reuse.
         *
         * @param challenge verifier challenge in {@code [0, q)}
         * @return the response {@code s}
         * @throws IllegalArgumentException if the challenge is out of range
         * @throws IllegalStateException    if the session was already used
         */
        public BigInteger respond(BigInteger challenge) {
            Objects.requireNonNull(challenge, "challenge");
            if (challenge.signum() < 0 || challenge.compareTo(Q) >= 0) {
                throw new IllegalArgumentException("challenge must be in [0, q)");
            }
            if (consumed) {
                throw new IllegalStateException("prover session already used");
            }
            consumed = true;
            return nonce.add(challenge.multiply(secret)).mod(Q);
        }
    }

    private static BigInteger randomInRange(BigInteger min, BigInteger max) {
        BigInteger range = max.subtract(min).add(BigInteger.ONE);
        int bits = range.bitLength();
        BigInteger candidate;
        do {
            candidate = new BigInteger(bits, RANDOM);
        } while (candidate.compareTo(range) >= 0);
        return candidate.add(min);
    }

    private static void requireInRange(BigInteger value, BigInteger min, BigInteger max, String name) {
        Objects.requireNonNull(value, name);
        if (value.compareTo(min) < 0 || value.compareTo(max) > 0) {
            throw new IllegalArgumentException(name + " must be in the valid range");
        }
    }
}

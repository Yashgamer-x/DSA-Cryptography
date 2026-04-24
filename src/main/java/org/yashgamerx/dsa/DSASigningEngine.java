package org.yashgamerx.dsa;

import java.math.BigInteger;
import java.util.Objects;

/**
 * DSASigningEngine.java <br>
 *
 * Stateless service that computes a DSA signature for a given message hash. <br><br>
 *
 * DSA Signing Algorithm <br>
 * ---------------------- <br>
 * Given domain parameters (p, q, g), private key x, nonce k, <br>
 * and message hash H(M): <br><br>
 *
 *   r = (g^k mod p) mod q <br>
 *   s = k^-1 * (H(M) + x*r) mod q <br><br>
 *
 * Signature = (r, s) <br>
 *
 * Degenerate Cases <br>
 * ---------------- <br>
 * The algorithm can produce a degenerate (unusable) signature if: <br>
 *   - r == 0  : g^k happened to be a multiple of q (extremely rare in practice) <br>
 *   - s == 0  : H(M) + x*r ≡ 0 (mod q) <br><br>
 *
 * In either case {@link #sign} returns {@code null} to signal the failure.
 * The caller must handle this: in real implementations, a new random k is
 * chosen and signing is retried. In this homework the inputs are fixed, so
 * the degenerate case is reported and steps 3-4 are skipped.
 */
public final class DSASigningEngine {

    private DSASigningEngine() {}

    /**
     * Computes the DSA signature (r, s) for the given message hash.
     *
     * @param params the DSA domain parameters (p, q, g, x, k must all be set)
     * @param messageHash H(M), the hash of the message being signed
     * @return the {@link DSASignature}, or {@code null} if the signature is
     *         degenerate (r == 0 or s == 0)
     * @throws NullPointerException if either argument is null
     */
    public static DSASignature sign(DSAParams params, BigInteger messageHash) {
        Objects.requireNonNull(params,      "params must not be null");
        Objects.requireNonNull(messageHash, "messageHash must not be null");

        BigInteger p = params.p;
        BigInteger q = params.q;
        BigInteger g = params.g;
        BigInteger x = params.x;
        BigInteger k = params.k;

        // ---- Step 1: r = (g^k mod p) mod q ----------------------------------
        BigInteger r = g.modPow(k, p).mod(q);

        // Degenerate: r == 0 means the nonce k was a bad choice.
        if (r.equals(BigInteger.ZERO)) {
            return null;
        }

        // ---- Step 2: s = k^-1 * (H(M) + x*r) mod q -------------------------
        //
        // First compute the numerator H(M) + x*r (mod q).
        // If this is zero, then s = 0 regardless of k^-1, which is degenerate.
        BigInteger numerator = messageHash.add(x.multiply(r)).mod(q);

        if (numerator.equals(BigInteger.ZERO)) {
            return null;
        }

        BigInteger kInverse = k.modInverse(q);
        BigInteger s = kInverse.multiply(numerator).mod(q);

        return new DSASignature(r, s);
    }
}
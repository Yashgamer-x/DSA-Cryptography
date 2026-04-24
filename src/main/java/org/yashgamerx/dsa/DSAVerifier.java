package org.yashgamerx.dsa;

import java.math.BigInteger;
import java.util.Objects;

/**
 * DSAVerifier.java <br><br>
 *
 * Stateless service that verifies a DSA signature against a message hash. <br>
 *
 * DSA Verification Algorithm <br>
 * ---------------------------<br>
 * Given public parameters (p, q, g, y), a signature (r, s), and H(M): <br><br>
 *
 *   w  = s^-1 mod q <br>
 *   u1 = H(M) * w mod q <br>
 *   u2 = r * w mod q <br>
 *   v  = (g^u1 * y^u2 mod p) mod q <br><br>
 *
 * The signature is valid if and only if v == r. <br><br>
 *
 * Security property verified by Step 4 of the homework <br>
 * ------------------------------------------------------ <br>
 * If an attacker (BG) obtains a valid signature (r, s) for H(M1) and tries
 * to use it as a signature for a different message H(M2), the verification
 * must fail. The test suite in {@code DSAVerifierTest} explicitly covers this.
 */
public final class DSAVerifier {

    private DSAVerifier() {}

    /**
     * Verifies the given signature against the given message hash.
     *
     * @param params      the DSA domain parameters (p, q, g, y must all be set)
     * @param signature   the (r, s) pair to check
     * @param messageHash H(M), the hash of the message whose authenticity is claimed
     * @return a {@link DSAVerificationResult} containing all intermediate values
     *         and the final valid/invalid verdict
     * @throws NullPointerException if any argument is null
     */
    public static DSAVerificationResult verify(DSAParams   params,
                                               DSASignature signature,
                                               BigInteger messageHash) {
        Objects.requireNonNull(params,      "params must not be null");
        Objects.requireNonNull(signature,   "signature must not be null");
        Objects.requireNonNull(messageHash, "messageHash must not be null");

        BigInteger p = params.p;
        BigInteger q = params.q;
        BigInteger g = params.g;
        BigInteger y = params.y;
        BigInteger r = signature.r;
        BigInteger s = signature.s;

        // ---- w = s^-1 mod q -------------------------------------------------
        BigInteger w = s.modInverse(q);

        // ---- u1 = H(M) * w mod q --------------------------------------------
        BigInteger u1 = messageHash.multiply(w).mod(q);

        // ---- u2 = r * w mod q -----------------------------------------------
        BigInteger u2 = r.multiply(w).mod(q);

        // ---- v = (g^u1 * y^u2 mod p) mod q ----------------------------------
        //
        // The two modular exponentiations are independent and could be
        // parallelized in a performance-critical context; here clarity wins.
        BigInteger gToU1 = g.modPow(u1, p);
        BigInteger yToU2 = y.modPow(u2, p);
        BigInteger v     = gToU1.multiply(yToU2).mod(p).mod(q);

        // ---- verdict ---------------------------------------------------------
        boolean valid = v.equals(r);

        return new DSAVerificationResult(w, u1, u2, v, valid);
    }
}
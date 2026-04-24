package org.yashgamerx.dsa;

import java.math.BigInteger;
import java.util.Objects;

/**
 * DSAVerificationResult.java <br><br>
 *
 * Immutable value object that captures every intermediate value produced
 * during DSA signature verification, together with the final verdict. <br><br>
 *
 * DSA Verification Algorithm <br>
 * --------------------------- <br>
 * Given public parameters (p, q, g, y), signature (r, s), and H(M): <br><br>
 *
 *   w  = s^-1 mod q <br>
 *   u1 = H(M) * w mod q <br>
 *   u2 = r * w mod q <br>
 *   v  = (g^u1 * y^u2 mod p) mod q <br>
 *
 * The signature is valid if and only if v == r. <br><br>
 *
 * Storing the intermediates w, u1, u2, v as fields (rather than only the
 * boolean result) satisfies the assignment requirement to print all of them,
 * and makes the test suite able to assert each computed value independently.
 */
public final class DSAVerificationResult {

    /** w = s^-1 mod q */
    public final BigInteger w;

    /** u1 = H(M) * w mod q */
    public final BigInteger u1;

    /** u2 = r * w mod q */
    public final BigInteger u2;

    /** v = (g^u1 * y^u2 mod p) mod q */
    public final BigInteger v;

    /** True when v == r; the signature is accepted. */
    public final boolean valid;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /**
     * Constructs a DSAVerificationResult with all intermediate values.
     *
     * @param w     s^-1 mod q
     * @param u1    H(M) * w mod q
     * @param u2    r * w mod q
     * @param v     (g^u1 * y^u2 mod p) mod q
     * @param valid true if v == r
     */
    public DSAVerificationResult(BigInteger w, BigInteger u1, BigInteger u2,
                                 BigInteger v, boolean valid) {
        this.w     = Objects.requireNonNull(w,  "w must not be null");
        this.u1    = Objects.requireNonNull(u1, "u1 must not be null");
        this.u2    = Objects.requireNonNull(u2, "u2 must not be null");
        this.v     = Objects.requireNonNull(v,  "v must not be null");
        this.valid = valid;
    }

    // -------------------------------------------------------------------------
    // Object overrides
    // -------------------------------------------------------------------------

    @Override
    public String toString() {
        return "DSAVerificationResult{w=" + w + ", u1=" + u1
                + ", u2=" + u2 + ", v=" + v + ", valid=" + valid + "}";
    }
}

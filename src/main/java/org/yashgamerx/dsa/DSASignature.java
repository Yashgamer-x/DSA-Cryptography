package org.yashgamerx.dsa;

import java.math.BigInteger;
import java.util.Objects;

/**
 * DSASignature.java <br><br>
 *
 * Immutable value object representing a DSA signature as the pair (r, s). <br><br>
 *
 * In DSA, signing a message hash H(M) with nonce k produces: <br>
 *   r = (g^k mod p) mod q <br>
 *   s = k^-1 * (H(M) + x*r) mod q <br><br>
 *
 * A signature is considered degenerate when r == 0 or s == 0. <br>
 * The {@link DSASigningEngine} returns {@code null} in the degenerate case
 * rather than constructing an invalid {@code DSASignature}.
 */
public final class DSASignature {

    /** First component of the signature. r = (g^k mod p) mod q */
    public final BigInteger r;

    /** Second component of the signature. s = k^-1 * (H(M) + x*r) mod q */
    public final BigInteger s;

    /**
     * Constructs a DSASignature from the given (r, s) pair.
     *
     * @param r the first signature component
     * @param s the second signature component
     * @throws NullPointerException if either r or s is null
     */
    public DSASignature(BigInteger r, BigInteger s) {
        this.r = Objects.requireNonNull(r, "r must not be null");
        this.s = Objects.requireNonNull(s, "s must not be null");
    }

    /**
     * Two signatures are equal when both r and s are equal.
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof DSASignature)) return false;
        DSASignature that = (DSASignature) other;
        return r.equals(that.r) && s.equals(that.s);
    }

    @Override
    public int hashCode() {
        return Objects.hash(r, s);
    }

    @Override
    public String toString() {
        return "DSASignature{r=" + r + ", s=" + s + "}";
    }
}
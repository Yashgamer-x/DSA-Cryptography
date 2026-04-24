package org.yashgamerx.dsa;

import java.math.BigInteger;
import java.util.Objects;

/**
 * DSAParams.java <br>
 *
 * Immutable value object that holds every DSA domain parameter and
 * derives the group generator g and the public key y on construction. <br><br>
 *
 * DSA parameter definitions <br>
 * -------------------------- <br>
 *   p  - a large prime (the group modulus) <br>
 *   q  - a prime that divides (p - 1); the order of the subgroup <br>
 *   h  - a generator candidate, where 1 < h < p <br>
 *   x  - the signer's private key, where 1 <= x <= q-1 <br>
 *   k  - a per-message secret nonce, where 1 <= k <= q-1 <br>
 *   g  - the subgroup generator: h^((p-1)/q) mod p    [derived] <br>
 *   y  - the signer's public key: g^x mod p            [derived] <br>
 *
 * Degenerate-input detection <br>
 * -------------------------- <br><br>
 * The constructor validates that g != 1 (mod p). If g == 1 the chosen h
 * is not a valid generator for the subgroup of order q, and the entire
 * scheme collapses. An {@link IllegalArgumentException} is thrown in that
 * case so callers fail fast with a clear message rather than silently
 * producing wrong signatures.
 */
public final class DSAParams {

    /** Large prime modulus. */
    public final BigInteger p;

    /** Prime divisor of (p - 1); the subgroup order. */
    public final BigInteger q;

    /** Generator candidate supplied by the user. */
    public final BigInteger h;

    /** Signer's private key. */
    public final BigInteger x;

    /** Per-message signing nonce. */
    public final BigInteger k;

    /** Subgroup generator derived as h^((p-1)/q) mod p. */
    public final BigInteger g;

    /** Signer's public key derived as g^x mod p. */
    public final BigInteger y;

    /**
     * Builds DSAParams and derives g and y from the raw inputs.
     *
     * @param p the prime modulus
     * @param q the prime factor of (p - 1)
     * @param h the generator candidate (1 < h < p)
     * @param x the private key (1 <= x <= q-1)
     * @param k the per-message nonce (1 <= k <= q-1)
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if g == 1, meaning h is not a valid generator
     */
    public DSAParams(BigInteger p, BigInteger q, BigInteger h,
                     BigInteger x, BigInteger k) {

        Objects.requireNonNull(p, "p must not be null");
        Objects.requireNonNull(q, "q must not be null");
        Objects.requireNonNull(h, "h must not be null");
        Objects.requireNonNull(x, "x must not be null");
        Objects.requireNonNull(k, "k must not be null");

        this.p = p;
        this.q = q;
        this.h = h;
        this.x = x;
        this.k = k;

        // g = h^((p-1)/q) mod p
        BigInteger exponent = p.subtract(BigInteger.ONE).divide(q);
        this.g = h.modPow(exponent, p);

        // Guard: g == 1 means h was not a valid generator for this subgroup.
        if (this.g.equals(BigInteger.ONE)) {
            throw new IllegalArgumentException(
                    "Derived g == 1: h=" + h + " is not a valid generator for "
                            + "the subgroup of order q=" + q + " mod p=" + p + ".");
        }

        // y = g^x mod p
        this.y = this.g.modPow(x, p);
    }


    /**
     * Convenience factory that accepts primitive {@code long} arguments and
     * wraps them in {@link BigInteger} before delegating to the main constructor.
     *
     * @param p the prime modulus
     * @param q the prime factor of (p - 1)
     * @param h the generator candidate
     * @param x the private key
     * @param k the per-message nonce
     * @return a fully constructed {@code DSAParams} instance
     */
    public static DSAParams of(long p, long q, long h, long x, long k) {
        return new DSAParams(
                BigInteger.valueOf(p),
                BigInteger.valueOf(q),
                BigInteger.valueOf(h),
                BigInteger.valueOf(x),
                BigInteger.valueOf(k)
        );
    }


    @Override
    public String toString() {
        return "DSAParams{p=" + p + ", q=" + q + ", h=" + h
                + ", x=" + x + ", k=" + k + ", g=" + g + ", y=" + y + "}";
    }
}

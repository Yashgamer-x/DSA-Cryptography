package org.yashgamerx.dsa;

import java.math.BigInteger;
import java.util.Objects;

/**
 * DSARunner.java
 *
 * Orchestrates one complete DSA demonstration run across the four steps
 * required by the assignment:
 *
 *   Step 1 - Derive and report g and y.
 *   Step 2 - Sign H(M1); report (r, s).
 *   Step 3 - Verify (r, s) against H(M1) -- expected: VALID.
 *   Step 4 - Verify (r, s) against H(M2) -- expected: INVALID.
 *            This simulates an attacker (BG) attempting to reuse a
 *            legitimate signature for a different message.
 *
 * This class is purely concerned with the computation flow. All console
 * output is delegated to {@link DSAPrinter}, keeping this class testable
 * without any I/O side effects.
 *
 * If the signing step yields a degenerate signature (returned as null by
 * {@link DSASigningEngine}), the run is halted at Step 2 and the result
 * object records the failure.
 */
public final class DSARunner {

    // -------------------------------------------------------------------------
    // Result record
    // -------------------------------------------------------------------------

    /**
     * Captures the outcome of one full DSA run.
     *
     * All fields except {@code params} and {@code label} may be null when the
     * run is cut short by a degenerate signing result.
     */
    public static final class RunResult {

        /** Human-readable label for this test case. */
        public final String label;

        /** Hash of the real message. */
        public final BigInteger realMessageHash;

        /** Hash of the fake message. */
        public final BigInteger fakeMessageHash;

        /** Domain parameters (always populated). */
        public final DSAParams params;

        /**
         * Computed signature, or {@code null} when the signature was degenerate
         * (s == 0 or r == 0).
         */
        public final DSASignature signature;

        /** True when signing produced a degenerate signature. */
        public final boolean degenerateSignature;

        /**
         * Verification result for the real message (null when signing failed).
         */
        public final DSAVerificationResult realVerification;

        /**
         * Verification result for the fake message (null when signing failed).
         */
        public final DSAVerificationResult fakeVerification;

        /** Private constructor -- built only by {@link DSARunner#run}. */
        private RunResult(String label,
                          BigInteger realMessageHash,
                          BigInteger fakeMessageHash,
                          DSAParams params,
                          DSASignature signature,
                          boolean degenerateSignature,
                          DSAVerificationResult realVerification,
                          DSAVerificationResult fakeVerification) {
            this.label               = label;
            this.realMessageHash     = realMessageHash;
            this.fakeMessageHash     = fakeMessageHash;
            this.params              = params;
            this.signature           = signature;
            this.degenerateSignature = degenerateSignature;
            this.realVerification    = realVerification;
            this.fakeVerification    = fakeVerification;
        }
    }

    // -------------------------------------------------------------------------
    // Singleton
    // -------------------------------------------------------------------------

    private DSARunner() {}

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Executes all four DSA steps for the given inputs and returns a
     * {@link RunResult} describing every computed value.
     *
     * The caller decides what to do with the result (print it, assert on it,
     * etc.). No output is produced by this method itself.
     *
     * @param label           display name for this test case
     * @param params          DSA domain parameters (p, q, g, x, k already set)
     * @param realMessageHash H(M1) - the authentic message hash to sign and verify
     * @param fakeMessageHash H(M2) - the forged message hash (must differ from H(M1))
     * @return a populated {@link RunResult}
     * @throws NullPointerException if any argument is null
     */
    public static RunResult run(String     label,
                                DSAParams  params,
                                BigInteger realMessageHash,
                                BigInteger fakeMessageHash) {

        Objects.requireNonNull(label,           "label must not be null");
        Objects.requireNonNull(params,          "params must not be null");
        Objects.requireNonNull(realMessageHash, "realMessageHash must not be null");
        Objects.requireNonNull(fakeMessageHash, "fakeMessageHash must not be null");

        // Step 2: sign H(M1)
        DSASignature signature = DSASigningEngine.sign(params, realMessageHash);

        // Degenerate case -- signing failed; steps 3 and 4 cannot proceed.
        if (signature == null) {
            return new RunResult(
                    label, realMessageHash, fakeMessageHash,
                    params,
                    null,   // no signature
                    true,   // degenerate = true
                    null,   // no real verification
                    null    // no fake verification
            );
        }

        // Step 3: verify (r, s) against H(M1) -- should be VALID
        DSAVerificationResult realVerification =
                DSAVerifier.verify(params, signature, realMessageHash);

        // Step 4: verify (r, s) against H(M2) -- should be INVALID
        DSAVerificationResult fakeVerification =
                DSAVerifier.verify(params, signature, fakeMessageHash);

        return new RunResult(
                label, realMessageHash, fakeMessageHash,
                params,
                signature,
                false,           // not degenerate
                realVerification,
                fakeVerification
        );
    }
}

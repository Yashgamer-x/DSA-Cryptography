package org.yashgamerx.dsa;

/**
 * DSAPrinter.java
 *
 * Responsible for all console output produced during a DSA run.
 *
 * Keeping every System.out call in one class means:
 *   - the computation classes (DSAParams, DSASigningEngine, DSAVerifier,
 *     DSARunner) remain free of I/O and are straightforward to unit-test;
 *   - changing the output format requires edits in exactly one place.
 *
 * The single public entry point is {@link #print(DSARunner.RunResult)},
 * which walks through a completed {@link DSARunner.RunResult} and prints
 * each of the four required steps.
 */
public final class DSAPrinter {

    private static final int SEPARATOR_WIDTH = 65;
    private static final String SEPARATOR    = "=".repeat(SEPARATOR_WIDTH);

    // Singleton -- this class is fully stateless.
    private DSAPrinter() {}

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Prints the full output for one DSA run.
     *
     * @param result a completed {@link DSARunner.RunResult} (must not be null)
     */
    public static void print(DSARunner.RunResult result) {
        printHeader(result);
        printStep1(result);
        printStep2(result);

        // If signing was degenerate, steps 3 and 4 cannot be shown.
        if (result.degenerateSignature) {
            printDegenerateWarning();
            return;
        }

        printStep3(result);
        printStep4(result);
        System.out.println();
    }

    // -------------------------------------------------------------------------
    // Private helpers -- one method per logical section
    // -------------------------------------------------------------------------

    private static void printHeader(DSARunner.RunResult result) {
        System.out.println(SEPARATOR);
        System.out.println(result.label);
        System.out.printf("  Inputs: p=%s, q=%s, h=%s, x=%s, k=%s%n",
                result.params.p, result.params.q, result.params.h,
                result.params.x, result.params.k);
        System.out.printf("          H(M1)=%s, H(M2)=%s%n",
                result.realMessageHash, result.fakeMessageHash);
        System.out.println(SEPARATOR);
    }

    private static void printStep1(DSARunner.RunResult result) {
        System.out.println("\n[Step 1] Key Material:");
        System.out.printf("  g = h^((p-1)/q) mod p  =  %s%n", result.params.g);
        System.out.printf("  y = g^x mod p           =  %s%n", result.params.y);
    }

    private static void printStep2(DSARunner.RunResult result) {
        System.out.println("\n[Step 2] Signing H(M1) = " + result.realMessageHash + ":");
        if (result.degenerateSignature) {
            System.out.println("  r = (g^k mod p) mod q          =  [see degenerate warning below]");
            System.out.println("  s = k^-1 * (H(M1)+x*r) mod q  =  0  <-- degenerate");
        } else {
            System.out.printf("  r = (g^k mod p) mod q          =  %s%n", result.signature.r);
            System.out.printf("  s = k^-1 * (H(M1)+x*r) mod q  =  %s%n", result.signature.s);
        }
    }

    private static void printDegenerateWarning() {
        System.out.println();
        System.out.println("  *** DEGENERATE SIGNATURE ***");
        System.out.println("  H(M1) + x*r ≡ 0 (mod q), which forces s = 0.");
        System.out.println("  s = 0 has no modular inverse, so verification");
        System.out.println("  is impossible. In real DSA a fresh nonce k would");
        System.out.println("  be chosen and signing retried. Because all inputs");
        System.out.println("  are fixed by the assignment, steps 3 and 4 are");
        System.out.println("  skipped.");
        System.out.println();
    }

    private static void printStep3(DSARunner.RunResult result) {
        System.out.println("\n[Step 3] Verification -- real message H(M1) = "
                + result.realMessageHash + " (expect: VALID):");
        printVerificationDetail(result.signature, result.realVerification);
    }

    private static void printStep4(DSARunner.RunResult result) {
        System.out.println("\n[Step 4] Verification -- fake message H(M2) = "
                + result.fakeMessageHash + " (expect: INVALID):");
        System.out.println("  [Same (r,s) as Step 2; BG is attempting a forgery]");
        printVerificationDetail(result.signature, result.fakeVerification);
    }

    /**
     * Prints the intermediate values and verdict for one verification attempt.
     *
     * @param sig    the signature being checked
     * @param vr     the verification result containing w, u1, u2, v, and valid
     */
    private static void printVerificationDetail(DSASignature           sig,
                                                DSAVerificationResult  vr) {
        System.out.printf("  Using signature (r=%s, s=%s)%n", sig.r, sig.s);
        System.out.printf("  w  = s^-1 mod q                   =  %s%n", vr.w);
        System.out.printf("  u1 = H(M)*w mod q                 =  %s%n", vr.u1);
        System.out.printf("  u2 = r*w mod q                    =  %s%n", vr.u2);
        System.out.printf("  v  = (g^u1 * y^u2 mod p) mod q   =  %s%n", vr.v);
        System.out.printf("  v == r?  -->  %s%n",
                vr.valid ? "YES -- VALID   (signature accepted)"
                        : "NO  -- INVALID (signature rejected)");
    }
}

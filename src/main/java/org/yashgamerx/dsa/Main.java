package org.yashgamerx.dsa;

public final class Main {

    private Main() {}

    public static void main(String[] args) {

        // ------------------------------------------------------------------
        // Test Case 1: Textbook example from the class handout
        //   p=7, q=3, h=3, x=2, k=1, H(M1)=3, H(M2)=4
        // ------------------------------------------------------------------
        runAndPrint(
                "TEST CASE 1 -- Class Handout Example",
                DSAParams.of(7, 3, 3, 2, 1),
                3L, 4L
        );

        // ------------------------------------------------------------------
        // Test Case 2: Inputs provided in the assignment
        //   p=47, q=23, h=5, x=7, k=13, H(M1)=3, H(M2)=7
        //
        //   NOTE: These inputs yield a degenerate signature.
        //   3 + 7*16 = 115; 115 mod 23 = 0 --> s = 0.
        //   The program detects this and explains the failure.
        // ------------------------------------------------------------------
        runAndPrint(
                "TEST CASE 2 -- Assignment Inputs (degenerate case)",
                DSAParams.of(47, 23, 5, 7, 13),
                3L, 7L
        );

        // ------------------------------------------------------------------
        // Test Case 3: Custom large input
        //   q = 104729 (prime)
        //   p = 2*q+1 = 209459 (safe prime; guarantees q | p-1)
        //   h = 3, x = 58391, k = 72163
        //   H(M1) = 41257, H(M2) = 83641
        // ------------------------------------------------------------------
        runAndPrint(
                "TEST CASE 3 -- Custom Large Input",
                DSAParams.of(209459, 104729, 3, 58391, 72163),
                41257L, 83641L
        );
    }

    /**
     * Runs one DSA demonstration and immediately prints the result.
     *
     * @param label           display label for this test case
     * @param params          pre-built DSAParams (g and y already derived)
     * @param realMessageHash H(M1)
     * @param fakeMessageHash H(M2)
     */
    private static void runAndPrint(String    label,
                                    DSAParams params,
                                    long      realMessageHash,
                                    long      fakeMessageHash) {

        DSARunner.RunResult result = DSARunner.run(
                label,
                params,
                java.math.BigInteger.valueOf(realMessageHash),
                java.math.BigInteger.valueOf(fakeMessageHash)
        );

        DSAPrinter.print(result);
    }
}
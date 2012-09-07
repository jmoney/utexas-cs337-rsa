package org.rsa.cs337.utils;

/**
 * The util file containing some helper methods for the RSA algorithm
 *
 * @author jmonette
 */
public class RSAUtils {

    /**
     * Private default constructor which will override the public default constructor. No need for the user to instantiate this class
     */
    private RSAUtils() {}

    /**
     * FAST EXPONENTIATION MOD ALGORITHM: (data^exponent) mod modulus
     * All calculations are done with the long data type
     * Because the first 4 higher order bytes should be 0,
     * cast the result as an int and return the lower 4 bytes.
     * If the higher 4 bytes are not 0, something went wrong.
     *
     * @param base     The base of the equation
     * @param exponent The exponent of the equation
     * @param modulus  The number to take the modulus with
     * @return
     */
    public static int dxmodn(long base, long exponent, long modulus) {
        long result = 1;

        /* Loop until the exponent is 0 */
        while (exponent != 0) {
            /* If the exponent is odd */
            if ((exponent & 1) == 1) {
                result = (result * base) % modulus;
            }

            /* Divide the exponent by 2 */
            exponent = exponent >> 1;

            base = (base * base) % modulus;
        }
        return (int) result;
    }

    /**
     * Splits an int value into a 4 byte array, big-endian
     *
     * @param value the in value to convert to a byte array
     * @return a byte array representation of the int value
     */
    public static byte[] intToByteArray(int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) (value)
        };
    }

    /**
     * The extended euclidean algorithm used in the RSA algorithm
     *
     * @param e
     * @param phiOfN
     * @return
     */
    public static long EEAlgorithm(long e, long phiOfN) {
        long[] uv = {e, phiOfN};
        long[] abcd = {1, 0, 0, 1};

        while (uv[1] != 0) {
            long u = uv[0];
            long v = uv[1];
            long a = abcd[0];
            long b = abcd[1];
            long c = abcd[2];
            long d = abcd[3];

            long q = u / v;

            uv[0] = v;
            uv[1] = u - (v * q);

            abcd[0] = c;
            abcd[1] = d;
            abcd[2] = a - (c * q);
            abcd[3] = b - (d * q);
        }

        /* a is going to be our return */
        long ret = abcd[0];

        /* Fix the return according to the rules of RSA */
        if (ret > phiOfN) {
            ret -= phiOfN;
        } else if (ret <= 0) {
            ret += phiOfN;
        }

        return ret;
    }

    /**
     * Recursive gcd algorithm used for picking e and checking properties of e/d for the RSA algorithm
     *
     * @param x the first value to use in the gcd algorithm
     * @param y the second value to use in the gcd algorithm
     * @return returns the gcd of x and y
     */
    public static long gcd(long x, long y) {
        if (y == 0) {
            return x;
        }
        return gcd(y, x % y);
    }
}

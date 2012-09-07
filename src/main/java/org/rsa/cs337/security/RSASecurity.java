package org.rsa.cs337.security;

import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Arrays;
import java.util.StringTokenizer;

import static org.rsa.cs337.utils.RSAUtils.*;

/**
 * This class contains the basic methods for the RSA algorithm
 *
 * @author jmonette
 */
public class RSASecurity {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(RSASecurity.class);

    /**
     * This method will generate the keys needed for the RSA algorithm. They will output on standard out.
     *
     * @param p The p variable used to generate keys in the RSA algorithm
     * @param q The q variable used to generate keys in the RSA algorithm
     */
    public static void generateKeys(long p, long q) {
        long e = 0L;
        long n = p * q;
        long phiOfN = (p - 1) * (q - 1);

        /* Pick an e */
        for (int i = 2; i < n; i++) {
            if (gcd(i, phiOfN) == 1) {
                e = i;
                break;
            }
        }

        /* Base on the e we picked, calculate d */
        long d = EEAlgorithm(e, phiOfN);

        /* Assert the RSA rules for e and d */
        assert ((1 <= e) && (e < n));
        assert ((1 <= d) && (d < n));
        assert (gcd(e, phiOfN) == 1);
        assert (gcd(d, phiOfN) == 1);
        assert (((e * d) % phiOfN) == 1);

        logger.info(n + " " + e + " " + d);
    }

    /**
     * This method will take the content of infile and encrypt the data and output to outfile following the RSA algorithm.
     *
     * @param infile  The filename name of the file to encrypt
     * @param keyfile The keyfile to read the keys from
     * @param outfile The output file name to output the encryption
     * @throws IOException
     */
    public static void encrypt(String infile, String keyfile, String outfile) throws IOException {
        /* Input and Output declarations */
        DataOutputStream
                outputStream = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outfile)));
        DataInputStream
                inputStream = new DataInputStream(new BufferedInputStream(new FileInputStream(infile)));
        StringTokenizer
                keys = new StringTokenizer(new BufferedReader(new FileReader(keyfile)).readLine());

        /* Values needed for the encryption */
        long n = Long.parseLong(keys.nextToken());
        long e = Long.parseLong(keys.nextToken());

        /* Is there more bytes in the file to encrypt */
        while (inputStream.available() != 0) {
            int data = 0;
            int C = 1;

            /* Read in 3 bytes at a time */
            /* Put them in a 4 byte block */
            /* Takes care of case where files will not end in a 0 byte */
            if (inputStream.available() != 0) { data += inputStream.readUnsignedByte(); }
            data = data << 8;

            if (inputStream.available() != 0) { data += inputStream.readUnsignedByte(); }
            data = data << 8;

            if (inputStream.available() != 0) { data += inputStream.readUnsignedByte(); }

            /* RSA can only encrypt data that is < n */
            assert (data < n);

            /* encrypt */
            /* (data^e) mod n */
            C = dxmodn(data, e, n);

            logger.debug("n=" + n + " e=" + e);
            logger.debug("data: " + data);
            logger.debug("C: " + C);
            logger.debug("Unencrypted: " + Arrays.toString(intToByteArray(data)));
            logger.debug("Encrypted:   " + Arrays.toString(intToByteArray(C)));

            /* write out data in 4 bytes */
            byte[] output = intToByteArray(C);
            if (inputStream.available() == 0 && output[1] == 0 && output[2] == 0 && output[3] == 0) {
                outputStream.write(output, 0, 1);
            } else if (inputStream.available() == 0 && output[2] == 0 && output[3] == 0) {
                outputStream.write(output, 0, 2);
            } else if (inputStream.available() == 0 && output[3] == 0) {
                outputStream.write(output, 0, 3);
            } else {
                outputStream.write(output, 0, 4);
            }
            outputStream.flush();
        }
    }

    /**
     * This method will take an encrypted file with name infile and decrypt according to the RSA algorithm and output to
     * the file name outfile. The same key file used to encrypt the file must be used to encrypt the file.
     *
     * @param infile  The filename name of the file to decrypt
     * @param keyfile The keyfile to read the keys from
     * @param outfile The output file name to output the decryption
     * @throws IOException
     */
    public static void decrypt(String infile, String keyfile, String outfile) throws IOException {
        /* Input and Output declarations */
        DataOutputStream
                outputStream = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outfile)));
        DataInputStream
                inputStream = new DataInputStream(new BufferedInputStream(new FileInputStream(infile)));
        StringTokenizer
                keys = new StringTokenizer(new BufferedReader(new FileReader(keyfile)).readLine());

        /* Values needed for the decryption */
        long n = Long.parseLong(keys.nextToken());
        long e = Long.parseLong(keys.nextToken());
        long d = Long.parseLong(keys.nextToken());

        /* Is there more bytes in the file to decrypt */
        while (inputStream.available() != 0) {
            /* Declarations to decrypt the data */
            int data = 0;
            int C = 1;

            /* Read in 4 bytes at a time */
            /* Put them in a 4 byte block */
            if (inputStream.available() != 0) { data += inputStream.readUnsignedByte(); }
            data = data << 8;

            if (inputStream.available() != 0) { data += inputStream.readUnsignedByte(); }
            data = data << 8;

            if (inputStream.available() != 0) { data += inputStream.readUnsignedByte(); }
            data = data << 8;

            if (inputStream.available() != 0) { data += inputStream.readUnsignedByte(); }

            /* RSA can only decrypt data that is < n */
            assert (data < n);

            /* decrypt */
            /* (data^d) mod n */
            C = dxmodn(data, d, n);

            logger.debug("n=" + n + " e=" + e + " d=" + d);
            logger.debug("data: " + data);
            logger.debug("C: " + C);
            logger.debug("Encrypted: " + Arrays.toString(intToByteArray(data)));
            logger.debug("Decrypted: " + Arrays.toString(intToByteArray(C)));

            /* write out data in 3 bytes */
            /* Takes care of case where a file cannot end in a 0 byte */
            byte[] output = intToByteArray(C);
            if (inputStream.available() == 0 && output[2] == 0 && output[3] == 0) {
                outputStream.write(output, 1, 1);
            } else if (inputStream.available() == 0 && output[3] == 0) {
                outputStream.write(output, 1, 2);
            } else {
                outputStream.write(output, 1, 3);
            }
            outputStream.flush();
        }
    }
}

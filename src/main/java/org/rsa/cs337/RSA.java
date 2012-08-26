package org.rsa.cs337;

import org.apache.log4j.Logger;
import org.rsa.cs337.security.RSASecurity;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;

public class RSA {

    private static final Logger logger = Logger.getLogger(RSA.class);

    public static void main(String[] args) {
        if (args[0].equalsIgnoreCase("key")) {
            long p = Long.parseLong(args[1]);
            long q = Long.parseLong(args[2]);
            if (p == q) {
                logger.error("Error: p = q");
                System.exit(1);
            }
            RSASecurity.generateKeys(p, q);
        } else if (args[0].equalsIgnoreCase("encrypt")) {
            try {
                RSASecurity.encrypt(args[1], args[2], args[3]);
            } catch (IOException e) {
                logger.error(accessExceptionStackTraceViaPrintWriter(e));
                System.exit(2);
            }
        } else if (args[0].equalsIgnoreCase("decrypt")) {
            try {
                RSASecurity.decrypt(args[1], args[2], args[3]);
            } catch (IOException e) {
                logger.error(accessExceptionStackTraceViaPrintWriter(e));
                System.exit(2);
            }
        } else {
            logger.error("Error: unknown option \"" + args[0] + "\"");
            System.exit(1);
        }
    }

    /**
     * Grab the stack from the exception and print it to the JSON string for the response
     *
     * @param throwable Any object that has Throwable in the class hierarchy as it will have a printStackTrace(Writer)
     *                  method to call
     * @return returns the stack trace as a String
     */
    private static String accessExceptionStackTraceViaPrintWriter(final Throwable throwable) {
        final Writer writer = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(writer);
        throwable.printStackTrace(printWriter);
        return writer.toString();
    }
}

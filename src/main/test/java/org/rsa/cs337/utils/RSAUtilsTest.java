package org.rsa.cs337.utils;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author jmonette
 * Date: 8/26/12
 */
public class RSAUtilsTest {

    private static final Logger logger = LoggerFactory.getLogger(RSAUtilsTest.class);
    /**
     * This is a basic test for the dxmodn algorithm
     */
    @Test
    public void dxmodnTest() {
        logger.debug("base = 0");
        RSAUtils.dxmodn(0, 0, 0);
    }
}

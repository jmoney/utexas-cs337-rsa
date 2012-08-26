package org.rsa.cs337.utils;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * @author jmonette
 * Date: 8/26/12
 */
public class RSAUtilsTest {

    @Test
    public void dxmodnBasicTest() {
        RSAUtils.dxmodn(0, 0, 0);
        assertTrue(true);
    }
}

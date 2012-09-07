package org.rsa.cs337.utils;

import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * @author jmonette
 */
public class RSAUtilsTest {

    @Test
    public void dxmodnIdentityTest1() {
        int response = RSAUtils.dxmodn(0L, 0L, 0L);
        assertThat(response, is(1));
    }

    @Test
    public void dxmodnIdentityTest2() {
        int response = RSAUtils.dxmodn(1L, 0L, 1L);
        assertThat(response, is(1));
    }

    @Test
    public void testMaxIntToByteArray() {
        byte[] response = RSAUtils.intToByteArray(Integer.MAX_VALUE);
        byte[] actual = {127, -1, -1, -1};
        assertThat(response, is(actual));
    }

    @Test
    public void testMinIntToByteArray() {
        byte[] response = RSAUtils.intToByteArray(Integer.MIN_VALUE);
        byte[] actual = {-128, 0, 0, 0};
        assertThat(response, is(actual));
    }

    /* EEAlgorithm tests */

    @Test
    public void basicGCDTest() {
        long response = RSAUtils.gcd(Long.MAX_VALUE, Long.MAX_VALUE);
        assertThat(response, is(Long.MAX_VALUE));
    }

    @Test
    public void smallGCDTest() {
        long response = RSAUtils.gcd(10L, 5L);
        assertThat(response, is(5L));
    }
}

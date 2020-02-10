package com.yzz.gmssl;

import org.junit.Test;
import static org.junit.Assert.*;

public class SM4Test {

    @Test
    public void testSM4() {
        byte[] key = "1234567812345678".getBytes();
        byte[] iv = "1234567812345678".getBytes();
        System.out.println(key.length);
        byte[] cipher = SM4.encrypt(key, iv, "abc".getBytes());
        byte[] plain = SM4.decrypt(key, iv, cipher);
        assertNotNull(cipher);
        assertArrayEquals(plain, "abc".getBytes());
    }
}

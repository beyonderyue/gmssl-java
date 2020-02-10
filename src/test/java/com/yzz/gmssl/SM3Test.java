package com.yzz.gmssl;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.junit.Test;

public class SM3Test {

    @Test
    public void testSM3() {
        byte[] digest = SM3.digest("abc".getBytes());

        System.out.println(HexBin.encode(digest));
    }
}

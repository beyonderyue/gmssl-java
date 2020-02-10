package com.yzz.gmssl;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.junit.Test;
import static org.junit.Assert.*;

public class SM2Test {

    @Test
    public void testAll() {
        KeyPair keyPair = SM2.generateKeyPair();

        SM2PrivateKey sm2PrivateKey = keyPair.getPrivateKey();
        byte[] signature = sm2PrivateKey.sign("abc".getBytes());

        SM2PublicKey sm2PublicKey = keyPair.getPublicKey();
        System.out.println(HexBin.encode(sm2PublicKey.getPublicKey()));
        assertTrue(sm2PublicKey.verify("abc".getBytes(), signature));

    }


}

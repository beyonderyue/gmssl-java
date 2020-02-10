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

    @Test
    public void testExch() {
        KeyPair local = SM2.generateKeyPair();
        KeyPair localempheral = SM2.generateKeyPair();
        System.out.println(HexBin.encode(local.getPrivateKey().getPrivateKey()));
        System.out.println(HexBin.encode(local.getPublicKey().getPublicKey()));
        System.out.println(HexBin.encode(localempheral.getPrivateKey().getPrivateKey()));
        System.out.println(HexBin.encode(localempheral.getPublicKey().getPublicKey()));


        KeyPair remote = SM2.generateKeyPair();
        KeyPair remoteempheral = SM2.generateKeyPair();
        System.out.println(HexBin.encode(remote.getPrivateKey().getPrivateKey()));
        System.out.println(HexBin.encode(remote.getPublicKey().getPublicKey()));
        System.out.println(HexBin.encode(remoteempheral.getPrivateKey().getPrivateKey()));
        System.out.println(HexBin.encode(remoteempheral.getPublicKey().getPublicKey()));



        byte[] key1 = SM2.calculateSharedKey(local.getPrivateKey().getPrivateKey(),
                localempheral.getPrivateKey().getPrivateKey(), "a",
                remote.getPublicKey().getPublicKey(), remoteempheral.getPublicKey().getPublicKey(), "a", 128, 1);
        byte[] key2 = SM2.calculateSharedKey(remote.getPrivateKey().getPrivateKey(),
                remoteempheral.getPrivateKey().getPrivateKey(), "a",
                local.getPublicKey().getPublicKey(), localempheral.getPublicKey().getPublicKey(), "a", 128, 0);
        System.out.println(HexBin.encode(key1));
        System.out.println(HexBin.encode(key2));
        assertArrayEquals(key1, key2);

    }


}

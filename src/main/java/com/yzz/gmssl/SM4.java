package com.yzz.gmssl;

public class SM4 {
    public static GmSSL gmSSL = SM.gmSSL;
    public static byte[] encrypt(byte[] key, byte[] iv, byte[] message) {
        if (key.length!=16 || iv.length!=16) {
            return null;
        }
        byte[] cipher = gmSSL.symmetricEncrypt("SMS4", message, key, iv);
        return cipher;
    }

    public static byte[] decrypt(byte[] key, byte[] iv, byte[] cipher) {
        if (key.length!=16 || iv.length!=16) {
            return null;
        }
        byte[] plain = gmSSL.symmetricDecrypt("SMS4", cipher, key, iv);
        return plain;
    }
}

package com.yzz.gmssl;

public class SM2 {
    public static final String ALGORITHM = "sm2";
    public static String getAlgorithm() {
        return ALGORITHM;
    }
    public static GmSSL gmSSL = SM.gmSSL;
    public static KeyPair generateKeyPair() {
        byte[] key = gmSSL.generateKeyPair(true);
        byte[] privateKey = new byte[32];
        byte[] publicKey = new byte[33];
        System.arraycopy(key, 0, privateKey, 0, 32);
        System.arraycopy(key, 32, publicKey, 0, 33);
        SM2PrivateKey sm2PrivateKey = new SM2PrivateKey();
        sm2PrivateKey.setPrivateKey(privateKey);
        SM2PublicKey sm2PublicKey = new SM2PublicKey();
        sm2PublicKey.setPublicKey(publicKey);
        KeyPair keyPair = new KeyPair();
        keyPair.setPrivateKey(sm2PrivateKey);
        keyPair.setPublicKey(sm2PublicKey);
        return keyPair;
    }

    public static byte[] sign(byte[] privateKey, byte[] message) {
        byte[] signature = gmSSL.sign("sm2sign", message, privateKey, "userid@soie-chain.com");
        return signature;
    }

    public static byte[] getPublicKeyFromPrivateKey(byte[] privateKey, boolean compressed) {
        byte[] publicKey = gmSSL.getPublicKey(privateKey, compressed);
        return publicKey;
    }

    public static boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
        int ret =  gmSSL.verify("sm2sign", message, signature, publicKey, "userid@soie-chain.com");
        return ret==1?true:false;
    }

    public static byte[] encrypt(byte[] publicKey, byte[] message) {
        byte[] cipher = gmSSL.publicKeyEncrypt("sm2encrypt-with-sm3", message, publicKey);
        return cipher;
    }

    public static byte[] decrypt(byte[] privateKey, byte[] cipher) {
        byte[] plainText = gmSSL.publicKeyDecrypt("sm2encrypt-with-sm3", cipher, privateKey);
        return plainText;
    }



}

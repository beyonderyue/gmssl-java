package com.yzz.gmssl;

public class SM2PublicKey {
    byte[] publicKey;

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public boolean verify(byte[] message, byte[] signature) {
        return SM2.verifySignature(publicKey, message, signature);
    }

    public byte[] encrypt(byte[] message) {
        byte[] ciphertext = SM2.encrypt(publicKey, message);
        return ciphertext;
    }
}

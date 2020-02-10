package com.yzz.gmssl;

public class SM2PrivateKey {
    private byte[] privateKey;

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public byte[] sign(byte[] message) {
        byte[] signature = SM2.sign(privateKey, message);
        return signature;
    }

    public byte[] getPublicKey(boolean compressed) {
        byte[] publicKey = SM2.getPublicKeyFromPrivateKey(privateKey, compressed);
        return publicKey;
    }

    public byte[] decrypt(byte[] cipher) {
        return SM2.decrypt(privateKey, cipher);
    }
}

package com.yzz.gmssl;

public class KeyPair {

    private SM2PrivateKey privateKey;

    public SM2PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(SM2PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    private SM2PublicKey publicKey;

    public SM2PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(SM2PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}

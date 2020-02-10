package com.yzz.gmssl;

public class SM3 {
    public static GmSSL gmSSL = SM.gmSSL;
    public static byte[] digest(byte[] message) {
        return gmSSL.digest("SM3", message);
    }
}

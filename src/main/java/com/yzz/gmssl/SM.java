package com.yzz.gmssl;

public class SM {
    public static GmSSL gmSSL = null;
    static {
        System.loadLibrary("gmssljni");
        gmSSL = new GmSSL();
    }
}

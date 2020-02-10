package com.yzz.gmssl;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.junit.Test;

public class GMSSLTest {

    @Test
    public void testAll() {
        int i;
        final GmSSL gmssl = SM.gmSSL;

        /* GmSSL versions */
        String[] versions = gmssl.getVersions();
        for (i = 0; i < versions.length; i++) {
            System.out.println(versions[i]);
        }

        /* Supported algorithms */
        System.out.print("Ciphers: ");
        String[] ciphers = gmssl.getCiphers();
        for (i = 0; i < ciphers.length - 1; i++) {
            System.out.print(ciphers[i] + ", ");
        }
        System.out.println(ciphers[i]);

        System.out.print("Digests: ");
        String[] digests = gmssl.getDigests();
        for (i = 0; i < digests.length - 1; i++) {
            System.out.print(digests[i] + ", ");
        }
        System.out.println(digests[i]);

        System.out.print("MACs: ");
        String[] macs = gmssl.getMacs();
        for (i = 0; i < macs.length - 1; i++) {
            System.out.print(macs[i] + ", ");
        }
        System.out.println(macs[i]);

        System.out.print("SignAlgorithms: ");
        String[] signAlgors = gmssl.getSignAlgorithms();
        for (i = 0; i < signAlgors.length - 1; i++) {
            System.out.print(signAlgors[i] + ", ");
        }
        System.out.println(signAlgors[i]);
        byte[] keypair = gmssl.generateKeyPair(true);

        byte[] privkey = new byte[32];
        System.arraycopy(keypair, 0, privkey, 0, 32);

        byte[] pubkey = new byte[keypair.length-32];
        System.arraycopy(keypair,32,pubkey,0,keypair.length-32);

        System.out.println("--------------------");
        System.out.println(HexBin.encode(privkey));
        System.out.print("PublicKeyEncryptions: ");

        pubkey = gmssl.getPublicKey(privkey, true);

        String[] encAlgors = gmssl.getPublicKeyEncryptions();
        for (i = 0; i < encAlgors.length - 1; i++) {
            System.out.print(encAlgors[i] + ", ");
        }
        System.out.println(encAlgors[i]);

        System.out.print("DeriveKeyAlgorithms: ");
        String[] kdfs = gmssl.getDeriveKeyAlgorithms();
        for (i = 0; i < kdfs.length - 1; i++) {
            System.out.print(kdfs[i] + ", ");
        }
        System.out.println(kdfs[i]);

        /* Crypto operations */
        System.out.print("Random(20) = ");
        byte[] data = gmssl.generateRandom(20);
        for (i = 0; i < data.length; i++) {
            System.out.printf("%02X", data[i]);
        }
        System.out.println("");

        System.out.printf("SMS4 IV length = %d bytes, key length = %d bytes, block size = %d bytes\n",
                gmssl.getCipherIVLength("SMS4"),
                gmssl.getCipherKeyLength("SMS4"),
                gmssl.getCipherBlockSize("SMS4"));

        byte[] key = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
        byte[] iv = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
        byte[] ciphertext = gmssl.symmetricEncrypt("SMS4", "01234567".getBytes(), key, iv);

        System.out.print("Ciphertext: ");
        for (i = 0; i < ciphertext.length; i++) {
            System.out.printf("%02X", ciphertext[i]);
        }
        System.out.println("");

        byte[] plaintext = gmssl.symmetricDecrypt("sms4", ciphertext, key, iv);

        System.out.print("Plaintext: ");
        for (i = 0; i < plaintext.length; i++) {
            System.out.printf("%02X", plaintext[i]);
        }

        byte[] dgst = gmssl.digest("SM3", "abc".getBytes());
        System.out.print("SM3(\"abc\") = ");
        for (i = 0; i < dgst.length; i++) {
            System.out.printf("%02X", dgst[i]);
        }
        System.out.println("");

        byte[] macTag = gmssl.mac("HMAC-SM3", "abc".getBytes(), "password".getBytes());
        System.out.print("HMAC-SM3(\"abc\") = ");
        for (i = 0; i < macTag.length; i++) {
            System.out.printf("%02X", macTag[i]);
        }
        System.out.println("");

        String publickey = "BC923A050AD206A8539A87738B57AEDB180706DDE653CB928A9FF2463D62845BAB9716D7FD4AFF0A32C041B062E34EC7C4953742C62B15A37064C43DF38500CB";

        byte[] sig = gmssl.sign("sm2sign", "abc".getBytes(), privkey, "userid@soie-chain.com");
        System.out.print("SM2 Signature : ");
        for (i = 0; i < sig.length; i++) {
            System.out.printf("%02X", sig[i]);
        }
        System.out.print("\n");

        System.out.println(HexBin.encode(privkey));
        int vret = gmssl.verify("sm2sign", "abc".getBytes(), sig, pubkey, "userid@soie-chain.com");
        System.out.println("Verification result = " + vret);

        byte[] sm2Ciphertext = gmssl.publicKeyEncrypt("sm2encrypt-with-sm3", "abc".getBytes(), pubkey);
        System.out.print("SM2 Ciphertext : ");
        for (i = 0; i < sm2Ciphertext.length; i++) {
            System.out.printf("%02X", sm2Ciphertext[i]);
        }
        System.out.print("\n");

        byte[] sm2Plaintext = gmssl.publicKeyDecrypt("sm2encrypt-with-sm3", sm2Ciphertext, privkey);
        System.out.print("SM2 Plaintext : ");
        for (i = 0; i < sm2Plaintext.length; i++) {
            System.out.printf("%02X", sm2Plaintext[i]);
        }
        System.out.print("\n");

        /* Errors */
        System.out.println("Errors:");
        String[] errors = gmssl.getErrorStrings();
        for (i = 0; i < errors.length; i++) {
            System.out.println(errors[i]);
        }

    }
}

package com.work.rsa;

import com.work.rsa.util.RSACrypto;
import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {

    public static void main(String[] args) {
        try {

            PrivateKey privateKey;
            PublicKey publicKey;

            RSACrypto r = new RSACrypto();

            KeyPair pair = r.generatorKey();

            if (existFile("publickey.key")) {
                publicKey = r.loadPublicKey("publickey.key");
            } else {
                publicKey = pair.getPublic();
                r.saveKey(publicKey, "publickey.key");
            }

            if (existFile("privatekey.key")) {
                privateKey = r.loadPrivateKey("privatekey.key");
            } else {
                privateKey = pair.getPrivate();
                r.saveKey(privateKey, "privatekey.key");
            }

            String text = "text";
            String encrypt = r.encrypt(text, publicKey);
            System.out.println("Encrypt: " + encrypt);

            String decrypt = r.decrypt(encrypt, privateKey);
            System.out.println("Decrypt: " + decrypt);

        } catch (Exception ex) {
            ex.printStackTrace(System.err);
        }
    }

    private static boolean existFile(String fileName) {
        return new File(fileName).exists();
    }
}

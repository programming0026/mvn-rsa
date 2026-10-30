package com.work.rsa.util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;


public class RSACrypto {

    private static final String ALGORITHM = "RSA";

    private static final String NAME_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    private static final char[] hexCode = "0123456789ABCDEF".toCharArray();

    private String toHexString(byte[] data) {
        StringBuilder r = new StringBuilder(data.length * 2);
        for (byte b : data) {
            r.append(hexCode[(b >> 4) & 0xF]);
            r.append(hexCode[(b & 0xF)]);
        }
        return r.toString();
    }

    private int hexToBin(char ch) {
        if ('0' <= ch && ch <= '9') {
            return ch - '0';
        }
        if ('A' <= ch && ch <= 'F') {
            return ch - 'A' + 10;
        }
        if ('a' <= ch && ch <= 'f') {
            return ch - 'a' + 10;
        }
        return -1;
    }

    private byte[] parseHexBinary(String s) {
        final int len = s.length();

        if (len % 2 != 0) {
            throw new IllegalArgumentException("hexBinary needs to be even-length: " + s);
        }

        byte[] out = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            int h = hexToBin(s.charAt(i));
            int l = hexToBin(s.charAt(i + 1));
            if (h == -1 || l == -1) {
                throw new IllegalArgumentException("contains illegal character for hexBinary: " + s);
            }

            out[i / 2] = (byte) (h * 16 + l);
        }

        return out;
    }

    public String encrypt(final String text, PublicKey publicKey) throws Exception {
        Cipher rsa;
        rsa = Cipher.getInstance(NAME_TRANSFORMATION);
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encriptado = rsa.doFinal(text.getBytes(StandardCharsets.UTF_8));
        return toHexString(encriptado);
    }

    public String decrypt(String text, PrivateKey privateKey) throws Exception {
        Cipher rsa;
        rsa = Cipher.getInstance(NAME_TRANSFORMATION);
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = parseHexBinary(text);
        byte[] bytesDesencriptados = rsa.doFinal(bytes);
        return new String(bytesDesencriptados, StandardCharsets.UTF_8);
    }

    public KeyPair generatorKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public void saveKey(Key key, String fileName) throws Exception {
        byte[] publicKeyBytes = key.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(publicKeyBytes);
        }
    }

    public PublicKey loadPublicKey(String fileName) throws Exception {
        byte[] bytes;
        try (FileInputStream fis = new FileInputStream(fileName)) {
            int numBtyes = fis.available();
            bytes = new byte[numBtyes];
            int read = fis.read(bytes);
            if (read < 0) {
                throw new Exception("Could not read the file " + fileName);
            }
        }

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        KeySpec keySpec = new X509EncodedKeySpec(bytes);
        PublicKey keyFromBytes = keyFactory.generatePublic(keySpec);
        return keyFromBytes;
    }

    public PrivateKey loadPrivateKey(String fileName) throws Exception {
        byte[] bytes;
        try (FileInputStream fis = new FileInputStream(fileName)) {
            int numBtyes = fis.available();
            bytes = new byte[numBtyes];
            int read = fis.read(bytes);
            if (read < 0) {
                throw new Exception("Could not read the file " + fileName);
            }
        }

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        KeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        PrivateKey keyFromBytes = keyFactory.generatePrivate(keySpec);
        return keyFromBytes;
    }
}

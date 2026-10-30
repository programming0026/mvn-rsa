package com.juniverse.rsa.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import javax.crypto.Cipher;

/**
 * Cifrado asimétrico con RSA: genera el par de llaves, las guarda y las carga de disco, y cifra o descifra textos.
 * <p>
 * Lo que se cifra con la llave pública solo se descifra con la privada. El texto cifrado se expresa en hexadecimal
 * para poder mostrarlo o almacenarlo como cadena. Las llaves se guardan en binario: la pública en formato X.509 y la
 * privada en PKCS#8.
 * <p>
 * RSA con relleno PKCS#1 v1.5 solo puede cifrar mensajes cortos (con 2048 bits, hasta 245 bytes); para datos grandes
 * se cifra una llave simétrica (por ejemplo AES) con RSA y los datos con esa llave.
 */
public class RSACrypto {

    private static final String ALGORITHM = "RSA";

    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    /** Tamaño de la llave en bits. */
    private static final int KEY_SIZE = 2048;

    /**
     * Cifra un texto con la llave pública.
     *
     * @param text      texto a cifrar (máximo 245 bytes en UTF-8 con llaves de 2048 bits)
     * @param publicKey llave pública del destinatario
     * @return el texto cifrado en hexadecimal (mayúsculas)
     * @throws GeneralSecurityException si la llave no es válida o el texto es demasiado largo
     */
    public String encrypt(String text, PublicKey publicKey) throws GeneralSecurityException {
        Cipher rsa = Cipher.getInstance(TRANSFORMATION);
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = rsa.doFinal(text.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().withUpperCase().formatHex(encrypted);
    }

    /**
     * Descifra un texto con la llave privada.
     *
     * @param text       texto cifrado en hexadecimal (mayúsculas o minúsculas)
     * @param privateKey llave privada que corresponde a la pública usada para cifrar
     * @return el texto original
     * @throws GeneralSecurityException si la llave no corresponde o el contenido está alterado
     * @throws IllegalArgumentException si el texto no es hexadecimal válido
     */
    public String decrypt(String text, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher rsa = Cipher.getInstance(TRANSFORMATION);
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = rsa.doFinal(HexFormat.of().parseHex(text));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Genera un par de llaves RSA de 2048 bits.
     *
     * @return el par de llaves (pública y privada)
     * @throws GeneralSecurityException si la JVM no ofrece RSA
     */
    public KeyPair generatorKey() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        generator.initialize(KEY_SIZE);
        return generator.generateKeyPair();
    }

    /**
     * Guarda una llave en un archivo en su formato codificado (X.509 la pública, PKCS#8 la privada).
     *
     * @param key      llave a guardar
     * @param fileName ruta del archivo; si existe se sobrescribe
     * @throws IOException si no se puede escribir el archivo
     */
    public void saveKey(Key key, String fileName) throws IOException {
        Files.write(Path.of(fileName), key.getEncoded());
    }

    /**
     * Carga una llave pública guardada con {@link #saveKey(Key, String)}.
     *
     * @param fileName ruta del archivo
     * @return la llave pública
     * @throws IOException              si no se puede leer el archivo
     * @throws GeneralSecurityException si el contenido no es una llave pública válida
     */
    public PublicKey loadPublicKey(String fileName) throws IOException, GeneralSecurityException {
        byte[] bytes = Files.readAllBytes(Path.of(fileName));
        return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(bytes));
    }

    /**
     * Carga una llave privada guardada con {@link #saveKey(Key, String)}.
     *
     * @param fileName ruta del archivo
     * @return la llave privada
     * @throws IOException              si no se puede leer el archivo
     * @throws GeneralSecurityException si el contenido no es una llave privada válida
     */
    public PrivateKey loadPrivateKey(String fileName) throws IOException, GeneralSecurityException {
        byte[] bytes = Files.readAllBytes(Path.of(fileName));
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }
}

package com.juniverse.rsa;

import com.juniverse.rsa.util.RSACrypto;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.logging.Logger;
import java.util.logging.Level;
/**
 * Demostración de RSA: crea (o reutiliza) las llaves {@code publickey.key} y {@code privatekey.key} en la carpeta
 * actual, cifra un texto con la pública y lo descifra con la privada.
 * <p>
 * Uso: {@code java -jar mvn-rsa-...-launcher.jar [texto]}. Sin argumentos cifra la palabra {@code text}.
 */
public class Main {
    private static final Logger LOGGER = AppLogger.get(Main.class);


    private static final String PUBLIC_KEY_FILE = "publickey.key";
    private static final String PRIVATE_KEY_FILE = "privatekey.key";

    /**
     * Punto de entrada.
     *
     * @param args opcional: el texto a cifrar (máximo 245 bytes en UTF-8)
     */
    public static void main(String[] args) {
        try {
            RSACrypto rsa = new RSACrypto();
            PublicKey publicKey;
            PrivateKey privateKey;

            if (Files.exists(Path.of(PUBLIC_KEY_FILE)) && Files.exists(Path.of(PRIVATE_KEY_FILE))) {
                publicKey = rsa.loadPublicKey(PUBLIC_KEY_FILE);
                privateKey = rsa.loadPrivateKey(PRIVATE_KEY_FILE);
                LOGGER.info("Llaves cargadas de " + PUBLIC_KEY_FILE + " y " + PRIVATE_KEY_FILE);
            } else {
                KeyPair pair = rsa.generatorKey();
                publicKey = pair.getPublic();
                privateKey = pair.getPrivate();
                rsa.saveKey(publicKey, PUBLIC_KEY_FILE);
                rsa.saveKey(privateKey, PRIVATE_KEY_FILE);
                LOGGER.info("Llaves nuevas guardadas en " + PUBLIC_KEY_FILE + " y " + PRIVATE_KEY_FILE);
            }

            String text = args.length > 0 ? args[0] : "text";
            String encrypted = rsa.encrypt(text, publicKey);
            LOGGER.info("Encrypt: " + encrypted);
            LOGGER.info("Decrypt: " + rsa.decrypt(encrypted, privateKey));
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }
}

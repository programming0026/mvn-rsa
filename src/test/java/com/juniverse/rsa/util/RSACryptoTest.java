package com.juniverse.rsa.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Pruebas de {@link RSACrypto}. */
class RSACryptoTest {

    private static final RSACrypto RSA = new RSACrypto();
    private static KeyPair pair;

    @BeforeAll
    static void generateKeys() throws Exception {
        pair = RSA.generatorKey();
    }

    @Test
    void generatesKeysOf2048Bits() {
        assertEquals(2048, ((RSAPublicKey) pair.getPublic()).getModulus().bitLength());
    }

    @Test
    void decryptsWhatWasEncrypted() throws Exception {
        String encrypted = RSA.encrypt("Hola, ñandú: 日本語", pair.getPublic());
        assertEquals("Hola, ñandú: 日本語", RSA.decrypt(encrypted, pair.getPrivate()));
    }

    @Test
    void ciphertextIsUppercaseHexOfKeySize() throws Exception {
        String encrypted = RSA.encrypt("text", pair.getPublic());
        assertEquals(512, encrypted.length()); // 256 bytes = 2048 bits
        assertTrue(encrypted.matches("[0-9A-F]+"));
    }

    @Test
    void sameTextEncryptsDifferentEachTime() throws Exception {
        assertNotEquals(RSA.encrypt("text", pair.getPublic()), RSA.encrypt("text", pair.getPublic()));
    }

    @Test
    void decryptAcceptsLowercaseHex() throws Exception {
        String encrypted = RSA.encrypt("text", pair.getPublic());
        assertEquals("text", RSA.decrypt(encrypted.toLowerCase(), pair.getPrivate()));
    }

    @Test
    void otherPrivateKeyCannotDecrypt() throws Exception {
        String encrypted = RSA.encrypt("secreto", pair.getPublic());
        KeyPair other = RSA.generatorKey();
        assertThrows(GeneralSecurityException.class, () -> RSA.decrypt(encrypted, other.getPrivate()));
    }

    @Test
    void rejectsTextTooLongForTheKey() {
        assertThrows(GeneralSecurityException.class, () -> RSA.encrypt("x".repeat(246), pair.getPublic()));
    }

    @Test
    void rejectsInvalidHex() {
        assertThrows(IllegalArgumentException.class, () -> RSA.decrypt("XYZ", pair.getPrivate()));
    }

    @Test
    void savedKeysCanBeLoadedAndUsed(@TempDir Path dir) throws Exception {
        String pub = dir.resolve("publickey.key").toString();
        String priv = dir.resolve("privatekey.key").toString();
        RSA.saveKey(pair.getPublic(), pub);
        RSA.saveKey(pair.getPrivate(), priv);

        assertEquals(pair.getPublic(), RSA.loadPublicKey(pub));
        assertEquals(pair.getPrivate(), RSA.loadPrivateKey(priv));
        String encrypted = RSA.encrypt("persistida", RSA.loadPublicKey(pub));
        assertEquals("persistida", RSA.decrypt(encrypted, RSA.loadPrivateKey(priv)));
    }
}

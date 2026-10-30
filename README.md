# Cifrado asimétrico con RSA

Genera un par de llaves RSA de 2048 bits, las guarda en disco y las reutiliza para cifrar un texto con la **llave pública** y descifrarlo con la **llave privada**. El resultado cifrado se muestra en hexadecimal.

## Cómo funciona RSA

| Llave | Para qué sirve | Quién la tiene |
|-------|----------------|----------------|
| **Pública** | Cifrar (y verificar firmas) | Se puede compartir con cualquiera |
| **Privada** | Descifrar (y firmar) | Solo su dueño |

Lo que se cifra con la pública únicamente se descifra con la privada: quien intercepta el mensaje cifrado no puede leerlo. Con el relleno PKCS#1 v1.5 cada cifrado del mismo texto da un resultado distinto, porque el relleno incluye bytes aleatorios.

## Características

- Llaves de 2048 bits generadas con `KeyPairGenerator`.
- Las llaves se guardan en `publickey.key` (formato X.509) y `privatekey.key` (PKCS#8) en la carpeta desde la que se ejecuta, y se **reutilizan** en las siguientes ejecuciones.
- Texto cifrado en hexadecimal (mayúsculas); al descifrar se aceptan mayúsculas y minúsculas.
- Soporta cualquier texto Unicode (UTF-8): acentos, ñ, caracteres asiáticos.

## Requisitos

- JDK 21 y Maven 3.9 o superior.

## Compilar y ejecutar

```bash
mvn compile exec:java                      # cifra la palabra "text"
mvn compile exec:java -Dexec.args="Hola"   # cifra el texto indicado
```

Salida de ejemplo:

```text
Llaves nuevas guardadas en publickey.key y privatekey.key
Encrypt: 64B9F8D25AE44746CEA8F73CC04B7C4EF6151F222440CC9A452D8DB0A47D8F8B...
Decrypt: Hola
```

## Estructura

```text
src/main/java/com/juniverse/rsa/
├── Main.java                 # demostración: crea o carga las llaves, cifra y descifra
└── util/RSACrypto.java       # encrypt, decrypt, generatorKey, saveKey, loadPublicKey, loadPrivateKey
src/test/java/com/juniverse/rsa/util/RSACryptoTest.java
```

## Pruebas

```bash
mvn test
```

Nueve pruebas: ida y vuelta con texto Unicode, tamaño de la llave y del texto cifrado, cifrados distintos para el mismo texto, hexadecimal en minúsculas, rechazo de una llave privada que no corresponde, de un texto demasiado largo y de hexadecimal inválido, y guardado y carga de las llaves en disco.

## Límites y buenas prácticas

- **Mensajes cortos:** con llaves de 2048 bits y relleno PKCS#1 v1.5 se pueden cifrar como máximo 245 bytes. Para datos grandes se usa cifrado híbrido: se cifran los datos con una llave simétrica (AES) y esa llave se cifra con RSA.
- **Relleno:** `RSA/ECB/PKCS1Padding` es el que se usa aquí por sencillez; en sistemas nuevos se prefiere `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`, que resiste ataques de relleno.
- **La llave privada no se comparte ni se sube a git:** `privatekey.key` se guarda sin contraseña, solo para fines didácticos. En un sistema real se protege con un almacén de llaves (`KeyStore`) o un gestor de secretos. Por eso el `.gitignore` de este proyecto excluye los archivos `*.key`.

## JAR ejecutable (fat jar)

```bash
mvn clean package
java -jar target/mvn-rsa-1.0.0-SNAPSHOT-launcher.jar "Hola RSA"
```

El archivo `-launcher.jar` incluye todas las dependencias.

## Licencia

Código de ejemplo de uso libre con fines educativos.

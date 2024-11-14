package com.example.rsa;

import java.math.BigInteger;
import org.apache.log4j.Logger;

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class);

    public static void main(String[] args) {
        int bitLength = 1024;

        // Generazione delle chiavi
        RSAKeyGenerator keyGen = new RSAKeyGenerator(bitLength);
        BigInteger publicKey = keyGen.getPublicKey();
        BigInteger privateKey = keyGen.getPrivateKey();
        BigInteger modulus = keyGen.getModulus();

        logger.info("Chiave pubblica: " + publicKey);
        logger.info("Chiave privata: " + privateKey);
        logger.info("Modulo: " + modulus);

        // Messaggio da cifrare
        BigInteger message = new BigInteger("123456789");

        // Crittazione del messaggio
        RSAEncryptor encryptor = new RSAEncryptor();
        BigInteger encryptedMessage = encryptor.encrypt(message, publicKey, modulus);
        logger.info("Messaggio criptato: " + encryptedMessage);

        // Decrittazione del messaggio
        RSADecryptor decryptor = new RSADecryptor();
        BigInteger decryptedMessage = decryptor.decrypt(encryptedMessage, privateKey, modulus);
        logger.info("Messaggio decriptato: " + decryptedMessage);

        // Verifica che il messaggio sia uguale a quello originale
        if (message.equals(decryptedMessage)) {
            logger.info("La decrittazione ha avuto successo, il messaggio è identico all'originale.");
        } else {
            logger.error("Errore nella decrittazione, il messaggio non corrisponde all'originale.");
        }
    }
}

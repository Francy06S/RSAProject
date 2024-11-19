package com.example.rsa;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.apache.log4j.Logger;
import java.util.*;

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
        Scanner input = new Scanner(System.in);
        String parola;
        do {
            System.out.print("Inserisci il messaggio da inviare: ");
            parola = input.nextLine();
        } while (parola.equals(""));
        input.close();

        byte[] bytes = parola.getBytes(StandardCharsets.UTF_8);
        BigInteger numero = new BigInteger(1, bytes);
        logger.info("Numero originale: " + numero);

        // Calcolo della dimensione massima del blocco
        int lunghezzaModuloByte = (modulus.bitLength() + 7) / 8; // Lunghezza del modulo in byte
        int dimensioneBlocco = lunghezzaModuloByte - 1; // Dimensione massima per un blocco

        if (bytes.length > dimensioneBlocco) {
            logger.warn("Il messaggio è troppo lungo, sarà suddiviso in blocchi.");
            // Suddivisione del messaggio in blocchi
            List<byte[]> blocchi = new ArrayList<>();
            for (int i = 0; i < bytes.length; i += dimensioneBlocco) {
                int fine = Math.min(i + dimensioneBlocco, bytes.length);
                blocchi.add(Arrays.copyOfRange(bytes, i, fine));
            }

            // Criptazione dei blocchi
            RSAEncryptor encryptor = new RSAEncryptor();
            List<BigInteger> blocchiCifrati = new ArrayList<>();
            for (byte[] blocco : blocchi) {
                BigInteger bloccoNumero = new BigInteger(1, blocco);
                BigInteger cifrato = encryptor.encrypt(bloccoNumero, publicKey, modulus);
                blocchiCifrati.add(cifrato);
                logger.info("Blocco criptato: " + cifrato);
            }

            // Decrittazione dei blocchi
            RSADecryptor decryptor = new RSADecryptor();
            StringBuilder messaggioDecifrato = new StringBuilder();
            for (BigInteger bloccoCifrato : blocchiCifrati) {
                BigInteger decifrato = decryptor.decrypt(bloccoCifrato, privateKey, modulus);
                messaggioDecifrato.append(new String(decifrato.toByteArray(), StandardCharsets.UTF_8));
            }

            logger.info("Messaggio decriptato: " + messaggioDecifrato);

            // Verifica che il messaggio sia uguale a quello originale
            if (parola.equals(messaggioDecifrato.toString())) {
                logger.info("La decrittazione ha avuto successo, il messaggio è identico all'originale.");
            } else {
                logger.error("Errore nella decrittazione, il messaggio non corrisponde all'originale.");
            }
        } else {
            logger.info("Il messaggio rientra nei limiti della chiave, può essere criptato direttamente.");
            // Criptazione del messaggio
            RSAEncryptor encryptor = new RSAEncryptor();
            BigInteger encryptedMessage = encryptor.encrypt(numero, publicKey, modulus);
            logger.info("Messaggio criptato: " + encryptedMessage);

            // Decrittazione del messaggio
            RSADecryptor decryptor = new RSADecryptor();
            BigInteger decryptedMessage = decryptor.decrypt(encryptedMessage, privateKey, modulus);
            String parolaDecifrata = new String(decryptedMessage.toByteArray(), StandardCharsets.UTF_8);
            logger.info("Messaggio decriptato: " + parolaDecifrata);

            // Verifica che il messaggio sia uguale a quello originale
            if (numero.equals(decryptedMessage)) {
                logger.info("La decrittazione ha avuto successo, il messaggio è identico all'originale.");
            } else {
                logger.error("Errore nella decrittazione, il messaggio non corrisponde all'originale.");
            }
        }
    }
}

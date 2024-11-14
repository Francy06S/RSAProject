package com.example.rsa;

import java.math.BigInteger;

public class RSADecryptor {
    public BigInteger decrypt(BigInteger encryptedMessage, BigInteger d, BigInteger n) {
        return encryptedMessage.modPow(d, n);
    }
}


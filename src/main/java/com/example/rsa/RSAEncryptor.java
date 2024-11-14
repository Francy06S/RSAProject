package com.example.rsa;

import java.math.BigInteger;

public class RSAEncryptor {
    public BigInteger encrypt(BigInteger message, BigInteger e, BigInteger n) {
        return message.modPow(e, n);
    }
}


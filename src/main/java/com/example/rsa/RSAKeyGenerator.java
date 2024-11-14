package com.example.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAKeyGenerator {
    private BigInteger n, d, e;

    public RSAKeyGenerator(int bitLength) {
        SecureRandom secureRandom = new SecureRandom();
        BigInteger p = new BigInteger(bitLength / 2, 100, secureRandom);
        BigInteger q = new BigInteger(bitLength / 2, 100, secureRandom);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("65537"); // Valore comunemente usato per e
        d = e.modInverse(phi);
    }

    public BigInteger getPublicKey() { return e; }
    public BigInteger getPrivateKey() { return d; }
    public BigInteger getModulus() { return n; }
}
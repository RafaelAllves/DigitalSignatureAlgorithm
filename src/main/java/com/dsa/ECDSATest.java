package com.dsa;
import java.security.*;
import java.math.BigInteger;
import java.util.Arrays;

public class ECDSATest {

    public static void main(String[] args) throws Exception {
        int numIterations = 10000;
        byte[] message = "Implementation of the ECDSA class for key generation and message signing".getBytes();

        long totalKeyGenTime = 0;
        for (int i = 0; i < numIterations; i++) {
            long startTime = System.nanoTime();
            KeyPair keyPair = ECDSA.generateKeyPair();
            long endTime = System.nanoTime();
            totalKeyGenTime += (endTime - startTime);
            System.out.println("Tempo geracao de chave (nanosegundos): " + (endTime - startTime));
        }
        System.out.println("Tempo médio de geração de chave (nanosegundos): " + (totalKeyGenTime / numIterations));

        PrivateKey privateKey = keyPair.getPrivate();
        long totalSignTime = 0;
        for (int i = 0; i < numIterations; i++) {
            long startTime = System.nanoTime();
            BigInteger[] signature = ECDSA.signMessage(message, privateKey);  
            long endTime = System.nanoTime();
            totalSignTime += (endTime - startTime);
            System.out.println("Tempo assinatura (nanosegundos): " + (endTime - startTime));
        }
        System.out.println("Tempo médio de assinatura (nanosegundos): " + (totalSignTime / numIterations));

        PublicKey publicKey = keyPair.getPublic();
        BigInteger[] signature = ECDSA.signMessage(message, privateKey);  
        long totalVerifyTime = 0;
        for (int i = 0; i < numIterations; i++) {
            long startTime = System.nanoTime();
            boolean isVerified = ECDSA.verifySignature(message, signature, publicKey);  
            long endTime = System.nanoTime();
            totalVerifyTime += (endTime - startTime);
            System.out.println("Tempo verificação (nanosegundos): " + (endTime - startTime));
        }
        System.out.println("Tempo médio de verificação (nanosegundos): " + (totalVerifyTime / numIterations));
    }
}

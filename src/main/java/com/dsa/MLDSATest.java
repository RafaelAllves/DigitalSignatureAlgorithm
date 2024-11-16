package com.dsa;
import org.openquantumsafe.Signature;
import java.security.*;
import java.math.BigInteger;
import java.util.Arrays;

public class MLDSATest {

    public static void main(String[] args) throws Exception {
        int numIterations = 10000;
        byte[] message = "651A8CE312285A4D402A739E6F0E0B7F800DAB68DF032F0CB5A3EF46195BECEA".getBytes();

        long totalKeyGenTime = 0;
        for (int i = 0; i < numIterations; i++) {
            long startTime = System.nanoTime();
            Signature sig = new Signature("Dilithium3");
            byte[] publicKey = sig.generate_keypair();
            byte[] privateKey = sig.export_secret_key();
            long endTime = System.nanoTime();
            totalKeyGenTime += (endTime - startTime);
            System.out.println("Tempo geracao de chave (nanosegundos): " + (endTime - startTime));
        }
        System.out.println("Tempo médio de geração de chave (nanosegundos): " + (totalKeyGenTime / numIterations));

        Signature sig = new Signature("Dilithium3");
        byte[] publicKey = sig.generate_keypair();
        byte[] privateKey = sig.export_secret_key();

        long totalSignTime = 0;
        for (int i = 0; i < numIterations; i++) {
            long startTime = System.nanoTime();
            byte[] signature = sig.sign(message);
            long endTime = System.nanoTime();
            totalSignTime += (endTime - startTime);
            System.out.println("Tempo assinatura (nanosegundos): " + (endTime - startTime));
        }
        System.out.println("Tempo médio de assinatura (nanosegundos): " + (totalSignTime / numIterations));

        byte[] signature = sig.sign(message);
        long totalVerifyTime = 0;
        for (int i = 0; i < numIterations; i++) {
            long startTime = System.nanoTime();
            boolean isVerified = sig.verify(message, signature, publicKey);
            long endTime = System.nanoTime();
            totalVerifyTime += (endTime - startTime);
            System.out.println("Tempo verificação (nanosegundos): " + (endTime - startTime));
        }
        System.out.println("Tempo médio de verificação (nanosegundos): " + (totalVerifyTime / numIterations));
    }
}

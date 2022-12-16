package com.example.beans;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class JavaApiApplicationBeans {

    public static PublicKey publicKey;


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public JavaApiApplicationBeans() throws NoSuchAlgorithmException, NoSuchProviderException {
    }

    public static byte[] generateSessionKey() throws NoSuchAlgorithmException,
            NoSuchProviderException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
        kgen.init(256);
        SecretKey key = kgen.generateKey();
        byte[] symmKey = key.getEncoded();
        return symmKey;
    }
    public static String encryptUsingSessionKey(byte[] symmKey1, String data)
            throws InvalidCipherTextException, UnsupportedEncodingException {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                new AESEngine(), new PKCS7Padding());
        cipher.init(true, new KeyParameter(symmKey1));
        byte[] data1 = data.getBytes();
        int outputSize = cipher.getOutputSize(data1.length);
        byte[] tempOP = new byte[outputSize];
        int processLen = cipher.processBytes(data1, 0, data1.length, tempOP, 0);
        int outputLen = cipher.doFinal(tempOP, processLen);
        byte[] result = new byte[processLen + outputLen];
        System.arraycopy(tempOP, 0, result, 0, result.length);
        String encryptedpid = Base64.getEncoder().encodeToString(result);
        return encryptedpid;
    }

    public static void CkycEncryptionUtil() throws NoSuchAlgorithmException, NoSuchProviderException {
        String fileName = "server_pub.cer";
       // String path = "D:\\Code_Cersai_public_cert_requestdetails\\server_pub.cer"
      // URL publicKeyFileName = JavaApiApplicationBeans.class.getClassLoader().getResource("server_pub.cer");
       // File publicKeyFileName = new File("demo/src/main/resources/server_pub.cer");
       // String publicKeyFileName = file.getAbsolutePath();
     //  ClassLoader classLoader = JavaApiApplicationBeans.class.getClassLoader();
     //   URL publicKeyFileName = classLoader.getResource("server_pub.cer");
        ClassLoader classLoader = JavaApiApplicationBeans.class.getClassLoader();
        //File publicKeyFileName = new File(classLoader.getResource("server_pub.cer").getFile());

        InputStream inputStream = null;

       // System.out.println("InputStream: "+inputStream.toString());

        //InputStream fileInputStream = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance(
                    "X.509", "BC");
            System.out.println("hello");
            inputStream = classLoader.getResourceAsStream(fileName);
            System.out.println("hello2");
            X509Certificate cert = (X509Certificate) certFactory
                    .generateCertificate(inputStream);
            publicKey = cert.getPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Could not initialize encryption module",
                    e);
        } finally {
            if (inputStream != null)
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
    }
    public static String encryptUsingPublicKey(String data1) throws IOException,
            GeneralSecurityException {
        byte[] data = data1.getBytes();
        // has to validate with XML version no. in header
        //versionNo == XML version no.
        boolean versionNo;
       // if(versionNo=="1.1")
      //  {
        Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
           // Cipher pkCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding");
        if(publicKey == null){

            String Error_message = "File not Found";
            return Error_message;
        }else{
            pkCipher.init(1, publicKey);

            byte[] encSessionKey = pkCipher.doFinal(data);
            String keyencryptedencoded = Base64.getEncoder().encodeToString(encSessionKey);
            return keyencryptedencoded;
        }
      /*  }
        else
        {
            Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            pkCipher.init(1, this.publicKey);
            byte[] encSessionKey = pkCipher.doFinal(data);
            return encSessionKey;
        }*/
       
    }


}

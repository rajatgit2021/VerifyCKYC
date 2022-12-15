package com.example.beans;

public class OutputData {

    String encryptUsingSessionKey;

    String generateSessionKey;

    String encryptUsingPublicKey;


    public String getEncryptUsingPublicKey() {
        return encryptUsingPublicKey;
    }
    public void setEncryptUsingPublicKey(String encryptUsingPublicKey) {
        this.encryptUsingPublicKey = encryptUsingPublicKey;
    }

    public String getEncryptUsingSessionKey() {
        return encryptUsingSessionKey;
    }
    public void setEncryptUsingSessionKey(String encryptUsingSessionKey) {
        this.encryptUsingSessionKey = encryptUsingSessionKey;
    }
    public String getGenerateSessionKey() {
        return generateSessionKey;
    }
    public void setGenerateSessionKey(String generateSessionKey) {
        this.generateSessionKey = generateSessionKey;
    }
}

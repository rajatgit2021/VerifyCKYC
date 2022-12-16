package com.example.controller;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import com.example.beans.InputData;
import com.example.beans.JavaApiApplicationBeans;
import com.example.beans.OutputData;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
@Controller
public class JavaApiApplicationController {

    public JavaApiApplicationController() throws NoSuchAlgorithmException, NoSuchProviderException {
    }

        @RequestMapping(method = RequestMethod.GET, value="/generateSessionKey")
        @ResponseBody
        public String generateSessionKey() throws NoSuchAlgorithmException, NoSuchProviderException {
            System.out.println(JavaApiApplicationBeans.generateSessionKey().toString());
            return JavaApiApplicationBeans.generateSessionKey().toString();
        }

        byte[]  data = JavaApiApplicationBeans.generateSessionKey();

        @RequestMapping(method = RequestMethod.POST, value="/encryptUsingSessionKey")
        @ResponseBody
        public OutputData encryptUsingSessionKey (@RequestBody InputData inputData) throws InvalidCipherTextException, IOException, GeneralSecurityException, URISyntaxException {
            OutputData outputData1 = new OutputData();
            outputData1.setEncryptUsingSessionKey(JavaApiApplicationBeans.encryptUsingSessionKey(data,inputData.getData()));
            JavaApiApplicationBeans.CkycEncryptionUtil();
            outputData1.setEncryptUsingPublicKey(JavaApiApplicationBeans.encryptUsingPublicKey(inputData.getData()));
            outputData1.setGenerateSessionKey(Base64.getEncoder().encodeToString(data));
            return outputData1;
        }

    }

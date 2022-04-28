package com.example.decryptstring.controller;

import com.example.decryptstring.AES;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;

@RestController
@RequestMapping("/")
public class TestController {

    @GetMapping
    public  HashMap<String, String> index(@RequestParam String originalString) {
        //create new random key

        final SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] associatedData = "ProtocolVersion1".getBytes(StandardCharsets.UTF_8); //meta data you want to verify with the secret message
        HashMap<String, String> response = new HashMap<>();
        try {
            byte[] cipherText = new AES().encrypt(originalString, secretKey, associatedData);
            String decrypted = new AES().decrypt(cipherText, secretKey, associatedData);
            response.put("originalString", originalString);
            response.put("encryptedString", cipherText.toString());
            response.put("decryptedString", decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return response;
    }
}

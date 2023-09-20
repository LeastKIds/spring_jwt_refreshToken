package com.example.jwt.util.AES;

import com.example.jwt.util.jwt.filter.JwtAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String SECRET_KEY = "ef03e4280591adb37d0844d9ef1e2db4"; // 16, 24, or 32 characters
    private static final String INIT_VECTOR = "b07d9ce9bfa38991fc4d467cc638a6c8"; // 16 bytes

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String encrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(hexStringToByteArray(INIT_VECTOR));
            SecretKeySpec skeySpec = new SecretKeySpec(hexStringToByteArray(SECRET_KEY), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
            logger.error(ex.toString());
        }
        return null;
    }

    public static String decrypt(String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(hexStringToByteArray(INIT_VECTOR));
            SecretKeySpec skeySpec = new SecretKeySpec(hexStringToByteArray(SECRET_KEY), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
            logger.error(ex.toString());
        }

        return null;
    }
}
package com.venus.encrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public final class VenusAesUtil {
    // 固定加密种子（可替换为自定义密钥种子，建议长度≥16位）
    private static final String ENCRYPT_SEED = "venus"; // 自定义种子
    // AES算法名称
    private static final String AES_ALGORITHM = "AES";
    // 完整算法模式+填充方式（JDK 1.8兼容，消除默认值依赖）
    private static final String AES_ECB_PKCS5 = "AES";
    // 密钥长度（128位，JDK 1.8默认支持，无需解锁JCE）
    private static final int KEY_SIZE = 128;

    // 缓存固定AES密钥（类加载时生成，加解密复用，确保一致性）
    private static final SecretKey AES_FIXED_KEY;

    // 静态代码块：初始化固定密钥，仅执行一次
    static {
        try {
            // 1. 生成密钥生成器
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
            // 2. 初始化密钥生成器（JDK 1.8兼容，跨JDK无差异）
            SecureRandom secureRandom = new SecureRandom(ENCRYPT_SEED.getBytes(StandardCharsets.UTF_8));
            keyGenerator.init(KEY_SIZE, secureRandom);
            // 3. 生成原始密钥并转换为SecretKeySpec
            SecretKey originalKey = keyGenerator.generateKey();
            byte[] keyBytes = originalKey.getEncoded();
            AES_FIXED_KEY = new SecretKeySpec(keyBytes, AES_ALGORITHM);
        } catch (Exception e) {
            throw new RuntimeException("AES密钥初始化失败", e);
        }
    }

    /**
     * AES-ECB加密
     * @param content 待加密明文（UTF-8编码）
     * @return 加密后的Base64字符串，异常返回null
     */
    public static String encrypt(String content) {
        // 入参校验
        if (content == null || content.trim().isEmpty()) {
            return null;
        }
        try {
            // 1. 获取密码器并初始化（加密模式）
            Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5);
            cipher.init(Cipher.ENCRYPT_MODE, AES_FIXED_KEY);
            // 2. 明文转字节数组（统一UTF-8）
            byte[] contentBytes = content.getBytes(StandardCharsets.UTF_8);
            // 3. 执行加密
            byte[] encryptBytes = cipher.doFinal(contentBytes);
            // 4. 加密结果转Base64字符串返回
            return Base64.getEncoder().encodeToString(encryptBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES-ECB解密
     * @param encryptContent 加密后的Base64字符串
     * @return 解密后的明文（UTF-8编码），异常返回null
     */
    public static String decrypt(String encryptContent) {
        // 入参校验
        if (encryptContent == null || encryptContent.trim().isEmpty()) {
            return null;
        }
        try {
            // 1. 获取密码器并初始化（解密模式）
            Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5);
            cipher.init(Cipher.DECRYPT_MODE, AES_FIXED_KEY);
            // 2. Base64字符串转加密字节数组
            byte[] encryptBytes = Base64.getDecoder().decode(encryptContent);
            // 3. 执行解密
            byte[] decryptBytes = cipher.doFinal(encryptBytes);
            // 4. 解密结果转UTF-8字符串返回
            return new String(decryptBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }



    public static void main(String[] args) {
        String[] keys = {"venustech.taihe.db.CONF"};

        for (String key : keys) {
            String encryptString = encrypt(key);
            System.out.println("加密 = " + encryptString);
            String decryptString = decrypt(encryptString);
            System.out.println("解密 = " + decryptString);
        }
    }
}


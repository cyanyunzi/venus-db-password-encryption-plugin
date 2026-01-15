package com.venus.encrypt;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.logging.Logger;

public final class VenusAesUtil {
    private static final Logger logger = Logger.getLogger(VenusAesUtil.class.getName());

    // 固定加密种子（可替换为自定义密钥种子，建议长度≥16位）
    private static final String ENCRYPT_SEED = "venus";
    // AES算法名称
    private static final String AES_ALGORITHM = "AES";
    // 完整算法模式+填充方式（JDK 1.8兼容）
    private static final String AES_ECB_PKCS5 = "AES/ECB/PKCS5Padding";
    // 密钥长度（128位，JDK 1.8默认支持，无需解锁JCE）
    private static final int KEY_SIZE = 128;

    // 缓存固定AES密钥（类加载时生成，加解密复用，确保一致性）
    private static final SecretKey AES_FIXED_KEY;

    // 静态代码块：初始化固定密钥，仅执行一次
    static {
        try {
            // 使用SHA-256哈希算法从种子生成固定长度的密钥
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(ENCRYPT_SEED.getBytes(StandardCharsets.UTF_8));
            // 截取前16字节（128位）作为AES密钥
            byte[] keyBytes = new byte[KEY_SIZE / 8];
            System.arraycopy(hash, 0, keyBytes, 0, keyBytes.length);
            // 创建固定密钥
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
            logger.warning("VenusAesUtil encrypt error:" + e.getMessage());
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
            logger.warning("VenusAesUtil decrypt error:" + e.getMessage());
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
        String decryptString = decrypt("Do94bppAKoQDhFn8ODJrf+DKtQj4J/U3hYN1HGKeEfU=");
        System.out.println(decryptString);
    }
}

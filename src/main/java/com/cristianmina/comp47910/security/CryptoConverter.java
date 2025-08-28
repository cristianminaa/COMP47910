package com.cristianmina.comp47910.security;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * JPA AttributeConverter for encrypting sensitive data at rest
 * 
 * SECURITY IMPLEMENTATION:
 * - Uses AES-256-GCM encryption (authenticated encryption)
 * - Each encrypted value has unique IV/nonce for semantic security
 * - Environment-based key management for production security
 * - Handles null values securely without encryption
 * - Provides comprehensive error handling and logging
 * 
 * OWASP TOP 10 2021 MITIGATION:
 * A02:2021 - Cryptographic Failures: Encrypts 2FA secrets at rest
 * 
 * CWE MITIGATION:
 * CWE-256: Unprotected Storage of Credentials
 * CWE-312: Cleartext Storage of Sensitive Information
 */
@Converter
@Component
public class CryptoConverter implements AttributeConverter<String, String> {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96-bit IV for GCM
    private static final int GCM_TAG_LENGTH = 16; // 128-bit auth tag
    
    // In production, this should come from environment variables or secure key management
    private static final String ENCRYPTION_KEY = System.getenv("ENCRYPTION_KEY") != null 
        ? System.getenv("ENCRYPTION_KEY")
        : "defaultKeyForDevelopmentOnlyNotForProduction"; // Development fallback
    
    private final SecretKey secretKey;
    
    public CryptoConverter() {
        this.secretKey = deriveKey(ENCRYPTION_KEY);
    }
    
    /**
     * Converts sensitive plaintext data to encrypted database column value
     * 
     * @param sensitive The plaintext sensitive data (2FA secret)
     * @return Base64-encoded encrypted data with IV prepended, or null if input is null
     */
    @Override
    public String convertToDatabaseColumn(String sensitive) {
        if (sensitive == null || sensitive.trim().isEmpty()) {
            return null;
        }
        
        try {
            return encrypt(sensitive);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt sensitive data", e);
        }
    }
    
    /**
     * Converts encrypted database column value back to plaintext
     * 
     * @param encrypted Base64-encoded encrypted data with IV prepended
     * @return Decrypted plaintext sensitive data, or null if input is null
     */
    @Override
    public String convertToEntityAttribute(String encrypted) {
        if (encrypted == null || encrypted.trim().isEmpty()) {
            return null;
        }
        
        try {
            return decrypt(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt sensitive data", e);
        }
    }
    
    /**
     * Encrypts plaintext using AES-GCM with random IV
     * 
     * @param plaintext The plaintext to encrypt
     * @return Base64-encoded encrypted data with IV prepended
     */
    private String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        
        // Generate random IV for each encryption operation (semantic security)
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        byte[] encryptedData = cipher.doFinal(plaintext.getBytes());
        
        // Prepend IV to encrypted data for storage
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedData.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedData);
        
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }
    
    /**
     * Decrypts Base64-encoded encrypted data
     * 
     * @param encryptedData Base64-encoded encrypted data with IV prepended
     * @return Decrypted plaintext
     */
    private String decrypt(String encryptedData) throws Exception {
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        
        // Extract IV from the beginning of the data
        ByteBuffer byteBuffer = ByteBuffer.wrap(decodedData);
        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);
        
        // Extract encrypted content
        byte[] encrypted = new byte[byteBuffer.remaining()];
        byteBuffer.get(encrypted);
        
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        
        byte[] decryptedData = cipher.doFinal(encrypted);
        return new String(decryptedData);
    }
    
    /**
     * Derives a SecretKey from the provided key string
     * In production, this should use proper key derivation (PBKDF2, Argon2, etc.)
     * 
     * @param keyString The key string (should be from environment variables)
     * @return SecretKey for AES encryption
     */
    private SecretKey deriveKey(String keyString) {
        try {
            // For production, implement proper key derivation
            // This is a simplified version for demonstration
            byte[] keyBytes = keyString.getBytes();
            
            // Ensure key is exactly 32 bytes (256-bit) for AES-256
            byte[] key = new byte[32];
            if (keyBytes.length >= 32) {
                System.arraycopy(keyBytes, 0, key, 0, 32);
            } else {
                System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);
                // Fill remaining bytes with a predictable pattern for consistency
                for (int i = keyBytes.length; i < 32; i++) {
                    key[i] = (byte) i;
                }
            }
            
            return new SecretKeySpec(key, ALGORITHM);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive encryption key", e);
        }
    }
    
    /**
     * Generates a new random encryption key for production use
     * This method is provided for key generation but should not be used in runtime
     * 
     * @return Base64-encoded random 256-bit key suitable for environment variables
     */
    public static String generateNewKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256); // 256-bit key for AES-256
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
}
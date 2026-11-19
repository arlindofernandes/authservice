package com.auth.authservice.config;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Validated
public class JwtProperties {
    @NotBlank private String privateKey;
    @NotBlank private String publicKey;
    @NotBlank private String issuer;
    @NotBlank private String audience;
    @NotBlank private String keyId;
    @Positive private long expiration;

    @PostConstruct
    void validateKeys() {
        getPrivateKey();
        PublicKey verificationKey = getPublicKey();
        if (!(verificationKey instanceof RSAPublicKey rsaPublicKey) || rsaPublicKey.getModulus().bitLength() < 2048) {
            throw new IllegalStateException("JWT public key must be an RSA key with at least 2048 bits");
        }
    }

    public PrivateKey getPrivateKey() { return parsePrivateKey(privateKey); }
    public PublicKey getPublicKey() { return parsePublicKey(publicKey); }

    private PrivateKey parsePrivateKey(String encodedKey) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedKey)));
        } catch (IllegalArgumentException | GeneralSecurityException exception) {
            throw new IllegalStateException("JWT private key must be a Base64-encoded PKCS#8 RSA key", exception);
        }
    }

    private PublicKey parsePublicKey(String encodedKey) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encodedKey)));
        } catch (IllegalArgumentException | GeneralSecurityException exception) {
            throw new IllegalStateException("JWT public key must be a Base64-encoded X.509 RSA key", exception);
        }
    }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }
    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public long getExpiration() { return expiration; }
    public void setExpiration(long expiration) { this.expiration = expiration; }
    public void setPrivateKey(String privateKey) { this.privateKey = privateKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }
}

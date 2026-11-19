package com.auth.authservice.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.junit.jupiter.api.Test;

class JwtPropertiesTest {

    @Test
    void acceptsAnRsaKeyPairWithAtLeast2048Bits() throws Exception {
        JwtProperties properties = validProperties();
        assertThatCode(properties::validateKeys).doesNotThrowAnyException();
    }

    @Test
    void rejectsAnInvalidPublicKey() throws Exception {
        JwtProperties properties = validProperties();
        properties.setPublicKey("YWJj");
        assertThatIllegalStateException().isThrownBy(properties::validateKeys)
                .withMessage("JWT public key must be a Base64-encoded X.509 RSA key");
    }

    private JwtProperties validProperties() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        JwtProperties properties = new JwtProperties();
        properties.setPrivateKey(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        properties.setPublicKey(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        properties.setIssuer("auth-service-test");
        properties.setAudience("test-clients");
        properties.setKeyId("test-key-1");
        properties.setExpiration(3600000);
        return properties;
    }
}

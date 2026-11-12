package com.auth.authservice.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import org.junit.jupiter.api.Test;

class JwtPropertiesTest {

    @Test
    void acceptsABase64SecretWithAtLeast256Bits() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("27YptbdYXI75gMxTSGIjja1H5yX5b4HdFWgUOItNLzs=");

        assertThatCode(properties::validateSecret).doesNotThrowAnyException();
    }

    @Test
    void rejectsSecretsShorterThan256Bits() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("YWJj");

        assertThatIllegalStateException()
                .isThrownBy(properties::validateSecret)
                .withMessage("JWT secret must contain at least 256 bits");
    }

    @Test
    void rejectsSecretsThatAreNotBase64() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("not-a-base64-secret!");

        assertThatIllegalStateException()
                .isThrownBy(properties::validateSecret)
                .withMessage("JWT secret must be Base64 encoded");
    }
}

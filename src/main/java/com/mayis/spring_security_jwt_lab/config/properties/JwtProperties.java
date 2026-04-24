package com.mayis.spring_security_jwt_lab.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "application.security.jwt")
public record JwtProperties(
        String accessSecret,
        String refreshSecret,
        long accessExpiration,
        long refreshExpiration
) {
}

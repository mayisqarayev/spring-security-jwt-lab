package com.mayis.spring_security_jwt_lab.dto.response.auth;

import java.util.Set;
import java.util.UUID;

public record AuthResponse(
        UUID userId,
        String username,
        String email,
        String accessToken,
        String refreshToken,
        String tokenType,
        Set<String> authorities
) {
}

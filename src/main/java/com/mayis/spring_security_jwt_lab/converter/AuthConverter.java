package com.mayis.spring_security_jwt_lab.converter;

import com.mayis.spring_security_jwt_lab.dto.response.auth.AuthResponse;
import com.mayis.spring_security_jwt_lab.entity.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class AuthConverter {

    public AuthResponse toAuthResponse(User user, String accessToken, String refreshToken, Set<? extends GrantedAuthority> authorities) {
        return new AuthResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                accessToken,
                refreshToken,
                "Bearer",
                authorities.stream().map(GrantedAuthority::getAuthority).collect(java.util.stream.Collectors.toSet())
        );
    }
}

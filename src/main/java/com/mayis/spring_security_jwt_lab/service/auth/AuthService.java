package com.mayis.spring_security_jwt_lab.service.auth;

import com.mayis.spring_security_jwt_lab.converter.AuthConverter;
import com.mayis.spring_security_jwt_lab.dto.request.auth.LoginRequest;
import com.mayis.spring_security_jwt_lab.dto.request.auth.RefreshTokenRequest;
import com.mayis.spring_security_jwt_lab.dto.request.auth.RegisterRequest;
import com.mayis.spring_security_jwt_lab.dto.response.auth.AuthResponse;
import com.mayis.spring_security_jwt_lab.entity.role.Role;
import com.mayis.spring_security_jwt_lab.entity.token.RefreshToken;
import com.mayis.spring_security_jwt_lab.entity.user.User;
import com.mayis.spring_security_jwt_lab.entity.user.UserStatus;
import com.mayis.spring_security_jwt_lab.entity.user.relation.UserRole;
import com.mayis.spring_security_jwt_lab.repository.role.RoleRepository;
import com.mayis.spring_security_jwt_lab.repository.user.UserRepository;
import com.mayis.spring_security_jwt_lab.repository.user.UserRoleRepository;
import com.mayis.spring_security_jwt_lab.security.auth.CustomUserDetails;
import com.mayis.spring_security_jwt_lab.security.jwt.JwtService;
import com.mayis.spring_security_jwt_lab.service.token.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthConverter authConverter;

    @Transactional
    public AuthResponse register(RegisterRequest request, HttpServletRequest httpServletRequest) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already exists");
        }
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username already exists");
        }

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setStatus(UserStatus.ACTIVE);
        user.setEnabled(true);

        User savedUser = userRepository.save(user);

        Role defaultRole = roleRepository.findByName("USER")
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName("USER");
                    role.setDescription("Default application user role");
                    return roleRepository.save(role);
                });

        UserRole userRole = new UserRole();
        userRole.setUser(savedUser);
        userRole.setRole(defaultRole);
        userRoleRepository.save(userRole);
        savedUser.getUserRoles().add(userRole);

        return issueTokens(savedUser, httpServletRequest);
    }

    public AuthResponse login(LoginRequest request, HttpServletRequest httpServletRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.usernameOrEmail(), request.password())
        );

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return issueTokens(user, httpServletRequest);
    }

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request, HttpServletRequest httpServletRequest) {
        String refreshToken = request.refreshToken();
        String subject = jwtService.extractRefreshSubject(refreshToken);
        User user = userRepository.findByEmail(subject)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        CustomUserDetails userDetails = new CustomUserDetails(user);

        if (!jwtService.isRefreshTokenValid(refreshToken, userDetails)) {
            throw new IllegalArgumentException("Refresh token is invalid");
        }

        RefreshToken storedToken = refreshTokenService.getActiveToken(refreshToken);
        refreshTokenService.markAsUsed(storedToken);
        refreshTokenService.revoke(refreshToken);

        return issueTokens(user, httpServletRequest);
    }

    public void logout(RefreshTokenRequest request) {
        refreshTokenService.revoke(request.refreshToken());
    }

    private AuthResponse issueTokens(User user, HttpServletRequest httpServletRequest) {
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String accessToken = jwtService.generateAccessToken(userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails);

        refreshTokenService.save(
                user,
                refreshToken,
                httpServletRequest.getRemoteAddr(),
                httpServletRequest.getHeader("User-Agent"),
                jwtService.extractRefreshExpiration(refreshToken)
        );

        return authConverter.toAuthResponse(
                user,
                accessToken,
                refreshToken,
                new java.util.LinkedHashSet<>(userDetails.getAuthorities())
        );
    }
}

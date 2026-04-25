package com.mayis.spring_security_jwt_lab.security.jwt;

import com.mayis.spring_security_jwt_lab.config.properties.JwtProperties;
import com.mayis.spring_security_jwt_lab.security.auth.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class JwtService {

    private static final String TOKEN_TYPE_CLAIM = "token_type";
    private static final String AUTHORITIES_CLAIM = "authorities";

    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String generateAccessToken(CustomUserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, JwtTokenType.ACCESS.name());
        claims.put(AUTHORITIES_CLAIM, userDetails.getAuthorities().stream().map(Object::toString).toList());
        return buildAccessToken(claims, userDetails);
    }

    public String generateRefreshToken(CustomUserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, JwtTokenType.REFRESH.name());
        return buildRefreshToken(claims, userDetails);
    }

    public String extractAccessSubject(String token) {
        return parseAccessClaims(token).getSubject();
    }

    public String extractRefreshSubject(String token) {
        return parseRefreshClaims(token).getSubject();
    }

    public Instant extractRefreshExpiration(String token) {
        return parseRefreshClaims(token).getExpiration().toInstant();
    }

    public boolean isAccessTokenValid(String token, UserDetails userDetails) {
        Claims claims = parseAccessClaims(token);
        return userDetails.getUsername().equals(claims.getSubject())
                && JwtTokenType.ACCESS.name().equals(claims.get(TOKEN_TYPE_CLAIM, String.class))
                && claims.getExpiration().toInstant().isAfter(Instant.now());
    }

    public boolean isRefreshTokenValid(String token, UserDetails userDetails) {
        Claims claims = parseRefreshClaims(token);
        return userDetails.getUsername().equals(claims.getSubject())
                && JwtTokenType.REFRESH.name().equals(claims.get(TOKEN_TYPE_CLAIM, String.class))
                && claims.getExpiration().toInstant().isAfter(Instant.now());
    }

    public Collection<?> extractAuthorities(String token) {
        return parseAccessClaims(token).get(AUTHORITIES_CLAIM, Collection.class);
    }

    private String buildAccessToken(Map<String, Object> claims, UserDetails userDetails) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(jwtProperties.accessExpiration())))
                .id(UUID.randomUUID().toString())
                .signWith(accessSigningKey())
                .compact();
    }

    private String buildRefreshToken(Map<String, Object> claims, UserDetails userDetails) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(jwtProperties.refreshExpiration())))
                .id(UUID.randomUUID().toString())
                .signWith(refreshSigningKey())
                .compact();
    }

    private Claims parseAccessClaims(String token) {
        return Jwts.parser()
                .verifyWith(accessSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Claims parseRefreshClaims(String token) {
        return Jwts.parser()
                .verifyWith(refreshSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey accessSigningKey() {
        return buildSecretKey(jwtProperties.accessSecret());
    }

    private SecretKey refreshSigningKey() {
        return buildSecretKey(jwtProperties.refreshSecret());
    }

    private SecretKey buildSecretKey(String secret) {
        byte[] keyBytes;

        try {
            keyBytes = Decoders.BASE64.decode(secret);
        } catch (IllegalArgumentException exception) {
            keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        }

        return Keys.hmacShaKeyFor(keyBytes);
    }
}

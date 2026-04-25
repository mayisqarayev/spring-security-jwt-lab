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
import java.util.function.Function;

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
        return buildToken(claims, userDetails, jwtProperties.accessExpiration(), accessSigningKey());
    }

    public String generateRefreshToken(CustomUserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, JwtTokenType.REFRESH.name());
        return buildToken(claims, userDetails, jwtProperties.refreshExpiration(), refreshSigningKey());
    }

    public String extractSubject(String token, JwtTokenType tokenType) {
        return extractClaim(token, Claims::getSubject, tokenType);
    }

    public Instant extractExpiration(String token, JwtTokenType tokenType) {
        Date expiration = extractClaim(token, Claims::getExpiration, tokenType);
        return expiration.toInstant();
    }

    public String extractTokenType(String token, JwtTokenType tokenType) {
        return extractAllClaims(token, tokenType).get(TOKEN_TYPE_CLAIM, String.class);
    }

    public boolean isAccessTokenValid(String token, UserDetails userDetails) {
        return isTokenValid(token, userDetails, JwtTokenType.ACCESS);
    }

    public boolean isRefreshTokenValid(String token, UserDetails userDetails) {
        return isTokenValid(token, userDetails, JwtTokenType.REFRESH);
    }

    public Collection<?> extractAuthorities(String token) {
        return extractAllClaims(token, JwtTokenType.ACCESS).get(AUTHORITIES_CLAIM, Collection.class);
    }

    private boolean isTokenValid(String token, UserDetails userDetails, JwtTokenType tokenType) {
        String subject = extractSubject(token, tokenType);
        String resolvedType = extractTokenType(token, tokenType);
        return subject.equals(userDetails.getUsername())
                && resolvedType.equals(tokenType.name())
                && extractExpiration(token, tokenType).isAfter(Instant.now());
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expirationSeconds,
            SecretKey secretKey
    ) {
        Instant now = Instant.now();
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(expirationSeconds)))
                .id(UUID.randomUUID().toString())
                .signWith(secretKey)
                .compact();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver, JwtTokenType tokenType) {
        Claims claims = extractAllClaims(token, tokenType);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token, JwtTokenType tokenType) {
        return Jwts.parser()
                .verifyWith(resolveSigningKey(tokenType))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey resolveSigningKey(JwtTokenType tokenType) {
        return tokenType == JwtTokenType.ACCESS ? accessSigningKey() : refreshSigningKey();
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

package com.mayis.spring_security_jwt_lab.repository.token;

import com.mayis.spring_security_jwt_lab.entity.token.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    List<RefreshToken> findAllByUserIdAndRevokedFalse(UUID userId);

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    void deleteByExpiresAtBefore(Instant instant);
}

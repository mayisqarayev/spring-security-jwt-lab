package com.mayis.spring_security_jwt_lab.repository.audit;

import com.mayis.spring_security_jwt_lab.entity.audit.AuthAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AuthAuditLogRepository extends JpaRepository<AuthAuditLog, UUID> {
}

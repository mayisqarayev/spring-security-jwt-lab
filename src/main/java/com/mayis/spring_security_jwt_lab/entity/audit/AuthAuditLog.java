package com.mayis.spring_security_jwt_lab.entity.audit;

import com.mayis.spring_security_jwt_lab.entity.base.BaseEntity;
import com.mayis.spring_security_jwt_lab.entity.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "auth_audit_logs")
public class AuthAuditLog extends BaseEntity {

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private AuditAction action;

    @Column(length = 255)
    private String email;

    @Column(length = 100)
    private String ipAddress;

    @Column(length = 255)
    private String userAgent;

    @Column(nullable = false)
    private boolean success;

    @Column(length = 500)
    private String failureReason;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
}

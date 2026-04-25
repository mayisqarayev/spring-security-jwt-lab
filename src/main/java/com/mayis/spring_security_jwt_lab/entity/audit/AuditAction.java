package com.mayis.spring_security_jwt_lab.entity.audit;

public enum AuditAction {
    REGISTER,
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    TOKEN_REFRESH,
    LOGOUT,
    TOKEN_REVOKED
}

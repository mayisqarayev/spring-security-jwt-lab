package com.mayis.spring_security_jwt_lab.repository.role;

import com.mayis.spring_security_jwt_lab.entity.role.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    boolean existsByName(String name);

    Optional<Permission> findByName(String name);
}

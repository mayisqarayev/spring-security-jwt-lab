package com.mayis.spring_security_jwt_lab.repository.role;

import com.mayis.spring_security_jwt_lab.entity.role.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {

    boolean existsByName(String name);

    Optional<Role> findByName(String name);
}

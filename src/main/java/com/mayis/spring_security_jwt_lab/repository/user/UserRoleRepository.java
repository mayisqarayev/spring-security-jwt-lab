package com.mayis.spring_security_jwt_lab.repository.user;

import com.mayis.spring_security_jwt_lab.entity.user.relation.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {

    boolean existsByUserIdAndRoleId(UUID userId, UUID roleId);

    List<UserRole> findAllByUserId(UUID userId);
}

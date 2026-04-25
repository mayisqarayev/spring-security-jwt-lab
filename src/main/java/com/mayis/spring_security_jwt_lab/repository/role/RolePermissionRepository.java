package com.mayis.spring_security_jwt_lab.repository.role;

import com.mayis.spring_security_jwt_lab.entity.role.relation.RolePermission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface RolePermissionRepository extends JpaRepository<RolePermission, UUID> {

    boolean existsByRoleIdAndPermissionId(UUID roleId, UUID permissionId);

    List<RolePermission> findAllByRoleId(UUID roleId);
}

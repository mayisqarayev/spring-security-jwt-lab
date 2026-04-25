package com.mayis.spring_security_jwt_lab.entity.role;

import com.mayis.spring_security_jwt_lab.entity.base.BaseEntity;
import com.mayis.spring_security_jwt_lab.entity.role.relation.RolePermission;
import com.mayis.spring_security_jwt_lab.entity.user.relation.UserRole;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@Entity
@Table(name = "roles")
public class Role extends BaseEntity {

    @Column(nullable = false, unique = true, length = 100)
    private String name;

    @Column(length = 255)
    private String description;

    @OneToMany(mappedBy = "role")
    private Set<RolePermission> rolePermissions = new HashSet<>();

    @OneToMany(mappedBy = "role")
    private Set<UserRole> userRoles = new HashSet<>();
}

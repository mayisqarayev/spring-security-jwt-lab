package com.mayis.spring_security_jwt_lab.security.auth;

import com.mayis.spring_security_jwt_lab.entity.role.relation.RolePermission;
import com.mayis.spring_security_jwt_lab.entity.user.User;
import com.mayis.spring_security_jwt_lab.entity.user.relation.UserRole;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

public class CustomUserDetails implements UserDetails {

    private final UUID id;
    private final String username;
    private final String password;
    private final boolean enabled;
    private final boolean accountNonExpired;
    private final boolean credentialsNonExpired;
    private final boolean accountNonLocked;
    private final Set<GrantedAuthority> authorities;

    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.username = user.getEmail();
        this.password = user.getPasswordHash();
        this.enabled = user.isEnabled();
        this.accountNonExpired = user.isAccountNonExpired();
        this.credentialsNonExpired = user.isCredentialsNonExpired();
        this.accountNonLocked = user.isAccountNonLocked();
        this.authorities = resolveAuthorities(user);
    }

    public UUID getId() {
        return id;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    private Set<GrantedAuthority> resolveAuthorities(User user) {
        Set<GrantedAuthority> mappedAuthorities = new LinkedHashSet<>();

        for (UserRole userRole : user.getUserRoles()) {
            String roleName = userRole.getRole().getName();
            mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + roleName));

            for (RolePermission rolePermission : userRole.getRole().getRolePermissions()) {
                mappedAuthorities.add(new SimpleGrantedAuthority(rolePermission.getPermission().getName()));
            }
        }

        return mappedAuthorities;
    }
}

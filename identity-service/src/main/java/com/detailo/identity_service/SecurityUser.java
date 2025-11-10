package com.detailo.identity_service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.stream.Collectors;
import com.detailo.identity_service.models.User;

// This class wraps our User entity and translates it for Spring Security
public class SecurityUser implements UserDetails {

    private final User user;

    public SecurityUser(User user) {
        this.user = user;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Translate our Set<Role> into a Collection<GrantedAuthority>
        return user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Or return user.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Or return user.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Or return user.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }
}
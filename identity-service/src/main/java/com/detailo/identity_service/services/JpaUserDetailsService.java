package com.detailo.identity_service.services;

import com.detailo.identity_service.SecurityUser;
import com.detailo.identity_service.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public JpaUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // "username" here is the email
        return userRepository
                .findByEmail(username)
                .map(SecurityUser::new) // Wrap the found User in our SecurityUser
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + username));
    }
}
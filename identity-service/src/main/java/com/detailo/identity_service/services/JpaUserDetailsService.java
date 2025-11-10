package com.detailo.identity_service.services;

import com.detailo.identity_service.SecurityUser;
import com.detailo.identity_service.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(JpaUserDetailsService.class);
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
                .orElseThrow(() -> {
                    String maskedUsername = maskEmail(username);
                    logger.debug("User not found for authentication attempt: {}", maskedUsername);
                    return new UsernameNotFoundException("Invalid credentials");
                });
    }

    private String maskEmail(String email) {
        if (email == null || email.isEmpty()) {
            return "***";
        }
        int atIndex = email.indexOf('@');
        if (atIndex <= 0) {
            return "***";
        }
        String localPart = email.substring(0, atIndex);
        String domain = email.substring(atIndex);
        if (localPart.length() <= 2) {
            return "***" + domain;
        }
        return localPart.substring(0, 1) + "***" + localPart.substring(localPart.length() - 1) + domain;
    }
}
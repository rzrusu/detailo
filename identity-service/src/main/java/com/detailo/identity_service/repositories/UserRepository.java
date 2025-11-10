package com.detailo.identity_service.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;
import com.detailo.identity_service.models.User;

public interface UserRepository extends JpaRepository<User, UUID> {
    
    // This is the crucial method Spring Security will use
    Optional<User> findByEmail(String email);
}
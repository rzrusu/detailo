package com.detailo.identity_service.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import com.detailo.identity_service.models.Role;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(String name);

}

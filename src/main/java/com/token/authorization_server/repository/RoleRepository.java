package com.token.authorization_server.repository;

import com.token.authorization_server.entitiy.Role;
import com.token.authorization_server.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByRole(RoleName roleName);
}

package com.token.authorization_server.repository;

import com.token.authorization_server.entitiy.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ClientRepository extends JpaRepository<Client, Integer> {

    Optional<Client> findByClientId(String clientId);

}

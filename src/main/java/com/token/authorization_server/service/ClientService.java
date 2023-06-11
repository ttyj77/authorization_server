package com.token.authorization_server.service;

import com.token.authorization_server.dto.CreateClientDto;
import com.token.authorization_server.dto.MessageDto;
import com.token.authorization_server.entitiy.Client;
import com.token.authorization_server.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientService implements RegisteredClientRepository {
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void save(RegisteredClient registeredClient) {

    }


    @Override
    public RegisteredClient findById(String id) {
        System.out.println("============================id");
        System.out.println("id = " + id);
        Client client = clientRepository.findByClientId(id)
                .orElseThrow(() -> new RuntimeException("client not found"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        System.out.println("========================client id");
        System.out.println("clientId = " + clientId);
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new RuntimeException("clientId not found"));
        return Client.toRegisteredClient(client);
    }

    public MessageDto create(CreateClientDto dto) {
        Client client = clientFromDto(dto);
        clientRepository.save(client);
        return new MessageDto("client " + client.getClientId() + " saved ");
    }

    private Client clientFromDto(CreateClientDto dto) {
        System.out.println("ClientService.clientFromDto");
        System.out.println("dto = " + dto);
        System.out.println("8888888888888888888888888888888888888888888888877897987");
        Client client = Client.builder()
                .clientId(dto.getClientId())
                .clientSecret(passwordEncoder.encode(dto.getClientSecret()))
                .authenticationMethods(dto.getAuthenticationMethods())
                .authorizationGrantTypes(dto.getAuthorizationGrantTypes())
                .redirectUris(dto.getRedirectUris())
                .scopes(dto.getScopes())
                .requireProofKey(dto.isRequireProofKey())
                .build();
        return client;

    }


}

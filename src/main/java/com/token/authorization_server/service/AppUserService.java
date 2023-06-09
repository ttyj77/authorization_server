package com.token.authorization_server.service;

import com.token.authorization_server.dto.CreateAppUserDto;
import com.token.authorization_server.dto.MessageDto;
import com.token.authorization_server.entitiy.AppUser;
import com.token.authorization_server.entitiy.Role;
import com.token.authorization_server.enums.RoleName;
import com.token.authorization_server.repository.AppUserRepository;
import com.token.authorization_server.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppUserService {
    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public MessageDto createUser(CreateAppUserDto dto) {
        System.out.println("AppUserService.createUser");
        System.out.println("===========================================================================");
        System.out.println("dto = " + dto);
        AppUser appUser = AppUser.builder()
                .username(dto.username())
                .password(passwordEncoder.encode(dto.password()))
                .build();
        Set<Role> roles = new HashSet<>();
        dto.roles().forEach(r -> {
            Role role = roleRepository.findByRole(RoleName.valueOf(r))
                    .orElseThrow(() -> new RuntimeException("role not found"));
            roles.add(role);
        });
        appUser.setRoles(roles);
        appUserRepository.save(appUser);
        return new MessageDto("user " + appUser.getUsername() + " saved");
    }
}

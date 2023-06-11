package com.token.authorization_server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthorizationServer2Application /*implements CommandLineRunner*/ {
//    @Autowired
//    RoleRepository repository;

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServer2Application.class, args);
    }

//    @Override
//    public void run(String... args) throws Exception {
//        Role adminRole = Role.builder().role(RoleName.ROLE_ADMIN).build();
//        Role userRole = Role.builder().role(RoleName.ROLE_USER).build();
//        repository.save(adminRole);
//        repository.save(userRole);
//    }
}

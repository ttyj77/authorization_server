package com.token.authorization_server.controller;

import com.token.authorization_server.dto.CreateAppUserDto;
import com.token.authorization_server.dto.MessageDto;
import com.token.authorization_server.service.AppUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AppUserService appUserService;

    @PostMapping("/create")
    public ResponseEntity<MessageDto> createDto(@RequestBody CreateAppUserDto dto) {
        System.out.println("dto = " + dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(appUserService.createUser(dto));
    }
}

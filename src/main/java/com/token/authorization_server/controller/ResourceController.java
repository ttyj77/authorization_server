//package com.token.authorization_server.controller;
//
//import com.token.authorization_server.dto.MessageDto;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.security.core.Authentication;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//@RestController
//@RequestMapping("/resource")
//public class ResourceController {
//    @GetMapping("/user")
//    public ResponseEntity<MessageDto> user(Authentication authentication){
//        return ResponseEntity.ok(new MessageDto("hello " + authentication.getName()));
//    }
//
//    @GetMapping("/admin")
//    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
//    public ResponseEntity<MessageDto> admin(Authentication authentication){
//        return ResponseEntity.ok(new MessageDto("hello Mr." + authentication.getName()));
//    }
//}

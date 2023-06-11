package com.token.authorization_server.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@Slf4j
public class LoginController {

    @GetMapping("/login")
    public String login() {
        System.out.println("LoginController.login");

        return "/login";
    }

//    @GetMapping("/oauth/confirm_access")
//    public String confirm(HttpServletRequest request) {
//        System.out.println("=================================");
//        AuthorizationRequest authorizationRequest = (AuthorizationRequest) request.getSession().getAttribute("authorizationRequest");
//        log.error("## => {}", authorizationRequest.getClientId()); // 세션에 로그인에 필요한 정보가 담겨 있다.
//        return "confirm";
//    }

//    @GetMapping("/logout")
//    public String logout() {
//        System.out.println("===================================================");
//        System.out.println("LoginController.logout");
//        return "/logout";
//    }

    @GetMapping("/logout-proc")
    public String losamplegout() {
        System.out.println("===================================================");
        System.out.println("LoginController.sample");
        return "/logout";
    }


    @PostMapping("/logout")
    public String logoutOK(HttpSecurity http) throws Exception {
        http
                .logout().logoutSuccessUrl("login?logout")
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
                .clearAuthentication(true);
        return "login?logout";
    }

    @GetMapping("/admin")
    public String admin() {
        return "sample";
    }

    @GetMapping("/user")
    public String user() {
        return "sample";
    }

}

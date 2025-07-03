package com.dcode.Security.controller;

import com.dcode.Security.entity.UserAuthEntity;
import com.dcode.Security.service.UserAuthEntityService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class UserAuthController {
    private UserAuthEntityService userAuthEntityService;
    private PasswordEncoder passwordEncoder;

    public UserAuthController(UserAuthEntityService userAuthEntityService, PasswordEncoder passwordEncoder) {
        this.userAuthEntityService = userAuthEntityService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody UserAuthEntity userAuthEntity) {
        userAuthEntity.setPassword(passwordEncoder.encode(userAuthEntity.getPassword()));
        userAuthEntityService.save(userAuthEntity);
        return ResponseEntity.ok("User registered successfully");
    }
}

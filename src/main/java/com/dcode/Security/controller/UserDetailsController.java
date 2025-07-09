package com.dcode.Security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserDetailsController {

    @GetMapping("/")
    public String defaultHomePage() {
        return "You are authenticated";
    }

    @GetMapping("/users")
    public String getUserDetails() {
        return "User details fetched successfully";
    }

}

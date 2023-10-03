package com.codewithabdel.springsecurityudemy.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {

    @GetMapping("/welcome")
    public  String tesHello(){
        return "test welcome";
    }
}

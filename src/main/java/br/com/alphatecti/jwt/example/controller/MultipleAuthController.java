package br.com.alphatecti.jwt.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MultipleAuthController {
   
    @GetMapping("/api/ping")
    public String getPing() {
        return "OK";
    }
    
    @PostMapping("/widget/ping")
    public String getPing(String value) {
        return "OK";
    }
    
    @GetMapping("/login")
    public String login() {
        return "OK";
    }
}
package br.com.alphatecti.jwt.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LDAPTestController {
   
    @GetMapping("/secure/admin/test")
    public String getPing() {
        return "OK";
    }
    
    @GetMapping("/secure/user/test")
    public String getPing(String value) {
        return "OK";
    }
    
    @GetMapping("/ldap/login")
    public String login() {
        return "OK";
    }
}
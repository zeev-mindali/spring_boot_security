package com.jb.security.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SimpleRest {
    @GetMapping("/test")
    public String getRestTest(){
        return "Me working :)";
    }
}

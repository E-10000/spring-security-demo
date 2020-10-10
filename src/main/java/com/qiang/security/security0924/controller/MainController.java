package com.qiang.security.security0924.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/")
    public String hello(){
        System.out.println("hello");
        return "hello";
    }

    @GetMapping("/test")
    public String test(){
        return "test";
    }

    @GetMapping("/admin")
    public String admin(){
        return "hello admin";
    }

    @GetMapping("/user")
    public String user(){
        return "hello user";
    }

    @GetMapping("app")
    public String app(){
        return "hello app";
    }
}

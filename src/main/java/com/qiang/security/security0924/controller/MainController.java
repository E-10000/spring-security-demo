package com.qiang.security.security0924.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;


@Controller
public class MainController {

    @GetMapping("/")
    public String hello(){
        System.out.println("hello");
        return "redirect:index.html";
    }

    @ResponseBody
    @GetMapping("/test")
    public String test(){
        return "test";
    }

    @ResponseBody
    @GetMapping("/admin")
    public String admin(){
        return "hello admin";
    }

    @ResponseBody
    @GetMapping("/user")
    public String user(){
        return "hello user";
    }

    @ResponseBody
    @GetMapping("app")
    public String app(){
        return "hello app";
    }
}

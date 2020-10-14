package com.qiang.security.security0924;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@MapperScan(value = "com.qiang.security.security0924.mapper")
@SpringBootApplication
public class Security0924Application {

    public static void main(String[] args) {
        SpringApplication.run(Security0924Application.class, args);
    }

}

package com.jwt;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
@MapperScan(basePackages = {"com.jwt.config"})
public class JWTServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(JWTServerApplication.class, args);
    }

}

package com.formLoginRBAC;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
@MapperScan(basePackages = {"com.formLogin"})
public class FormLoginRBACApplication {

    public static void main(String[] args) {
        SpringApplication.run(FormLoginRBACApplication.class, args);
    }

}

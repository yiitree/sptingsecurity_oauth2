package com.formLogin;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
@MapperScan(basePackages = {"com.formLogin"})
public class FormLoginServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(FormLoginServerApplication.class, args);
    }

}

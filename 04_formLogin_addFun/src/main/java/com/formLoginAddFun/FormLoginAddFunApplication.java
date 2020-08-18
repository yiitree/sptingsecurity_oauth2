package com.formLoginAddFun;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
@MapperScan(basePackages = {"com.formLoginAddFun"})
public class FormLoginAddFunApplication {

    public static void main(String[] args) {
        SpringApplication.run(FormLoginAddFunApplication.class, args);
    }

}

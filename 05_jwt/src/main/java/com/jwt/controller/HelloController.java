package com.jwt.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
public class HelloController {

    @GetMapping("/sys_user")
    public String hello() {
        return "world";
    }

    @PostMapping("/sys_log")
    public String hello1() {
        return "world1";
    }

}

package com.formLoginRBAC.config.auth.imagecode;

import java.time.LocalDateTime;

public class CaptchaCode {

    private final String code;

    private final LocalDateTime expireTime;


    public CaptchaCode(String code, int expireAfterSeconds){
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireAfterSeconds);
    }

    public boolean isExpired(){
        return  LocalDateTime.now().isAfter(expireTime);
    }

    public String getCode() {
        return code;
    }
}

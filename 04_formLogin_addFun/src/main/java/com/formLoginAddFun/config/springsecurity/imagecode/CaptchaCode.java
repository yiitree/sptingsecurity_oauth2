package com.formLoginAddFun.config.springsecurity.imagecode;

import java.time.LocalDateTime;

public class CaptchaCode {

    //验证码文字
    private String code;

    //验证码失效时间
    private LocalDateTime expireTime;

    public CaptchaCode(String code, int expireAfterSeconds){
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireAfterSeconds);
    }

    //验证码是否失效
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expireTime);
    }

    public String getCode() {
        return code;
    }

}

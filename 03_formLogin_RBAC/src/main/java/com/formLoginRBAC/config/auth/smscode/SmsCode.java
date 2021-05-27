package com.formLoginRBAC.config.auth.smscode;

import java.time.LocalDateTime;

public class SmsCode {

    private final String code; //短信验证码

    private final LocalDateTime expireTime; //过期时间

    private final String mobile;


    public SmsCode(String code, int expireAfterSeconds,String mobile){
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireAfterSeconds);
        this.mobile = mobile;
    }

    public boolean isExpired(){
        return  LocalDateTime.now().isAfter(expireTime);
    }

    public String getCode() {
        return code;
    }

    public String getMobile() {
        return mobile;
    }
}

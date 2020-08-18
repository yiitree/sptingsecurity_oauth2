package com.formLoginAddFun.config.springsecurity.smscode;

import java.time.LocalDateTime;

public class SmsCode {

    //短信验证码
    private String code;

    //过期时间
    private LocalDateTime expireTime;

    private String mobile;


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

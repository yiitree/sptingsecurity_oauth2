package com.formLoginRBAC.config.auth.smscode;

import com.formLoginRBAC.config.springsecurity.service.MyUserDetailsService;
import com.formLoginRBAC.config.springsecurity.handler.MyAuthenticationFailureHandler;
import com.formLoginRBAC.config.springsecurity.handler.MyAuthenticationSuccessHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class SmsCodeSecurityConfig
        extends SecurityConfigurerAdapter<DefaultSecurityFilterChain,HttpSecurity> {

    @Resource
    MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Resource
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    @Resource
    MyUserDetailsService myUserDetailsService;

    @Resource
    SmsCodeValidateFilter smsCodeValidateFilter;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        SmsCodeAuthenticationFilter smsCodeAuthenticationFilter = new SmsCodeAuthenticationFilter();
        smsCodeAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        smsCodeAuthenticationFilter.setAuthenticationSuccessHandler(myAuthenticationSuccessHandler);
        smsCodeAuthenticationFilter.setAuthenticationFailureHandler(myAuthenticationFailureHandler);

        SmsCodeAuthenticationProvider smsCodeAuthenticationProvider = new SmsCodeAuthenticationProvider();
        smsCodeAuthenticationProvider.setUserDetailsService(myUserDetailsService);

        http.addFilterBefore(smsCodeValidateFilter,UsernamePasswordAuthenticationFilter.class);
        http.authenticationProvider(smsCodeAuthenticationProvider)
                .addFilterAfter(smsCodeAuthenticationFilter,UsernamePasswordAuthenticationFilter.class);
    }

}

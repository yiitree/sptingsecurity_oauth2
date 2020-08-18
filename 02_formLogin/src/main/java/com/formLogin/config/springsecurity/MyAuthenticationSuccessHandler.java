package com.formLogin.config.springsecurity;

import com.formLogin.config.exception.AjaxResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录成功结果处理
 */
@Component
public class MyAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Value("${spring.security.loginType}")
    private String loginType;

    private static ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws ServletException, IOException {

        if("JSON".equalsIgnoreCase(loginType)){
            response.setContentType("application/json;charset=UTF-8");
            // 设置登录成功返回内容
            response.getWriter().write(objectMapper.writeValueAsString(AjaxResponse.success()));
//            response.getWriter().write(objectMapper.writeValueAsString(
//                    AjaxResponse.success("/index")
//            ));
        }else{
            //跳转到登陆之前请求的页面
            super.onAuthenticationSuccess(request,response,authentication);
        }
    }
}

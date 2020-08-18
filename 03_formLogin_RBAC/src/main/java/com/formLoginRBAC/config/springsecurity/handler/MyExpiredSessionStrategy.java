package com.formLoginRBAC.config.springsecurity.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 自定义超时管理策略
 * @Author: 曾睿
 * @Date: 2020/8/17 13:49
 */
public class MyExpiredSessionStrategy implements SessionInformationExpiredStrategy {
    //jackson的JSON处理对象
    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        Map<String, Object> map = new HashMap<>();
        map.put("code", 0);
        map.put("msg", "您的登录已经超时或者已经在另一台机器登录，您被迫下线。"
                + event.getSessionInformation().getLastRequest());

        // Map -> Json
        String json = objectMapper.writeValueAsString(map);

        //输出JSON信息的数据
        event.getResponse().setContentType("application/json;charset=UTF-8");
        event.getResponse().getWriter().write(json);

        // 或者是跳转html页面，url代表跳转的地址
        // redirectStrategy.sendRedirect(event.getRequest(), event.getResponse(), "url");
    }
}

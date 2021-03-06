package com.formLoginAddFun.config;

import com.formLoginAddFun.config.accesslog.AccessLogInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Spring内部的一种配置方式
 * 配置拦截器
 */
@Configuration
public class MyWebMvcConfigurer implements WebMvcConfigurer {

    /**
     * 拦截器白名单
     * 设置排除路径，spring boot 2.*，注意排除掉静态资源的路径，不然静态资源无法访问
     */
    private final String[] excludePath = {"/static"};

    /**
     * 添加拦截器（记录日志）
     * @param registry
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AccessLogInterceptor()).addPathPatterns("/**").excludePathPatterns(excludePath);
    }
}

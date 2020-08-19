package com.formLoginAddFun.config.springsecurity;

import com.formLoginAddFun.config.springsecurity.handler.MyAuthenticationFailureHandler;
import com.formLoginAddFun.config.springsecurity.handler.MyAuthenticationSuccessHandler;
import com.formLoginAddFun.config.springsecurity.handler.MyExpiredSessionStrategy;
import com.formLoginAddFun.config.springsecurity.handler.MyLogoutSuccessHandler;
import com.formLoginAddFun.config.springsecurity.imagecode.CaptchaCodeFilter;
import com.formLoginAddFun.config.springsecurity.service.MyUserDetailsService;
import com.formLoginAddFun.config.springsecurity.smscode.SmsCodeSecurityConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.annotation.Resource;
import javax.sql.DataSource;

// 开启springsecurity注解配置
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class SecurityConfig_formLogin_03验证码短信模式 extends WebSecurityConfigurerAdapter {

    @Resource
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Resource
    private MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    @Resource
    private MyLogoutSuccessHandler myLogoutSuccessHandler;

    @Resource
    private MyUserDetailsService myUserDetailsService;

    @Resource
    private DataSource dataSource;

    @Resource
    private CaptchaCodeFilter captchaCodeFilter;

    /**
     * 验证码配置，由于配置较多，所以单独写一个config中
     */
    @Resource
    private SmsCodeSecurityConfig smsCodeSecurityConfig;

    /**
     * 用于连接springsecurity数据库
     * 把登录信息保存到数据库中，重启项目也不会影响登录
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //禁用跨站csrf攻击防御，后面的章节会专门讲解
        http.addFilterBefore(captchaCodeFilter, UsernamePasswordAuthenticationFilter.class)
                .csrf().disable()
                // 登录模式
                .formLogin()
                // 登录表单form中用户名输入框input的name名，不修改的话默认是username
                .usernameParameter("username")
                // form中密码输入框input的name名，不修改的话默认是password
                .passwordParameter("password")
                // 登录表单form中action的地址，也就是处理认证请求的路径
                .loginProcessingUrl("/login")
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailureHandler)
                // 增加短信配置
            .and()
                .apply(smsCodeSecurityConfig)
            .and()
                // 退出
                .logout()
                .logoutUrl("/signout")
                .deleteCookies("JSESSIONID")
                .logoutSuccessHandler(myLogoutSuccessHandler)

//                //用户未登录时，访问任何资源都转跳到该路径，即登录页面
//                .loginPage("/login.html")
            .and()
                .authorizeRequests()
                // 无需登录即可访问
                .antMatchers("/login.html","/login","/invalidSession.html", "/kaptcha","/smscode","/smslogin").permitAll()
                // 登陆之后即可访问
                .antMatchers("/index").authenticated()
                // 需要相关角色才可访问
                .anyRequest().access("@rbacService.hasPermission(request,authentication)")

//        config.antMatchers("/system/*").access("hasAuthority('ADMIN') or hasAuthority('USER')")
//                .anyRequest().authenticated();


            .and()
                // Spring Security创建使用session的方法
                .sessionManagement()
                .sessionCreationPolicy(
                        //Spring Security在需要时才创建session
                        SessionCreationPolicy.IF_REQUIRED
                )
            .and()
                .sessionManagement()
                // 登录超时跳转
                .invalidSessionUrl("/invalidSession.html")
            .and()
                // 默认情况下，Spring Security启用了migrationSession保护方式。
                // 即对于同一个cookies的SESSIONID用户，每次登录验证将创建一个新的HTTP会话，旧的HTTP会话将无效，并且旧会话的属性将被复制。
                // 设置为“none”时，原始会话不会无效
                // 设置“newSession”后，将创建一个干净的会话，而不会复制旧会话中的任何属性
                .sessionManagement().sessionFixation().migrateSession()
            .and()
                // 记住我 checkbox勾选框name属性的值目前必须是“remember-me” 默认效果是：2周
                .rememberMe()
                // 把登录信息保存到数据库，重启不会影响
                .tokenRepository(persistentTokenRepository())
                .rememberMeParameter("remember-me-new")
                .rememberMeCookieName("remember-me-cookie")
                // 单位秒
                .tokenValiditySeconds(2 * 24 * 60 * 60)
            .and().sessionManagement()
                // 表示同一个用户最大的登录数量
                .maximumSessions(1)
                // true表示已有登录就不予许再次登录，false表示会挤掉已登录人员
                .maxSessionsPreventsLogin(false)
                // 表示自定义一个session被下线(超时)之后的处理策略
                .expiredSessionStrategy(new MyExpiredSessionStrategy())

        ;

    }

    /**
     * 添加用户
     * @param auth
     * @throws Exception
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 自定义登录用户
        auth.userDetailsService(myUserDetailsService).passwordEncoder(passwordEncoder());
    }

    /**
     * 加密配置
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 静态资源白名单
     * @param web
     */
    @Override
    public void configure(WebSecurity web) {
        //将项目中静态资源路径开放出来
        web.ignoring().antMatchers( "/css/**", "/fonts/**", "/img/**", "/js/**");
    }



}

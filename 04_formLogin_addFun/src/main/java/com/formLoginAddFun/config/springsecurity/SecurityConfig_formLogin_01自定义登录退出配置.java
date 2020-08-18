package com.formLoginAddFun.config.springsecurity;//package com.formLoginAddFun.config.springsecurity;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.builders.WebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
//import javax.annotation.Resource;
//
//@Configuration
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//public class SecurityConfig_formLogin_01自定义登录退出配置 extends WebSecurityConfigurerAdapter {
//
//    @Resource
//    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
//
//    @Resource
//    private MyAuthenticationFailureHandler myAuthenticationFailureHandler;
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        //禁用跨站csrf攻击防御，后面的章节会专门讲解
//        http.csrf().disable()
//                // 登录模式
//                .formLogin()
//                // 登录表单form中用户名输入框input的name名，不修改的话默认是username
//                .usernameParameter("username")
//                // form中密码输入框input的name名，不修改的话默认是password
//                .passwordParameter("password")
//                // 登录表单form中action的地址，也就是处理认证请求的路径
//                .loginProcessingUrl("/login")
//                .successHandler(myAuthenticationSuccessHandler)
//                .failureHandler(myAuthenticationFailureHandler)
//
////                //用户未登录时，访问任何资源都转跳到该路径，即登录页面
////                .loginPage("/login.html")
////                //登录认证成功后默认转跳的路径
////                .defaultSuccessUrl("/index")
////                // 登录失败后跳转路径
////                .failureUrl("/login.html")
//
//            .and()
//                .authorizeRequests()
//                //不需要通过登录验证就可以被访问的资源路径
//                .antMatchers("/login.html","/login","/invalidSession.html").permitAll()
//                //需要对外暴露的资源路径
//                .antMatchers("/biz1","/biz2")
//                //user角色和admin角色都可以访问
//                .hasAnyAuthority("ROLE_user","ROLE_admin")
//                .antMatchers("/syslog","/sysuser")
//                //admin角色可以访问
//                .hasAnyRole("admin")
//                //.antMatchers("/syslog").hasAuthority("sys:log")
//                //.antMatchers("/sysuser").hasAuthority("sys:user")
//                .anyRequest().authenticated()
//            .and()
//                // Spring Security创建使用session的方法
//                .sessionManagement()
//                .sessionCreationPolicy(
//                        //Spring Security在需要时才创建session
//                        SessionCreationPolicy.IF_REQUIRED
//                )
//            .and()
//                .sessionManagement()
//                // 登录超时跳转
//                .invalidSessionUrl("/invalidSession.html")
//            .and()
//                // 默认情况下，Spring Security启用了migrationSession保护方式。
//                // 即对于同一个cookies的SESSIONID用户，每次登录验证将创建一个新的HTTP会话，旧的HTTP会话将无效，并且旧会话的属性将被复制。
//                // 设置为“none”时，原始会话不会无效
//                // 设置“newSession”后，将创建一个干净的会话，而不会复制旧会话中的任何属性
//                .sessionManagement().sessionFixation().migrateSession()
//            .and().sessionManagement()
//                // 表示同一个用户最大的登录数量
//                .maximumSessions(1)
//                // true表示已有登录就不予许再次登录，false表示会挤掉已登录人员
//                .maxSessionsPreventsLogin(false)
//                // 表示自定义一个session被下线(超时)之后的处理策略
//                .expiredSessionStrategy(new MyExpiredSessionStrategy());
//
//    }
//
//    /**
//     * 添加用户
//     * @param auth
//     * @throws Exception
//     */
//    @Override
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        // 在内存里面存储用户的身份认证和授权信息。
//        auth.inMemoryAuthentication()
//                // 用户名
//                .withUser("user")
//                // 密码
//                .password(passwordEncoder().encode("123456"))
//                // 角色
//                .roles("user")
//                .and()
//                .withUser("admin")
//                .password(passwordEncoder().encode("123456"))
//                //.authorities("sys:log","sys:user")
//                .roles("admin")
//                .and()
//                //配置BCrypt加密
//                .passwordEncoder(passwordEncoder());
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder();
//    }
//
//    /**
//     * 静态资源白名单
//     * @param web
//     */
//    @Override
//    public void configure(WebSecurity web) {
//        //将项目中静态资源路径开放出来
//        web.ignoring().antMatchers( "/css/**", "/fonts/**", "/img/**", "/js/**");
//    }
//
//}

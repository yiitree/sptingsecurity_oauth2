package com.formLoginRBAC.config.springsecurity;//package com.formLoginRBAC.config.springsecurity;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.builders.WebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
//@Configuration
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//public class SecurityConfig_formLogin_默认配置 extends WebSecurityConfigurerAdapter {
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        //禁用跨站csrf攻击防御，后面的章节会专门讲解
//        http.csrf().disable()
//                .formLogin()
//                //用户未登录时，访问任何资源都转跳到该路径，即登录页面
//                .loginPage("/login.html")
//                //登录表单form中action的地址，也就是处理认证请求的路径
//                .loginProcessingUrl("/login")
//                //登录表单form中用户名输入框input的name名，不修改的话默认是username
//                .usernameParameter("username")
//                //form中密码输入框input的name名，不修改的话默认是password
//                .passwordParameter("password")
//                //登录认证成功后默认转跳的路径
//                .defaultSuccessUrl("/index")
//                .and()
//                .authorizeRequests()
//                //不需要通过登录验证就可以被访问的资源路径
//                .antMatchers("/login.html","/login").permitAll()
//                //需要对外暴露的资源路径
//                .antMatchers("/biz1","/biz2")
//                //user角色和admin角色都可以访问
//                .hasAnyAuthority("ROLE_user","ROLE_admin")
//                .antMatchers("/syslog","/sysuser")
//                //admin角色可以访问
//                .hasAnyRole("admin")
//                //.antMatchers("/syslog").hasAuthority("sys:log")
//                //.antMatchers("/sysuser").hasAuthority("sys:user")
//                .anyRequest().authenticated();
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

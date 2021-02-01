package com.jwt.config.springsecurity;

import com.jwt.config.springsecurity.handler.MyLogoutSuccessHandler;
import com.jwt.config.filter.JwtAuthenticationTokenFilter;
import com.jwt.config.springsecurity.service.MyUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.annotation.Resource;
import javax.sql.DataSource;
import java.util.Arrays;

/**
 * springsecurity配置
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private MyLogoutSuccessHandler myLogoutSuccessHandler;

    @Resource
    private MyUserDetailsService myUserDetailsService;

    @Resource
    private DataSource datasource;

    @Resource
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
                // CSRF(跨站请求伪造)
                .csrf()
                // 暂时关闭
                .disable()
                //打开防护，此时会springsecurity请求XSRF-TOKEN返回，使用post请求的时候需要携带才可以访问
//                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .ignoringAntMatchers("/authentication")
//             .and()
                .cors()
            .and()
                //将我们的自定义jwtAuthenticationTokenFilter，加载到UsernamePasswordAuthenticationFilter的前面。
                .logout()
                .logoutUrl("/signout")
                //.logoutSuccessUrl("/login.html")
                .deleteCookies("JSESSIONID")
                .logoutSuccessHandler(myLogoutSuccessHandler)
//             .and()
//                .rememberMe()
//                .rememberMeParameter("remember-me-new")
//                .rememberMeCookieName("remember-me-cookie")
//                .tokenValiditySeconds(2 * 24 * 60 * 60)
//                // 把登录信息保存到数据库，重启不会影响
//                .tokenRepository(persistentTokenRepository())
            .and()
                // 设置白名单
                .authorizeRequests()
                .antMatchers("/authentication","/refreshtoken").permitAll()
                .antMatchers("/index").authenticated()
                .anyRequest().access("@rbacService.hasPermission(request,authentication)")
            .and()
                // 因为我们使用了JWT，表明了我们的应用是一个前后端分离的应用，所以我们可以开启STATELESS禁止使用session。
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    /**
     * 自定义登录方式
     * @param auth
     * @throws Exception
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    /**
     * 密码解密方式
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * permitall没有绕过spring security，其中包含了登录的以及匿名的。
     * ingore是完全绕过了spring security的所有filter，相当于不走spring security
     * @param web
     */
    @Override
    public void configure(WebSecurity web) {
        //将项目中静态资源路径开放出来
        web.ignoring()
           .antMatchers( "/css/**", "/fonts/**", "/img/**", "/js/**");
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(datasource);
        return tokenRepository;
    }

    /**
     * 因为使用到了AuthenticationManager ,所以在继承WebSecurityConfigurerAdapter的SpringSecurity配置实现类中，将AuthenticationManager 声明为一个Bean。并将"/authentication"和 "/refreshtoken"开放访问权限，如何开放访问权限，我们之前的文章已经讲过了。
     * @return
     * @throws Exception
     */
    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    /**
     * 跨域配置
     * 使用这种方法实现的效果等同于注入一个CorsFilter过滤器
     * @return
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8888"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        configuration.applyPermitDefaultValues();
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}

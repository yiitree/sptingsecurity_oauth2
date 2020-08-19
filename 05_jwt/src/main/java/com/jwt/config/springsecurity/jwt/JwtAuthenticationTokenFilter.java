package com.jwt.config.springsecurity.jwt;

import com.jwt.config.springsecurity.service.MyUserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 拦截校验jwt令牌信息
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Resource
    JwtTokenUtil jwtTokenUtil;

    @Resource
    MyUserDetailsService myUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // 拦截接口请求，从请求request获取token，从token中解析得到用户名
        String jwtToken = request.getHeader(jwtTokenUtil.getHeader());
        if(!StringUtils.isEmpty(jwtToken)){
            String username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            //如果可以正确的从JWT中提取用户信息，并且该用户未被授权
            if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
                //然后通过UserDetailsService获得系统用户（从数据库、或其他其存储介质）
                UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);
                //根据用户信息和JWT令牌，验证系统用户与用户输入的一致性，并判断JWT是否过期。如果没有过期，至此表明了该用户的确是该系统的用户。
                if(jwtTokenUtil.validateToken(jwtToken,userDetails)){
                    //但是，你是系统用户不代表你可以访问所有的接口。所以需要构造UsernamePasswordAuthenticationToken传递用户、权限信息，并将这些信息通过authentication告知Spring Security。Spring Security会以此判断你的接口访问权限
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        }

        filterChain.doFilter(request,response);
    }
}

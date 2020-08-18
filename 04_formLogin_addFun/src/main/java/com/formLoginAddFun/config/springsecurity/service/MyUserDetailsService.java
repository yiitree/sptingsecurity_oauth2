package com.formLoginAddFun.config.springsecurity.service;

import com.formLoginAddFun.config.springsecurity.domain.MyUserDetails;
import com.formLoginAddFun.config.springsecurity.mapper.MyUserDetailsServiceMapper;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 动态登录验证
 * UserDetailsService为springsecurity自带的用户登录判断
 */
@Component
public class MyUserDetailsService implements UserDetailsService {

    @Resource// 和@Autowird类似，Resource根据类名称注入
    private MyUserDetailsServiceMapper myUserDetailsServiceMapper;

    /**
     * springsecurity自动调用loadUserByUsername进行登录判断
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

//        String password; //密码
//        String username;  //用户名
//        boolean enabled;  //账号是否可用
//        Collection<? extends GrantedAuthority> authorities;  //用户的权限集合
//        boolean accountNonExpired;   //是否没过期
//        boolean accountNonLocked;   //是否没被锁定 但是比如accountNonLocked字段用于登录多次错误锁定，但我们一般不会在表里存是否锁定，而是存一个锁定时间字段。
//        boolean credentialsNonExpired;  //是否没过期

        //加载基础用户信息 username,password,enabled
        MyUserDetails myUserDetails = myUserDetailsServiceMapper.findByUserName(username);

        //加载用户角色列表
        List<String> roleCodes = myUserDetailsServiceMapper.findRoleByUserName(username);

        //通过用户角色列表加载用户的资源权限列表 authorities
        List<String> authorties = myUserDetailsServiceMapper.findAuthorityByRoleCodes(roleCodes);

        //角色是一个特殊的权限，ROLE_前缀
        roleCodes = roleCodes.stream()
                .map(rc -> "ROLE_" +rc)
                .collect(Collectors.toList());

        authorties.addAll(roleCodes);

        myUserDetails.setAuthorities(
                AuthorityUtils.commaSeparatedStringToAuthorityList(
                        String.join(",",authorties)
                )
        );
        return myUserDetails;
    }
}

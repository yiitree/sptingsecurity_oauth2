package com.formLoginAddFun.config.springsecurity.smscode;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 短信校验成功
 * 当短信验证码校验成功，继续执行过滤器链中的SmsCodeAuthenticationFilter对用户进行认证授权.
 *
 * 由于没有用户名和密码，所以需要再写一个授权过滤器，进行授权
 *
 * 只不过将用户名、密码换成手机号进行认证，短信验证码在此部分已经没有用了，因为我们在SmsCodeValidateFilter已经验证过了。
 *
 */
public class SmsCodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    // 手机号
    public static final String SPRING_SECURITY_FORM_MOBILE_KEY = "mobile";

    // 请求中携带手机号的参数名称
    private String mobileParameter = SPRING_SECURITY_FORM_MOBILE_KEY;

    // 指定当前过滤器是否只处理POST请求
    private boolean postOnly = true;


    public SmsCodeAuthenticationFilter() {
        // 指定当前过滤器处理的请求路径
        super(new AntPathRequestMatcher("/smslogin", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response)
            throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        String moblie = obtainMobile(request);


        if (moblie == null) {
            moblie = "";
        }

        moblie = moblie.trim();

        SmsCodeAuthenticationToken authRequest = new SmsCodeAuthenticationToken(moblie);

        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }


    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }


    protected void setDetails(HttpServletRequest request,
                              SmsCodeAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }


    public void setMobileParameter(String mobileParameter) {
        Assert.hasText(mobileParameter, "mobile parameter must not be empty or null");
        this.mobileParameter = mobileParameter;
    }


    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getMobileParameter() {
        return mobileParameter;
    }


}

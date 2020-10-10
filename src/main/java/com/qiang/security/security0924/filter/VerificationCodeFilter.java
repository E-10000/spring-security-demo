package com.qiang.security.security0924.filter;

import com.qiang.security.security0924.Handler.MyAuthenticationFailureHandler;
import com.qiang.security.security0924.exception.VerificationCodeException;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


//检验验证码的过滤器
public class VerificationCodeFilter extends OncePerRequestFilter {
    private AuthenticationFailureHandler authenticationFailureHandler = new MyAuthenticationFailureHandler();

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        //非登陆请求不校验验证码
        if (!"/auth/form".equals(httpServletRequest.getRequestURI())){
            filterChain.doFilter(httpServletRequest,httpServletResponse);
        }else {
            try {
                verificationCode(httpServletRequest);
                filterChain.doFilter(httpServletRequest,httpServletResponse);
            }catch (VerificationCodeException e){
                authenticationFailureHandler.onAuthenticationFailure(httpServletRequest,httpServletResponse,e);
            }
        }
    }

    public void verificationCode(HttpServletRequest httpServletRequest) throws VerificationCodeException {
        String requestCode = httpServletRequest.getParameter("captcha");
        HttpSession session = httpServletRequest.getSession();
        String saveCode = (String) session.getAttribute("captcha");
        if (!StringUtils.isEmpty(saveCode)){
            //随手清楚验证码，无论成功失败，客户端应该在登陆失败时刷新验证码
            session.removeAttribute("captcha");
        }
        //验证不通过
        if (StringUtils.isEmpty(requestCode)||StringUtils.isEmpty(saveCode)||!requestCode.equals(saveCode)){
            throw new VerificationCodeException();
        }
    }
}

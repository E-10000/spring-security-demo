package com.qiang.security.security0924.other;

import org.springframework.security.web.session.InvalidSessionStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//实现invalidSessionStrategy接口，自定义会话过期策略
public class MyInvalidSessionStrategy implements InvalidSessionStrategy {
    @Override
    public void onInvalidSessionDetected(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ServletException {
        //但是设置了这个之后，连登陆界面都变成了session无效，目前还不知道怎么设置这部分
        httpServletResponse.setContentType("application/json;charset=UTF-8");
        httpServletResponse.getWriter().write("session无效");

//        httpServletResponse.setHeader("refresh","3;/myLogin.html");
    }
}

package com.qiang.security.security0924.other;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class MyWebAuthenticationDetails extends WebAuthenticationDetails {

    private boolean imageCodeIsRight;

    public MyWebAuthenticationDetails(HttpServletRequest request) {

        super(request);
    }

    public boolean getImageCodeIsRight(){
        return this.imageCodeIsRight;
    }

    //补充用户提交的验证码和session保存的验证码
//    public MyWebAuthenticationDetails(HttpServletRequest request) {
//
//
//
//        HttpSession session = request.getSession();
//        session.getAttribute("captcha");
//    }
}

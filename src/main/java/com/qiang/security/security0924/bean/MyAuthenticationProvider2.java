package com.qiang.security.security0924.bean;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

//书本上这个类和上一个类同名，真实非常神奇呢
//@Component
//public class MyAuthenticationProvider2 extends DaoAuthenticationProvider {
//
//    //把构造方法注入UserDetailService和PasswordEncoder
//    public MyAuthenticationProvider2(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder){
//        this.setUserDetailsService(userDetailsService);
//        this.setPasswordEncoder(passwordEncoder);
//    }
//
//    @Override
//    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
//        super.additionalAuthenticationChecks(userDetails, authentication);
//    }
//}

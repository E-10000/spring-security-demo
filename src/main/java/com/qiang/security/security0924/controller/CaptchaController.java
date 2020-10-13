package com.qiang.security.security0924.controller;

import com.google.code.kaptcha.Producer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.image.BufferedImage;
import java.io.IOException;

/*
当访问/captcha.jpg，得到一张基于配置类设定的一张图片，验证码保存与哦session中
 */
@RestController
public class CaptchaController {
    @Autowired
    private Producer captchaProducer;

    @GetMapping("/captcha.jpg")
    public void getCaptcha(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //设置内容类型
        response.setContentType("image/jpeg");
        //创建验证码文本
        String capText = captchaProducer.createText();
        //将验证码文本设置到session
        request.getSession().setAttribute("captcha",capText);
        //创建验证码图片
        BufferedImage bi = captchaProducer.createImage(capText);
        //获取相应输出流
        ServletOutputStream out = response.getOutputStream();
        //将图片验证码写到响应输出流
        ImageIO.write(bi,"jpg",out);
        //推送并且关闭输出流
        try{
            out.flush();
        }finally {
            out.close();
        }
    }
}

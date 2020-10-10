package com.qiang.security.security0924.config;

import com.google.code.kaptcha.Producer;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Properties;

/*
配置类，用于配置一个验证图片
 */
@Configuration
public class KaptchaConfig {

    @Bean
    public Producer captcha(){
        Properties properties = new Properties();
        //宽度
        properties.setProperty("kaptcha.image.width","150");
        //长度
        properties.setProperty("kaptcha.image.height","50");
        //字符集
        properties.setProperty("kaptcha.textproducer.char.string","0123456789");
        //字符长度
        properties.setProperty("kaptcha.textproducer.char.length","4");
        Config config = new Config(properties);
        DefaultKaptcha defaultKaptcha =new DefaultKaptcha();
        defaultKaptcha.setConfig(config);
        return defaultKaptcha;
    }
}

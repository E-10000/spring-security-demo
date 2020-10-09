package com.qiang.security.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.io.PrintWriter;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

//  在内存中设置用户，可以用账号登陆
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

//        安全框架多少以后，要设置加密模式了
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("user").password(new BCryptPasswordEncoder().encode("123")).roles("USER")
                .and()
                .withUser("admin").password(new BCryptPasswordEncoder().encode("123")).roles("USER","ADMIN");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {

    }

    //  设置安全拦截设置的地方
    @Override
    protected void configure(HttpSecurity http) throws Exception {

//      http.authorizeRequests().anyRequest().authenticated()  返回一个拦截注册器
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/app/**").permitAll()///app/**所有人都可以访问，不受安全框架拦截
                .anyRequest().authenticated()
        .and()
//      登陆页面为 /myLogin.html，并且登陆页不设权限
        .formLogin().loginPage("/myLogin.html") //登陆的页面为
//        .loginProcessingUrl("/test")//指定处理登陆请求的路径，但是俺不懂
                /*这个是登陆成功的逻辑
                 */
                .successHandler(new AuthenticationSuccessHandler(){

                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.setContentType("application/json;charset=UTF-8");
                        PrintWriter out = httpServletResponse.getWriter();
                        out.write("{\"error_code\":\"0\",\"message\":\"欢迎登陆系统\"}");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.setContentType("application/json;charset=UTF-8");
                        PrintWriter out = httpServletResponse.getWriter();
                        out.write("{\"error_code\":\"401\",\"name\":\"" +e.getClass() + "\",\"message\":\"" + e.getMessage() + "\"}");
                    }
                })
                .permitAll()
        .and()
//      csrf是跨域保护功能
        .csrf().disable();
    }

//  在表中创建几个用户，链接数据库，在数据表中创建数据，但是不能登陆直接来用
    @Override
    protected UserDetailsService userDetailsService() {
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager();
        manager.setDataSource(dataSource);
        if (!manager.userExists("user")){
            manager.createUser(User.withUsername("user").password("123").roles("USER").build());
        }
        if (!manager.userExists("admin")){
            manager.createUser(User.withUsername("admin").password("123").roles("ADMIN").build());
        }
        if (!manager.userExists("test")){
            manager.createUser(User.withUsername("test").password("123").roles("USER").build());
        }
        return manager;
    }
}

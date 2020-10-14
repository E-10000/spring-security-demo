package com.qiang.security.security0924.dao;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

//不要用@Data ，因为会重写了hashCode，我们还要自己写这个函数呢
@AllArgsConstructor//满参构造器
@NoArgsConstructor//无参构造器
@Setter//set
@Getter//get
public class User implements UserDetails {

    private Long id;

    private String username;

    private String password;

    private String roles;

    private boolean enable;

    private List<GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

//    @Override
//    public String getPassword() {
//        return this.password;
//    }
//
//    @Override
//    public String getUsername() {
//        return this.username;
//    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.enable;
    }

    //重写equals和hashCode，实现持久层数据库连接登陆的会话并发控制
    @Override
    public boolean equals(Object obj) {
        return obj instanceof User ? this.username.equals(((User)obj).username):false;
    }

    @Override
    public int hashCode() {
        return this.username.hashCode();
    }
}

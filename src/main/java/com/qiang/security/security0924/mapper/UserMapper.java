package com.qiang.security.security0924.mapper;

import com.qiang.security.security0924.dao.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {

    @Select("select * from users where username=#{username}")
    User findByUsername(@Param("username") String username);
}

package com.test.mapper;

import com.test.bean.SysUser;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {
 
    @Select("select * from sys_user where username = #{username}")
    SysUser getByUsername(@Param("username") String username);
}
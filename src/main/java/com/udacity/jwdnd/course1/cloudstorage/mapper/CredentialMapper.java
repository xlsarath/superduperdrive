package com.udacity.jwdnd.course1.cloudstorage.mapper;

import com.udacity.jwdnd.course1.cloudstorage.model.Credential;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface CredentialMapper {

        @Select("SELECT * FROM credentials WHERE userid = #{userid}")
        List<Credential> getAllCredentials(Integer userid);

        @Insert("INSERT INTO credentials (url, username, key, password, userid) values (#{credential.url}, #{credential.username}, #{credential.key}, #{credential.password}, #{userid})")
        int insert(@Param("credential") Credential credential, Integer userid);

        @Update("UPDATE CREDENTIALS SET url = #{credential.url}, username = #{credential.username}, key = #{credential.key}, password = #{credential.password} WHERE credentialid = #{credential.credentialid} AND #{userid}")
        boolean update(@Param("credential") Credential credential, Integer userid);

        @Delete("DELETE FROM credentials WHERE credentialid = #{id} and userid = #{userid}")
        boolean delete(Integer id, Integer userid);
}

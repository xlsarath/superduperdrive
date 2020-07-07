package com.udacity.jwdnd.course1.cloudstorage.mapper;

import com.udacity.jwdnd.course1.cloudstorage.model.Files;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;

import java.util.List;


@Mapper
public interface FilehandleMapper {

    @Select("SELECT * FROM FILES WHERE userid = #{userid}")
    List<Files> getFiles(Integer userid);

    @Insert("INSERT INTO FILES (filename, contenttype, filesize, filedata, userid) VALUES (#{file.fileName}, #{file.contentType}, #{file.fileSize}, #{file.fileData}, #{userId})")
    @Options(useGeneratedKeys = true, keyProperty = "fileId")
    int insert(Files files);


}

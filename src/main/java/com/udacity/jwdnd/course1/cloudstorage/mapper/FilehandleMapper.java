package com.udacity.jwdnd.course1.cloudstorage.mapper;

import com.udacity.jwdnd.course1.cloudstorage.model.File;
import org.apache.ibatis.annotations.*;

import java.util.List;


@Mapper
public interface FilehandleMapper {

    @Select("SELECT * FROM FILES WHERE userid = #{userid}")
    List<File> getFilesByUserId(Integer userid);

    @Select("SELECT * FROM FILES")
    List<File> getAllFiles();

    @Select("SELECT * FROM FILES WHERE fileid = #{fileid} and userid = #{userid}")
    File get(int fileid, int userid);

    @Insert("INSERT INTO FILES (filename, contenttype, filesize, filedata, userid) VALUES (#{file.filename}, #{file.contenttype}, #{file.filesize}, #{file.filedata}, #{file.userid})")
    //@Options(useGeneratedKeys = true, keyProperty = "fileId")
    int insert(@Param("file") File file);

    @Delete("DELETE FROM FILES WHERE fileid = #{fileid} and userid = #{userid}")
    boolean delete(int fileid, int userid);

}

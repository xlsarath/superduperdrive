package com.udacity.jwdnd.course1.cloudstorage.services;

import com.udacity.jwdnd.course1.cloudstorage.mapper.FilehandleMapper;
import com.udacity.jwdnd.course1.cloudstorage.model.Files;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@Service
public class FileHandleService {

    private FilehandleMapper filehandleMapper;

    public FileHandleService(FilehandleMapper filehandleMapper) {
        this.filehandleMapper = filehandleMapper;
    }

    private List<Files> getFiles(Integer userId){
        return filehandleMapper.getFiles(userId);
    }

    private int addFile(MultipartFile multipartFile, Integer userid) throws IOException {
        return filehandleMapper.insert(new Files(null,multipartFile.getName(),multipartFile.getContentType(),multipartFile.getSize(),userid,multipartFile.getBytes()));
    }

}
